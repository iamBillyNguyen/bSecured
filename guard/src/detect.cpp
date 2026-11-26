#include "detect.h"

#include "bsecured_config.h"

#include <cctype>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>

#include <curl/curl.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sodium.h>

// OpenSSL renamed this in 3.0; keep building on a 1.1.1 host too.
#if OPENSSL_VERSION_NUMBER < 0x30000000L
#define SSL_get1_peer_certificate SSL_get_peer_certificate
#endif

using namespace std;

namespace bsecured {
namespace {

// Base64-encodes bytes, standard variant with padding. Matches Python's
// base64.b64encode, which is what the server decodes.
string base64(const unsigned char* data, size_t len)
{
    string out(sodium_base64_encoded_len(len, sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), data, len, sodium_base64_VARIANT_ORIGINAL);
    out.pop_back(); // Sodium counts a trailing NUL in the length
    return out;
}

// Escapes a string so it is safe inside a JSON string value.
string json_escape(const string& s)
{
    string o;
    o.reserve(s.size() + 2);

    for (unsigned char c : s)
    {
        switch (c)
        {
            case '"': o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n"; break;
            case '\r': o += "\\r"; break;
            case '\t': o += "\\t"; break;
            default:
                if (c < 0x20)
                {
                    char u[7];
                    snprintf(u, sizeof u, "\\u%04x", c);
                    o += u;
                }
                else
                {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

// Gets the current UTC time as an ISO 8601 string with milliseconds,
// e.g. 2026-10-13T18:22:04.113Z.
string now_iso_utc()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto ms = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
    time_t t = system_clock::to_time_t(now);
    tm tm{};
    gmtime_r(&t, &tm);

    // The real timestamp is 24 chars; the generous size also satisfies GCC's
    // -Wformat-truncation, which conservatively assumes full int width per %d field.
    char buf[128];
    snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, static_cast<int>(ms.count()));
    return buf;
}

// Finds the first proxy environment variable that is set, returning its name, or "".
string proxy_env_name()
{
    for (const char* name : {"https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"})
    {
        if (const char* v = getenv(name); v && *v)
        {
            return name;
        }
    }
    return "";
}

// Reads a certificate's issuer as a one-line string.
string issuer_of(X509* cert)
{
    char line[256];
    X509_NAME_oneline(X509_get_issuer_name(cert), line, sizeof line);
    return line;
}

// Reads a whole file into a string, or "" if it cannot be opened. Files under /proc
// report a size of zero, so this reads to the end rather than trusting the size.
string read_file(const string& path)
{
    ifstream in(path, ios::binary);
    if (!in)
    {
        return "";
    }
    return string(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
}

// Strips trailing whitespace, such as the newline that ends a /proc file.
string trim_right(string s)
{
    const size_t end = s.find_last_not_of(" \t\r\n");
    s.erase(end == string::npos ? 0 : end + 1);
    return s;
}

}

// The server SPKI pins this build accepts, split out of the comma-separated
// BSEC_PINNED_SPKI. More than one lets a planned key rotation pass without a false
// alarm; the current pin is first, any backups after.
vector<string> pinned_spkis()
{
    vector<string> pins;
    const string raw = BSEC_PINNED_SPKI;
    size_t start = 0;
    for (;;)
    {
        const size_t comma = raw.find(',', start);
        const size_t end = (comma == string::npos) ? raw.size() : comma;
        string pin = raw.substr(start, end - start);
        // Trim surrounding whitespace so " a , b " still yields "a" and "b"
        const size_t a = pin.find_first_not_of(" \t\r\n");
        const size_t b = pin.find_last_not_of(" \t\r\n");
        if (a != string::npos)
        {
            pin = pin.substr(a, b - a + 1);
            if (!pin.empty())
            {
                pins.push_back(pin);
            }
        }
        if (comma == string::npos) // no trailing comma, so that was the last pin
        {
            break;
        }
        start = comma + 1;
    }
    return pins;
}

// True if the observed leaf SPKI matches any pin we accept. An empty key or an empty
// set never matches, so an unpinned build always reports.
bool pin_matches(const string& observed_spki)
{
    if (observed_spki.empty())
    {
        return false;
    }
    for (const string& pin : pinned_spkis())
    {
        if (pin == observed_spki)
        {
            return true;
        }
    }
    return false;
}

// The device id compiled into this build, exposed for the probe tool.
string device_id()
{
    return BSEC_DEVICE_ID;
}

// Connects to the configured server, completes the TLS handshake, and reads the leaf
// certificate.
Observation probe()
{
    Observation obs;
    obs.proxy_env = proxy_env_name();

    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (ctx == nullptr)
    {
        return obs;
    }

    // Load trust anchors so SSL_get_verify_result is meaningful, but do NOT abort
    // on a verification failure: the guard must still connect to observe the
    // certificate an interceptor is presenting. The pin, not the chain, is the
    // detection; system_trust_ok is recorded only as evidence.
    const string ca = BSEC_CA_FILE;
    if (!ca.empty())
    {
        SSL_CTX_load_verify_locations(ctx, ca.c_str(), nullptr);
    }
    else
    {
        SSL_CTX_set_default_verify_paths(ctx);
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);

    BIO* bio = BIO_new_ssl_connect(ctx);
    if (bio != nullptr)
    {
        SSL* ssl = nullptr;
        BIO_get_ssl(bio, &ssl);
        if (ssl != nullptr)
        {
            SSL_set_tlsext_host_name(ssl, BSEC_SERVER_HOST); // SNI
            const string where = string(BSEC_SERVER_HOST) + ":" + BSEC_SERVER_PORT;
            BIO_set_conn_hostname(bio, where.c_str());

            if (BIO_do_connect(bio) == 1 && BIO_do_handshake(bio) == 1)
            {
                obs.system_trust_ok = (SSL_get_verify_result(ssl) == X509_V_OK);
                if (X509* cert = SSL_get1_peer_certificate(ssl))
                {
                    obs.issuer = issuer_of(cert);
                    unsigned char* der = nullptr;
                    int n = i2d_X509_PUBKEY(X509_get_X509_PUBKEY(cert), &der);
                    if (n > 0 && der != nullptr)
                    {
                        unsigned char digest[SHA256_DIGEST_LENGTH];
                        SHA256(der, static_cast<size_t>(n), digest);
                        obs.observed_spki = base64(digest, sizeof digest);
                        obs.connected = true;
                        OPENSSL_free(der);
                    }
                    X509_free(cert);
                }
            }
        }
        BIO_free_all(bio);
    }

    SSL_CTX_free(ctx);
    ERR_clear_error(); // Leave no error on the thread's OpenSSL queue
    return obs;
}

// Finds the line that starts with "TracerPid:" and reads the number after it. The
// kernel writes it as "TracerPid:\t<pid>"; strtol skips the tab. Anything that is not a
// plain non-negative number counts as no tracer, rather than as a false alarm.
long parse_tracer_pid(const string& status_text)
{
    static const string key = "TracerPid:";
    size_t line = 0;
    while (line < status_text.size())
    {
        size_t eol = status_text.find('\n', line);
        if (eol == string::npos)
        {
            eol = status_text.size();
        }
        if (status_text.compare(line, key.size(), key) == 0)
        {
            const char* start = status_text.c_str() + line + key.size();
            char* end = nullptr;
            errno = 0;
            const long pid = strtol(start, &end, 10);
            const bool ends_cleanly = *end == '\0' || isspace(static_cast<unsigned char>(*end));
            return (end == start || errno != 0 || pid < 0 || !ends_cleanly) ? 0 : pid;
        }
        line = eol + 1;
    }
    return 0;
}

// Looks at our own tracing state. /proc/self/status describes the main thread, which
// is the thread a debugger or tracer attaches to by process id. The tracer's name and
// the ptrace policy are evidence only; either may be unreadable, which is not an error.
TracerObservation check_tracer()
{
    TracerObservation obs;
    obs.tracer_pid = parse_tracer_pid(read_file("/proc/self/status"));
    if (obs.tracer_pid == 0)
    {
        return obs;
    }

    obs.tracer_name = trim_right(read_file("/proc/" + to_string(obs.tracer_pid) + "/comm"));
    const string scope = trim_right(read_file("/proc/sys/kernel/yama/ptrace_scope"));
    if (scope.size() == 1 && isdigit(static_cast<unsigned char>(scope[0])))
    {
        obs.ptrace_scope = scope[0] - '0'; // Yama's values are 0 to 3
    }
    return obs;
}

namespace {

// Builds the report JSON by hand, so the exact bytes are what gets signed. Field order
// matches the server's model; the server verifies over these bytes and never
// re-serializes. The evidence object arrives already serialized by its guard.
string build_report_json(const char* threat_type, const string& evidence_json)
{
    string json = "{";
    json += "\"v\":1";
    json += ",\"device_id\":\"" + json_escape(BSEC_DEVICE_ID) + "\"";
    json += ",\"build_id\":\"" + json_escape(BSEC_BUILD_ID) + "\"";
    json += ",\"detected_at\":\"" + now_iso_utc() + "\"";
    json += ",\"threat_type\":\"" + json_escape(threat_type) + "\"";
    json += ",\"evidence\":" + evidence_json;
    json += "}";
    return json;
}

// The anti-MitM evidence: the key and issuer the server actually presented. Values are
// base64 (safe) or escaped.
string mitm_evidence_json(const Observation& obs)
{
    string json = "{";
    json += "\"observed_spki\":\"" + json_escape(obs.observed_spki) + "\"";
    json += ",\"system_trust_ok\":" + string(obs.system_trust_ok ? "true" : "false");
    json += ",\"issuer\":\"" + json_escape(obs.issuer) + "\"";
    json += ",\"proxy_env\":" + (obs.proxy_env.empty() ? "null" : "\"" + json_escape(obs.proxy_env) + "\"");
    json += "}";
    return json;
}

// The anti-debugging evidence: who is tracing us, and the ptrace policy in force. The
// tracer's name is chosen by another process, so it is escaped like any other input.
string debugger_evidence_json(const TracerObservation& obs)
{
    string json = "{";
    json += "\"tracer_pid\":" + to_string(obs.tracer_pid);
    json += ",\"tracer_name\":" + (obs.tracer_name.empty() ? "null" : "\"" + json_escape(obs.tracer_name) + "\"");
    json += ",\"ptrace_scope\":" + (obs.ptrace_scope < 0 ? string("null") : to_string(obs.ptrace_scope));
    json += "}";
    return json;
}

// Signs the message with the build's Ed25519 seed, returning the base64 signature,
// or "" if the seed is misconfigured.
string sign_b64(const string& message)
{
    unsigned char seed[crypto_sign_SEEDBYTES];
    size_t seed_len = 0;
    if (sodium_base642bin(seed, sizeof seed, BSEC_SEED_B64, strlen(BSEC_SEED_B64),
                          nullptr, &seed_len, nullptr, sodium_base64_VARIANT_ORIGINAL) != 0 ||
        seed_len != sizeof seed)
    {
        return ""; // Misconfigured seed
    }

    unsigned char pk[crypto_sign_PUBLICKEYBYTES], sk[crypto_sign_SECRETKEYBYTES];
    crypto_sign_seed_keypair(pk, sk, seed);
    unsigned char sig[crypto_sign_BYTES];
    crypto_sign_detached(sig, nullptr,
                         reinterpret_cast<const unsigned char*>(message.data()), message.size(), sk);
    sodium_memzero(seed, sizeof seed);
    sodium_memzero(sk, sizeof sk);
    return base64(sig, sizeof sig);
}

// libcurl write callback that discards the response body, returning the number of
// bytes handled (all of them).
size_t discard(char*, size_t size, size_t nmemb, void*)
{
    return size * nmemb;
}

// Builds a report of the given type around its evidence, signs the exact bytes with the
// build's Ed25519 seed, and POSTs it to the server. Returns true only on HTTP 200. Shared
// by every guard, so each one only decides when to report and what evidence to carry.
bool post_signed_report(const char* threat_type, const string& evidence_json)
{
    const string body = build_report_json(threat_type, evidence_json);
    const string sig = sign_b64(body);
    if (sig.empty())
    {
        return false;
    }

    CURL* curl = curl_easy_init();
    if (curl == nullptr)
    {
        return false;
    }

    curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/json");
    const string sig_header = "X-BSec-Signature: " + sig;
    headers = curl_slist_append(headers, sig_header.c_str());

    const string url = string(BSEC_REPORT_URL) + "/v1/reports";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(body.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    if (const string ca = BSEC_CA_FILE; !ca.empty())
    {
        curl_easy_setopt(curl, CURLOPT_CAINFO, ca.c_str());
    }

    const CURLcode rc = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return rc == CURLE_OK && status == 200;
}

}

// Builds a MITM_PIN_FAILURE report from the observation, signs it with the build's
// Ed25519 seed, and POSTs it to the server. Returns true only on HTTP 200. Never throws.
bool send_report(const Observation& obs)
{
    if (!obs.connected)
    {
        return false;
    }
    return post_signed_report("MITM_PIN_FAILURE", mitm_evidence_json(obs));
}

// Builds a DEBUGGER_ATTACHED report naming the tracer, signs it with the build's Ed25519
// seed, and POSTs it to the server. Returns true only on HTTP 200. Never throws.
bool send_debugger_report(const TracerObservation& obs)
{
    if (obs.tracer_pid <= 0)
    {
        return false;
    }
    return post_signed_report("DEBUGGER_ATTACHED", debugger_evidence_json(obs));
}

}
