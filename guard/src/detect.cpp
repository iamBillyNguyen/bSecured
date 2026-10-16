#include "detect.h"

#include "bsecured_config.h"

#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>

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

}

// The SPKI pin compiled into this build, exposed for the probe tool.
string pinned_spki()
{
    return BSEC_PINNED_SPKI;
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

namespace {

// Builds the report JSON by hand, so the exact bytes are what gets signed. Field order
// matches the server's model; the server verifies over these bytes and never
// re-serializes. Evidence values are base64 (safe) or escaped.
string build_report_json(const Observation& obs)
{
    string json = "{";
    json += "\"v\":1";
    json += ",\"device_id\":\"" + json_escape(BSEC_DEVICE_ID) + "\"";
    json += ",\"build_id\":\"" + json_escape(BSEC_BUILD_ID) + "\"";
    json += ",\"detected_at\":\"" + now_iso_utc() + "\"";
    json += ",\"threat_type\":\"MITM_PIN_FAILURE\"";
    json += ",\"evidence\":{";
    json += "\"observed_spki\":\"" + json_escape(obs.observed_spki) + "\"";
    json += ",\"system_trust_ok\":" + string(obs.system_trust_ok ? "true" : "false");
    json += ",\"issuer\":\"" + json_escape(obs.issuer) + "\"";
    json += ",\"proxy_env\":" + (obs.proxy_env.empty() ? "null" : "\"" + json_escape(obs.proxy_env) + "\"");
    json += "}}";
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

}

// Builds a MITM_PIN_FAILURE report from the observation, signs it with the build's
// Ed25519 seed, and POSTs it to the server. Returns true only on HTTP 200. Never throws.
bool send_report(const Observation& obs)
{
    if (!obs.connected)
    {
        return false;
    }

    const string body = build_report_json(obs);
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
