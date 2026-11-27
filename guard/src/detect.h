#pragma once

#include <string>
#include <vector>

namespace bsecured {

struct Observation
{
    bool connected = false;             // Did the TLS handshake complete
    std::string observed_spki;          // base64 SHA-256 of the leaf SPKI ("" if not connected)
    std::string issuer;                 // The leaf certificate's issuer
    bool system_trust_ok = false;       // Did the chain verify against the trust store
    std::string proxy_env;              // Name of the proxy env var in effect ("" -> JSON null)
};

// What one look at the process's own tracing state reveals (anti-debugging).
struct TracerObservation
{
    long tracer_pid = 0;                // Process id tracing us, from TracerPid (0 if none)
    std::string tracer_name;            // The tracer's command name ("" if unreadable -> JSON null)
    int ptrace_scope = -1;              // Yama ptrace_scope in force (-1 if unknown -> JSON null)
};

// Connects to the configured server, completes the handshake, and reads the leaf
// certificate. On failure returns an Observation with connected=false, never throws.
Observation probe();

// Builds a MITM_PIN_FAILURE report from the observation, signs it with the build's
// Ed25519 seed, and posts it to the server. Returns true only on HTTP 200. Never throws.
bool send_report(const Observation& obs);

// Reads the TracerPid field from the text of a /proc/<pid>/status file. Returns 0 when
// the field is absent or malformed. Pure, so it can be tested without /proc.
long parse_tracer_pid(const std::string& status_text);

// Reads /proc/self/status for a tracer and, if there is one, its name and the ptrace
// policy in force. Where /proc does not exist (e.g. macOS), reports no tracer.
TracerObservation check_tracer();

// Builds a DEBUGGER_ATTACHED report naming the tracer, signs it with the build's Ed25519
// seed, and posts it to the server. Returns true only on HTTP 200. Never throws.
bool send_debugger_report(const TracerObservation& obs);

// The set of acceptable server SPKI pins compiled into this build (the current pin
// plus any backups), exposed for the probe tool.
std::vector<std::string> pinned_spkis();

// True if an observed leaf SPKI matches any pin in the compiled-in set. An empty
// observation or an empty set never matches, so an unpinned build always reports.
bool pin_matches(const std::string& observed_spki);

// The device id compiled into this build, exposed for the probe tool.
std::string device_id();

} 
