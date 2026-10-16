#pragma once

#include <string>

namespace bsecured {

struct Observation
{
    bool connected = false;             // Did the TLS handshake complete
    std::string observed_spki;          // base64 SHA-256 of the leaf SPKI ("" if not connected)
    std::string issuer;                 // The leaf certificate's issuer
    bool system_trust_ok = false;       // Did the chain verify against the trust store
    std::string proxy_env;              // Name of the proxy env var in effect ("" -> JSON null)
};

// Connects to the configured server, completes the handshake, and reads the leaf
// certificate. On failure returns an Observation with connected=false, never throws.
Observation probe();

// Builds a MITM_PIN_FAILURE report from the observation, signs it with the build's
// Ed25519 seed, and posts it to the server. Returns true only on HTTP 200. Never throws.
bool send_report(const Observation& obs);

// The SPKI pin compiled into this build, exposed for the probe tool.
std::string pinned_spki();

// The device id compiled into this build, exposed for the probe tool.
std::string device_id();

} 
