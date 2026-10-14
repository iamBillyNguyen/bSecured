// The two things the guard does: look at the server's certificate, and report
// what it saw. Both are declared here so the standalone probe tool can call them
// with the same code the live guard uses.
#pragma once

#include <string>

// No `using namespace std;` in a header — it would leak into every file that
// includes this. The .cpp files that include it declare their own.

namespace bsecured {

/**
 * What one TLS connection to the server revealed. The fields match the evidence
 * the server records for a MITM_PIN_FAILURE report.
 */
struct Observation
{
    bool connected = false;             // did the TLS handshake complete
    std::string observed_spki;          // base64 SHA-256 of the leaf SPKI ("" if not connected)
    std::string issuer;                 // the leaf certificate's issuer
    bool system_trust_ok = false;       // did the chain verify against the trust store
    std::string proxy_env;              // name of the proxy env var in effect ("" -> JSON null)
};

/**
 * Connects to the configured server, completes the handshake, and reads the leaf
 * certificate. On failure returns an Observation with connected=false, never throws.
 */
Observation probe();

/**
 * Builds a MITM_PIN_FAILURE report from the observation, signs it with the build's
 * Ed25519 seed, and POSTs it to the server. Never throws.
 * @param obs the observation to report
 * @returns true only on HTTP 200
 */
bool send_report(const Observation& obs);

/**
 * The SPKI pin compiled into this build, exposed for the probe tool
 * @returns the pinned base64 SHA-256 of the server's SPKI
 */
std::string pinned_spki();

/**
 * The device id compiled into this build, exposed for the probe tool
 * @returns the device id
 */
std::string device_id();

}  // namespace bsecured
