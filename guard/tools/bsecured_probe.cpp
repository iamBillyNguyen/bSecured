// See one observation without running the whole guard, and optionally send a
// report. Useful for the demo and for testing the pin check on its own.
//
//     bsecured_probe            print what one connection reveals
//     bsecured_probe --report   also send a report if the pin does not match
#include "detect.h"

#include <cstdio>
#include <cstring>

#include <curl/curl.h>
#include <sodium.h>

using namespace std;

// Prints what one connection to the server reveals, and optionally reports a mismatch.
// Pass --report to send a report when the pin does not match. Returns 0 on success,
// 1 if not connected or the report failed, and 2 on an initialization error.
int main(int argc, char** argv)
{
    const bool do_report = argc > 1 && strcmp(argv[1], "--report") == 0;
    if (sodium_init() < 0)
    {
        fprintf(stderr, "libsodium failed to initialize\n");
        return 2;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);

    const bsecured::Observation obs = bsecured::probe();
    printf("connected:        %s\n", obs.connected ? "yes" : "no");
    if (!obs.connected)
    {
        printf("could not complete a TLS handshake with the server\n");
        return 1;
    }
    const bool matches = obs.observed_spki == bsecured::pinned_spki();
    printf("observed SPKI:    %s\n", obs.observed_spki.c_str());
    printf("pinned SPKI:      %s\n", bsecured::pinned_spki().c_str());
    printf("pin:              %s\n", matches ? "MATCH" : "MISMATCH (interception?)");
    printf("issuer:           %s\n", obs.issuer.c_str());
    printf("system trust ok:  %s\n", obs.system_trust_ok ? "yes" : "no");
    printf("proxy env:        %s\n", obs.proxy_env.empty() ? "(none)" : obs.proxy_env.c_str());

    if (do_report && !matches)
    {
        const bool sent = bsecured::send_report(obs);
        printf("report sent:      %s\n", sent ? "yes (200)" : "no");
        return sent ? 0 : 1;
    }
    return 0;
}
