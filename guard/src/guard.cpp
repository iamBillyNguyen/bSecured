// Orchestration: start once, then poll the server on an interval and report a
// changed detection. All network and crypto work is in detect.cpp.
#include "bsecured_guard.h"

#include "bsecured_config.h"
#include "detect.h"

#include <chrono>
#include <mutex>
#include <thread>

#include <curl/curl.h>
#include <sodium.h>

using namespace std;

namespace bsecured {
namespace {

// The guard's background loop: check the server on an interval and report a changed
// detection. Report-on-change policy:
//   pin matches       -> re-arm, stay quiet (a recovery is not itself a report,
//                        because the minimal server only accepts failures)
//   new failing cert  -> report, then remember it
//   same failing cert -> stay quiet
// A send that fails leaves us armed, so the next poll retries. Runs forever.
void poll_forever()
{
    // The SPKI of the last failure we reported. Empty means "armed".
    string last_reported;

    for (;;)
    {
        try
        {
            const Observation obs = probe();
            if (obs.connected)
            {
                if (obs.observed_spki == pinned_spki())
                {
                    last_reported.clear();
                }
                else if (obs.observed_spki != last_reported)
                {
                    if (send_report(obs))
                    {
                        last_reported = obs.observed_spki;
                    }
                }
            }
        }
        catch (...)
        {
            // A guard must never bring down the application it protects.
        }
        this_thread::sleep_for(chrono::seconds(BSEC_POLL_SECONDS));
    }
}

}

// Starts the background guard on the first call; later calls do nothing.
// Initializes libsodium and libcurl, then launches the poll loop on a detached
// thread. Never throws: if the guard cannot start, the application still runs.
void ensure_started() noexcept
{
    static once_flag once;
    call_once(once, []
    {
        try
        {
            if (sodium_init() < 0)
            {
                return;
            }
            curl_global_init(CURL_GLOBAL_DEFAULT);
            thread(poll_forever).detach();
        }
        catch (...)
        {
            // If the guard cannot start, the application still runs.
        }
    });
}

}
