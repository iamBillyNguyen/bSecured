// Orchestration: start once, then run two watches, each on its own thread and
// interval, that report a changed detection: the server's key (anti-MitM) and the
// process's tracer (anti-debugging). Separate threads keep a slow TLS handshake
// from delaying debugger detection. All network and crypto work is in detect.cpp.
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
                if (pin_matches(obs.observed_spki))
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

// The anti-debugging watch: read our own tracing state on an interval and report a
// newly attached tracer, once. Runs forever.
//
// A debugger pauses every thread when it attaches, this one included, so a report
// goes out only once the debugger lets the process run again.
void watch_debugger_forever()
{
    // The process id of the last tracer we reported. 0 means "armed".
    long last_reported = 0;

    for (;;)
    {
        try
        {
            const TracerObservation obs = check_tracer();

            if (obs.tracer_pid == 0)
            {
                // Re-arm: no trace now, so the next is new
                last_reported = 0;
            }
            if (obs.tracer_pid != last_reported)
            {
                // If send succeeds, save pid only, else retry on the next poll
                if (send_debugger_report(obs)) 
                {
                    last_reported = obs.tracer_pid;
                }
            }
            // Else: stay quiet, the same trace is still attached
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
// Initializes libsodium and libcurl, then launches each watch on its own detached
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
            thread(watch_debugger_forever).detach();
        }
        catch (...)
        {
            // If the guard cannot start, the application still runs.
        }
    });
}

}
