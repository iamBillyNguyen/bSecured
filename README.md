# bSecured

Compile-time runtime self-protection (RASP) for native C++ applications on Linux,
with authenticated telemetry to a live monitoring dashboard. The `bsecured` tool
compiles a detection guard into an existing CMake application without changing its
source, and the guard reports tampering to a server that shows detections live.

## The question this prototype answers

**Can a detection guard be injected into an unmodified third-party CMake build, and
can that guard report a man-in-the-middle (MitM) interception to a central dashboard
in a way the server can trust?**

The prototype implements one guard end to end — a minimal anti-MitM certificate
check — because it exercises every layer the full project depends on: build
injection, a native runtime guard, authenticated ingestion, and a live dashboard.

**What counts as success.** Each is reproducible with the steps below:

1. `bsecured` injects the guard into every source file of the sample application
   **without editing the application**, and refuses to finish if injection did not
   take effect.
2. A guarded binary whose pinned key matches the server stays **silent**; when the
   server presents a different key, the guard **detects the mismatch**.
3. The server accepts a correctly **signed** report and **rejects a forged one**
   (HTTP 401), and a report can only be **read with the application's dashboard key**.
4. An accepted report appears on the dashboard **live** (within ~1 s).

## Repository layout

| Directory | Component | Status |
| :--- | :--- | :--- |
| `server/` | Device registration, report ingestion, per-application read API and live SSE stream (Node.js, Express; in-memory) | Built |
| `dashboard/` | The dashboard page — runs on the developer's computer, reads from the server | Built |
| `cli/` | `bsecured` tool: pins the server, injects the guard into a CMake build, and builds it | Built |
| `guard/` | Injected runtime detection (C++): minimal anti-MitM pin check + signed report | Built |
| `sample-project/` | A sample C++ application to harden: a terminal notebook that runs until you quit | Built |

One repository on purpose: a change to the report format touches the guard, the
server and the tooling together, and one commit identifies the state of the whole
system for every recorded result. Each directory has its own README with detail;
this file is the setup, run, and test guide for the whole prototype.

## Special software, hardware, and access needed

**Software.** **Node.js 18 or newer and npm** for the server. **Python 3.11+ with
`pynacl`** for the `bsecured` tool. For the guard: a C++17 compiler, CMake **3.28 or
newer** (the injection mechanism needs it), OpenSSL (libraries and the `openssl`
command), libcurl built against OpenSSL, and libsodium. Exact packages and install
commands are in [Dependencies](#dependencies). For the full interception
demonstration, an interception proxy such as **mitmproxy**.

**Hardware.** The prototype runs on a single Linux machine (or macOS for
development). The **graded deliverable targets two Linux machines on different glibc
distributions** — the `bsecured` tool and compiler on one host, the protected
application on another — to show the guard is portable across distributions. Nothing
in the prototype needs more than an ordinary laptop.

**Access.** The guard reports to a bSecured server reachable over **HTTPS**. For
local testing this is a self-signed server you run yourself (steps below); for the
recorded demonstration it is a deployed instance with a real certificate. **No user
account or login is needed** anywhere: a dashboard is opened with a per-application
key the tool generates, not with credentials. The server keeps everything **in
memory** — there is no database to set up (persistence is deferred to COMP 8900).

## Dependencies

### System packages

| Need | Why | Ubuntu / Debian | macOS (Homebrew) |
| :--- | :--- | :--- | :--- |
| Node.js ≥ 18 + npm | the server | `nodejs npm` | `node` |
| Python 3.11+ | the `bsecured` tool | `python3 python3-venv` | `python3` |
| C++17 compiler, Make | build the guard and the sample | `build-essential` | Xcode command-line tools |
| CMake ≥ 3.28 | guard injection (`CMAKE_PROJECT_TOP_LEVEL_INCLUDES`) | `cmake` | `cmake` |
| OpenSSL (dev + CLI) | the guard's TLS pin check; the tool computes the pin | `libssl-dev openssl` | `openssl@3` |
| libcurl (OpenSSL) | the guard sends the signed report | `libcurl4-openssl-dev` | ships with macOS |
| libsodium | Ed25519 signing in the guard | `libsodium-dev` | `libsodium` |

```bash
# Ubuntu / Debian
sudo apt install nodejs npm python3 python3-venv build-essential cmake \
                 libssl-dev libcurl4-openssl-dev libsodium-dev openssl

# macOS
brew install node cmake openssl@3 libsodium       # Python 3 and curl are already present
```

### Language packages

* **server** (`server/package.json`): `express`. Node's built-in `crypto` does the
  Ed25519 verification — no other runtime dependency.
* **cli** (`cli/requirements.txt`): `pynacl`, installed into a Python virtual environment.

## Set up

```bash
git clone <this repository>

# Server (Node.js)
cd bSecured/server
npm install

# The bsecured tool (Python) — a separate virtual environment at the repo root
cd ..
python3 -m venv .venv
.venv/bin/pip install -r cli/requirements.txt
```

The C++ dependencies are the system packages above; there is nothing more to install
for the guard.

## Run and test the prototype

Three self-contained tracks, each reproducible on one machine; together they cover
the four success conditions. Run them from the repository root unless noted.

### Track 1 — Automated server tests (the ingestion and trust logic)

```bash
cd server
npm test
```

**Success:** all tests pass. They cover signature verification, per-application
isolation, the uniform 401 for forged or unknown senders, and that a report cannot
name its own project.

### Track 2 — The guard detects a man-in-the-middle (the core question)

Builds the sample application with the guard compiled in and checks the pin against a
server. No browser involved.

```bash
# 1. A self-signed certificate for a local HTTPS server
cd server
openssl req -x509 -newkey rsa:2048 -nodes -keyout dev-key.pem -out dev-cert.pem \
  -days 7 -subj "/CN=localhost/O=bSecured dev" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

# 2. Start the server over HTTPS, in-memory store (leave running)
BSEC_PORT=8443 BSEC_TLS_CERT=dev-cert.pem BSEC_TLS_KEY=dev-key.pem node server.js

# 3. Second terminal, from the repository root: build the sample WITH the guard
BSEC_SERVER_URL=https://127.0.0.1:8443 \
  .venv/bin/python cli/bsecured.py --in sample-project --seed demo-seed
```

The tool copies `sample-project/` to a sibling `sample-project-bsecured/` (**the
original is never modified**), registers a device, injects the guard into all three
source files, and builds. It prints `guard: injected into 3 source file(s)`. Because
the server is self-signed it also prints the server's key pin (trust on first use);
pass `--expect-pin <pin>` to require a known one.

```bash
# 4. Good path: the pinned key matches, so the guard stays silent
sample-project-bsecured/.bsecured/build/notes      # type a few commands, then `quit`

# 5. Detection: ask the built-in probe what the server is presenting
sample-project-bsecured/.bsecured/guard-build/bsecured_probe        # -> pin: MATCH

#    Simulate an interceptor: stop the server (Ctrl+C), restart it with a DIFFERENT
#    certificate, then run the probe again.
cd server
openssl req -x509 -newkey rsa:2048 -nodes -keyout evil-key.pem -out evil-cert.pem \
  -days 1 -subj "/CN=localhost/O=Interceptor" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
BSEC_PORT=8443 BSEC_TLS_CERT=evil-cert.pem BSEC_TLS_KEY=evil-key.pem node server.js
# back in the repository root:
sample-project-bsecured/.bsecured/guard-build/bsecured_probe        # -> pin: MISMATCH
```

**Success:** `MATCH` on the original certificate and `MISMATCH` on the swapped one,
and the guarded `notes` sends no report while the pin matches. That is the anti-MitM
detection working. (Delivering that detection *through* a live interceptor needs the
report channel to trust the proxy's certificate authority — see the full demo note
and "What is simulated" below.)

### Track 3 — Live server and dashboard (authenticated ingestion, shown live)

Shows a signed report arriving on the dashboard in real time, over loopback HTTP so
no browser certificate trust is needed. It uses the server-side helper scripts, which
stand in for a reporting guard.

```bash
# 1. Start the server over HTTP, in-memory store
cd server
node server.js

# 2. Second terminal (in server/): register a device and open the dashboard
../.venv/bin/python scripts/devices.py register      # creates the dashboard key + one device
../.venv/bin/python scripts/local_dashboard.py       # opens the dashboard in your browser

# 3. Third terminal (in server/): send a signed report — use the command `register` printed
../.venv/bin/python scripts/send_report.py --url http://127.0.0.1:8000 \
    --device <device-id> --seed "$(cat .bsecured/<device-id>.seed)"
#    add --forge to sign with the wrong key; it must be rejected with 401
```

**Success:** the report **pushes onto the dashboard live** over the SSE stream (within
about a second); `--forge` is rejected (401) and never appears; opening the dashboard
needs the application's key.

### Full interception demonstration (the recorded video)

The complete guard → server → dashboard path under a real interceptor is the scenario
for the demo video. It needs a server with a certificate the endpoint trusts (the
deployed instance, or a local certificate authority you install) and an interception
proxy (e.g. `mitmproxy`) whose certificate authority is in the endpoint's system
trust store. The guarded application is built against that server, run behind the
proxy, and the pin mismatch is detected and delivered, appearing on the dashboard as
a `MITM_PIN_FAILURE`. This is also where the two-machine (two-distribution) setup is
exercised. See `guard/README.md` and `server/README.md`.

## What is implemented, reused, and simulated

**Implemented for the prototype**

* `bsecured` build injection into an unmodified CMake project, with post-configure
  verification that the guard reached every source file (`cli/`).
* The anti-MitM guard: an OpenSSL TLS handshake, its own SubjectPublicKeyInfo (SPKI)
  pin comparison, and an Ed25519-signed report sent with libcurl — started once from a
  force-included header and reporting only when the observed key changes (`guard/`).
* The server: device registration, signed-report ingestion, a per-application read
  API, and a live Server-Sent Events stream, with an in-memory store (`server/`).
* The dashboard page that reads and streams an application's detections (`dashboard/`).

**Reused** (not written here): Express and Node's built-in `crypto` (Ed25519
verification); PyNaCl and libsodium (Ed25519 signing); OpenSSL; libcurl; CMake.

**Simulated or stood in for**

* The two server-side scripts (`server/scripts/devices.py`, `send_report.py`) stand in
  for a reporting guard so the server can be exercised without a C++ build.
* Local tracks use a self-signed server. Because the guard pins a self-signed server's
  exact certificate for its report channel, a report cannot be *delivered* through an
  interceptor locally — detection still fires; delivery through a proxy is shown in the
  full demo against a trusted-certificate server.

**Not in the prototype (designed, deferred):** anti-debugging and tamper-detection
guards; classifying benign interception (corporate proxy, captive portal) from
hostile; replay protection; and the two other injection fallback mechanisms. These are
described in the proposal (§7) and the component READMEs.

## Secrets — do not commit

The tool keeps each build's state in a gitignored `.bsecured/` directory inside the
build folder: the application's **dashboard key**, each device's **signing seed**, and
the pinned server certificate. These are secrets. Never commit `.bsecured/`, `*.seed`,
or a real `.env`; the repository's `.gitignore` already excludes them, and the tool
warns if it detects otherwise.

## Where to go next

* [`server/README.md`](server/README.md) — the API, the report protocol, and the one-dashboard-per-application model.
* [`guard/README.md`](guard/README.md) — the guard's design, configuration, and the standalone probe.
* The proposal (`../Proposal/bSecured.md`, §7) — the full design and how the prototype narrows it.
