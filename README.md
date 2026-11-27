# bSecured

> WORK IN PROGRESS

The `bsecured` tool compiles a detection guard into an existing CMake application without
changing its source, and the guard reports tampering to a hosted server that shows detections
live. Below, we give the dependencies and the steps to set up, run, and test the tool on a
Linux host. We have verified it on Ubuntu 24.04 (ARM64).

Unlike the earlier prototype, the monitoring backend is now deployed to a hosted platform
(Express.js on Render, backed by a managed PostgreSQL database on Neon) and presents a
publicly trusted certificate. No local certificate authority, trust-store import, or local
server is required to reproduce the demonstration: the orchestrator and guard target the
hosted address directly.

## Repository layout

| Directory | Component |
| :--- | :--- |
| `server/` | Device registration, report ingestion, per-application read API, and live SSE stream (Node.js, Express). Deployed to Render; persists to a managed PostgreSQL database on Neon, with an in-memory store kept only as a local fallback.
| `dashboard/` | The dashboard page — runs on the developer's computer, reads from the hosted server over the live SSE stream
| `cli/` | `bsecured` tool: pins the server's public key, injects the guard into a CMake build, and builds it
| `guard/` | Injected runtime detection (C++): anti-MitM public-key pin check (with a backup-pin set) and anti-debugging tracer check, each sending a signed report
| `sample-project/` | A sample C++ application to harden: a terminal notebook that runs until you quit

## Dependencies

### System packages

The build host needs the toolchain to build and run a guarded application; the interception
and cross-distribution tests additionally need mitmproxy and Docker.

| Need | Why | Ubuntu / Debian |
| :--- | :--- | :--- |
| Python 3.11+ | the `bsecured` tool | `python3 python3-venv`
| C++17 compiler, Make | build the guard and the sample | `build-essential`
| CMake ≥ 3.28 | guard injection (`CMAKE_PROJECT_TOP_LEVEL_INCLUDES`) | `cmake`
| pkg-config | lets CMake locate libsodium during the guard build | `pkg-config`
| OpenSSL (dev + CLI) | the guard's TLS pin check; the tool computes the pin | `libssl-dev openssl`
| libcurl (OpenSSL) | the guard sends the signed report | `libcurl4-openssl-dev`
| libsodium | Ed25519 signing in the guard | `libsodium-dev`
| mitmproxy | interception test (anti-MitM detection, backup pin) | `mitmproxy`
| Docker | cross-distribution portability test | `docker.io`
| GDB | anti-debugging test (T4) | `gdb`
| Node.js ≥ 18 + npm | report-authenticity test; running the server locally (optional — it is already hosted) | `nodejs npm`

```bash
# Ubuntu / Debian
sudo apt install python3 python3-venv build-essential cmake pkg-config \
                 libssl-dev libcurl4-openssl-dev libsodium-dev openssl \
                 mitmproxy docker.io gdb nodejs npm
```

### Language packages

* **cli** (`cli/requirements.txt`): `pynacl`, installed into a Python virtual environment.
* **server** (`server/package.json`): `express` and `pg` (the PostgreSQL client). Node's
  built-in `crypto` does the Ed25519 verification. These are needed for the server's unit
  tests and to run it locally; the hosted deployment already has them. The authenticity check
  (`server/scripts/check-authenticity.js`) uses only Node built-ins.

## Special software, hardware, and access

* **Software.** A Linux host (verified on Ubuntu 24.04). The interception test uses
  **mitmproxy** with transparent `iptables` redirection; the cross-distribution test uses
  **Docker** (a Fedora container stands in for a second distribution); the anti-debugging test
  uses **GDB**.
* **Hardware.** An ordinary 64-bit machine; no special hardware. We have verified the build and
  tests on an ARM64 (aarch64) virtual machine and have not yet tested on x86-64. A single VM is
  sufficient — the interceptor and the guarded binary run on the same host, and Docker provides
  the second distribution.
* **Access.** `sudo` on the test host, to trust mitmproxy's CA, add the `iptables` rule, and
  attach GDB (Ubuntu's default ptrace policy blocks an unprivileged attach). No
  credentials are needed to send reports to the hosted backend. Running or deploying the
  backend yourself additionally requires a **Render** account and a **Neon** PostgreSQL
  connection string (`DATABASE_URL`); neither is needed to reproduce the client-side
  demonstration against the already-deployed backend.

## Set up

```bash
git clone <this repository>
cd bSecured

# The bsecured tool (Python) — a virtual environment at the repo root
python3 -m venv .venv
.venv/bin/pip install -r cli/requirements.txt

# The server's packages, for its unit tests (and, optionally, to run it locally instead of
# the hosted deployment; a local run with PostgreSQL also needs a DATABASE_URL in
# ../.env.local, then: npm run db:init)
cd server && npm install && cd ..
```

## Run

The orchestrator and guard default to the hosted backend (`https://bsecured-server.onrender.com`),
so no server setup is needed.

```bash
# 1. Confirm the hosted backend is live
curl -s https://bsecured-server.onrender.com/healthz

# 2. Build the sample application with the guard, pinned to the hosted backend
.venv/bin/python cli/bsecured.py --in sample-project --seed 123456789

# 3. Open the live dashboard and leave it running
.venv/bin/python cli/bsecured.py dashboard sample-project-bsecured

# 4. Run the guarded application — while the key matches the pin, the guard stays silent
sample-project-bsecured/.bsecured/build/notes
```

## Test

### Anti-MitM detection and the backup pin

Insert mitmproxy so the key the server presents no longer matches the pin. Generate and
trust mitmproxy's CA once, redirect a dedicated user's HTTPS traffic to mitmproxy, run
mitmproxy transparently, and run the guarded binary as that user so only its traffic is
intercepted:

```bash
# generate mitmproxy's CA on first run, then stop it
mitmdump --mode transparent & sleep 2; pkill -f 'mitmdump --mode transparent'

sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy-ca.crt
sudo update-ca-certificates
sudo useradd -m bsecdemo
sudo sysctl -w net.ipv4.ip_forward=1
sudo iptables -t nat -A OUTPUT -p tcp --dport 443 -m owner --uid-owner bsecdemo -j REDIRECT --to-ports 8080
mitmproxy --mode transparent --listen-host 127.0.0.1 --listen-port 8080 --showhost
sudo -u bsecdemo sample-project-bsecured/.bsecured/build/notes
```

**Success:** within about five seconds a `MITM_PIN_FAILURE` incident pushes onto the dashboard
live. Its evidence carries the observed key, the certificate issuer, and `system_trust_ok:
true` — the fingerprint of a trusted-looking interceptor.

To confirm the **backup pin** absorbs a covered key change (a certificate renewal) without a
false alarm, rebuild with the interceptor's key added to the pin set and run it under the same
interception; the guard stays silent (`--backup-pin` may be repeated for several keys):

```bash
.venv/bin/python cli/bsecured.py --in sample-project --seed 123456789 --backup-pin <observed-key>
sudo -u bsecdemo sample-project-bsecured/.bsecured/build/notes
```

### Report authenticity: a forged report is rejected

The server accepts a report only if it is signed by the key registered for its device. To
show that a report signed with any other key is rejected and never stored, run the server's
unit tests, then the same check against the hosted backend:

```bash
# Unit tests, against an in-memory store (no database or network needed)
cd server && npm test && cd ..

# The same check against the hosted backend (Node built-ins only)
node server/scripts/check-authenticity.js
```

The script registers a throwaway device and sends four reports: a genuine one signed with the
device's key, a forged one signed with an attacker's key, the genuine body altered after
signing, and one from a device that was never registered. It then reads back the reports stored
for its project through the same interface the dashboard reads from. Each run leaves its
throwaway device and the one genuine report in the database, under a dashboard key the script
discards, so no dashboard ever shows them.

**Success:** `npm test` passes, including `a forged signature is rejected and nothing is
stored`, and the script prints:

```text
PASS  genuine report, device's key (control)   expected 200, got 200 {"report_id":...}
PASS  forged report, attacker's key            expected 401, got 401 {"error":"rejected"}
PASS  altered body, original signature         expected 401, got 401 {"error":"rejected"}
PASS  unregistered device                      expected 401, got 401 {"error":"rejected"}
PASS  stored for this project                  1 report(s): ["genuine"]
```

The server gives the same `{"error":"rejected"}` for an unknown device and for a bad signature,
so a caller cannot probe for valid device ids. The accepted control shows the device is
registered, so the forged report was rejected for its signature alone. Against a local server
(`node server/scripts/check-authenticity.js http://127.0.0.1:8000`), the server's log names each
reason: `bad_signature` for the forged and altered reports, `unknown_device` for the last.

This covers reports signed with the wrong key or altered after signing. It does not cover a
replayed genuine report, which the server does not yet reject, or a report signed with a key
extracted from the binary itself.

### Anti-debugging detection (T4)

With the guarded application running in one terminal (Run, step 4) and the dashboard open,
attach GDB from a second terminal. Ubuntu's default ptrace policy (`ptrace_scope` 1) lets only
a parent process or root attach, so attach with `sudo`:

```bash
cat /proc/sys/kernel/yama/ptrace_scope     # record the policy; 1 on a default Ubuntu
sudo gdb -p "$(pidof notes)"
```

```text
(gdb) continue
```

GDB pauses every thread when it attaches, the guard's included, so the guard checks again only
after `continue`.

**Success:** within about five seconds of `continue`, one `DEBUGGER_ATTACHED` incident pushes
onto the dashboard. Its evidence names the tracer (`tracer_pid`, `tracer_name=gdb`) and the
`ptrace_scope` in force. While GDB stays attached, no further incident appears.

To confirm that a detach re-arms the guard, interrupt GDB with Ctrl-C, detach, wait at least
five seconds (one polling interval), and attach again from the same GDB session, so the
tracer's process id is unchanged:

```text
(gdb) detach
# wait at least five seconds
(gdb) attach <pid of notes>
(gdb) continue
```

A second incident appears: exactly one per attach. Finally, run the application for a few
minutes with no debugger attached; no `DEBUGGER_ATTACHED` incident appears.

### Cross-distribution portability

Run the Ubuntu-built binary in a Fedora container, a different distribution with its own C
library and system libraries:

```bash
cp sample-project-bsecured/.bsecured/build/notes /tmp/notes
docker run --rm -it -v /tmp/notes:/notes:ro fedora:40 bash
# inside the container:
dnf -y install openssl-libs libsodium libcurl ca-certificates
ln -sf /usr/lib64/libsodium.so.26 /usr/lib64/libsodium.so.23   # ABI-compatible SONAME alias
ldd /notes
/notes
```

The binary runs and the guard operates normally, confirming the build is portable across
distributions.

### Persistence across a restart

Restart the hosted backend from the Render dashboard, then reload the dashboard a few minutes
later: the earlier incident and the registered device are still present, because the backend
persists to PostgreSQL rather than to memory.
