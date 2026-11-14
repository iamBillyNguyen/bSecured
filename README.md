# bSecured

> WORK IN PROGRESS

The `bsecured` tool compiles a detection guard into an existing CMake application without
changing its source, and the guard reports tampering to a hosted server that shows detections
live. Below, we give the dependencies and the steps to set up, run, and test the tool on a
Linux host. We have verified it on Ubuntu 24.04.

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
| `guard/` | Injected runtime detection (C++): anti-MitM public-key pin check (with a backup-pin set) + signed report
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
| Node.js ≥ 18 + npm | *only to run the server locally* (optional — it is already hosted) | `nodejs npm`

```bash
# Ubuntu / Debian
sudo apt install python3 python3-venv build-essential cmake pkg-config \
                 libssl-dev libcurl4-openssl-dev libsodium-dev openssl \
                 mitmproxy docker.io
```

### Language packages

* **cli** (`cli/requirements.txt`): `pynacl`, installed into a Python virtual environment.
* **server** (`server/package.json`): `express` and `pg` (the PostgreSQL client). Node's
  built-in `crypto` does the Ed25519 verification. These are needed only to run the server
  locally; the hosted deployment already has them.

## Special software, hardware, and access

* **Software.** A Linux host (verified on Ubuntu 24.04). The interception test uses
  **mitmproxy** with transparent `iptables` redirection; the cross-distribution test uses
  **Docker** (a Fedora container stands in for a second distribution).
* **Hardware.** An ordinary x86-64 machine; no special hardware. A single VM is sufficient —
  the interceptor and the guarded binary run on the same host, and Docker provides the second
  distribution.
* **Access.** `sudo` on the test host, to trust mitmproxy's CA and add the `iptables` rule. No
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

# (Optional) the server, only to run it locally instead of using the hosted deployment.
# A local run also needs a PostgreSQL DATABASE_URL in ../.env.local, then: npm run db:init
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
