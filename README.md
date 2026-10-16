# bSecured

> WORK IN PROGRESS

The `bsecured` tool
compiles a detection guard into an existing CMake application without changing its
source, and the guard reports tampering to a server that shows detections live. Below, we outline the  steps to reproduce the anti-mitm demonstration on a Linux host. Essentially, we have verified it on Ubuntu 24.04.

## Repository layout

| Directory | Component |
| :--- | :--- |
| `server/` | Device registration, report ingestion, per-application read API and live SSE stream (Node.js, Express; in-memory)
| `dashboard/` | The dashboard page — runs on the developer's computer, reads from the server
| `cli/` | `bsecured` tool: pins the server, injects the guard into a CMake build, and builds it
| `guard/` | Injected runtime detection (C++): minimal anti-MitM pin check + signed report
| `sample-project/` | A sample C++ application to harden: a terminal notebook that runs until you quit

## Dependencies

### System packages

| Need | Why | Ubuntu / Debian |
| :--- | :--- | :--- |
| Node.js ≥ 18 + npm | the server | `nodejs npm`
| Python 3.11+ | the `bsecured` tool | `python3 python3-venv`
| C++17 compiler, Make | build the guard and the sample | `build-essential`
| CMake ≥ 3.28 | guard injection (`CMAKE_PROJECT_TOP_LEVEL_INCLUDES`) | `cmake`
| pkg-config | lets CMake locate libsodium during the guard build | `pkg-config`
| OpenSSL (dev + CLI) | the guard's TLS pin check; the tool computes the pin | `libssl-dev openssl`
| libcurl (OpenSSL) | the guard sends the signed report | `libcurl4-openssl-dev`
| libsodium | Ed25519 signing in the guard | `libsodium-dev`

```bash
# Ubuntu / Debian
sudo apt install nodejs npm python3 python3-venv build-essential cmake pkg-config libssl-dev libcurl4-openssl-dev libsodium-dev openssl
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

## Run and test the prototype

**Scope note.** Steps 1 and 2 below — establishing a local certificate authority (CA),
installing it in the system trust store, and importing it into the browser — constitute
local-development scaffolding. They are required only because the demonstration runs a
self-signed server on the loopback interface, and they are not part of the bSecured design.
In the hosted deployment planned for the subsequent course (COMP 8900), the server presents
a publicly trusted certificate, which renders the local CA, the trust-store installation,
and the browser import unnecessary; a developer then targets the hosted address and both the
guard and the browser trust it automatically.

The demonstration proceeds as follows:

1. Establish a local CA,
   install it in the system trust store, and import `demo-ca-cert.pem` into the browser
   (Certificates → Authorities, trusted to identify websites):
   ```bash
   cd server
   openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
     -keyout demo-ca-key.pem -out demo-ca-cert.pem -subj "/CN=bSecured demo CA"
   sudo cp demo-ca-cert.pem /usr/local/share/ca-certificates/bsecured-demo-ca.crt
   sudo update-ca-certificates
   ```
2. Issue the server
   certificate from the CA (Subject Alternative Name `IP:127.0.0.1`) and confirm it chains to
   the trusted CA (expected output: `server-cert.pem: OK`):
   ```bash
   openssl req -newkey rsa:2048 -nodes -keyout server-key.pem -out server.csr -subj "/CN=127.0.0.1"
   openssl x509 -req -in server.csr -CA demo-ca-cert.pem -CAkey demo-ca-key.pem \
     -CAcreateserial -days 7 -out server-cert.pem -extfile <(printf "subjectAltName=IP:127.0.0.1")
   openssl verify -CAfile /etc/ssl/certs/ca-certificates.crt server-cert.pem
   ```
3. Start the server over HTTPS and leave it running:
   ```bash
   BSEC_PORT=8443 BSEC_TLS_CERT=server-cert.pem BSEC_TLS_KEY=server-key.pem node server.js
   ```
4. Build the sample application with the guard:
   ```bash
   BSEC_SERVER_URL=https://127.0.0.1:8443 \
     .venv/bin/python cli/bsecured.py --in sample-project --seed demo-seed
   ```
5. Open the live dashboard:
   ```bash
   .venv/bin/python cli/bsecured.py dashboard sample-project-bsecured
   ```
6. Run the guarded application:
   ```bash
   sample-project-bsecured/.bsecured/build/notes
   ```
7. Induce the risk — re-issue a certificate from the same CA (repeating Step 2's two OpenSSL
   commands) and reload the running server without restarting it:
   ```bash
   kill -HUP "$(pgrep -f 'node server.js')"
   ```
8. Observe the dashboard: a `MITM_PIN_FAILURE` incident appears in real time within
   approximately five seconds.

**Success:** within about 5 seconds the guard's next poll sees the new key, and a
`MITM_PIN_FAILURE` **pushes onto the dashboard live**. Its evidence carries the
observed key, the certificate issuer, and `system_trust_ok: true` — the realistic
fingerprint of a trusted-looking interceptor. This is also where the two-machine
(two-distribution) setup is exercised.