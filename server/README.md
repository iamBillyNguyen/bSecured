# bSecured server

Receives signed detection reports from injected guards, keeps them in memory, and
streams them live to a dashboard. A Node.js / Express app (Node ≥ 18). Prototype
scope: the minimal anti-MitM guard is the only reporter, and the store is
in-memory — a database and hosting are Term-2 work.

## Run locally

```bash
cd server
npm install
node server.js                 # HTTP on http://127.0.0.1:8000, in-memory store
```

For the guard's TLS pin check the server must speak HTTPS. Point it at a
certificate and its key:

```bash
BSEC_TLS_CERT=dev-cert.pem BSEC_TLS_KEY=dev-key.pem node server.js   # HTTPS
```

An HTTPS server reloads its certificate on **`SIGHUP`** (`kill -HUP <pid>`) without
a restart: it re-reads `BSEC_TLS_CERT`/`BSEC_TLS_KEY` and swaps them on the live
listener, so the in-memory store, registered devices, and the dashboard's SSE stream
all survive. This is how a rotated key reaches a pinning guard during a demo.

Configuration is read from the environment (see `.env.example`): `BSEC_HOST`,
`BSEC_PORT`, `BSEC_MAX_BODY_BYTES`, and the two `BSEC_TLS_*` paths. Nothing here
is secret — the server stores no keys.

In a second terminal you can exercise the server without compiling anything, using
the Python helper scripts in `scripts/` (they need a Python environment with
`pynacl`). `scripts/devices.py` registers a device the way the `bsecured` tool does
during a build, and `scripts/local_dashboard.py` opens the dashboard on this
computer:

```bash
python3 scripts/devices.py register       # creates the dashboard key and one device
python3 scripts/local_dashboard.py        # opens the dashboard in your browser
```

Then send a report with the command `register` printed. It appears on the
dashboard live. `--forge` signs with a random key and must be rejected.

## Tests

```bash
npm test                        # runs `node --test`, in-memory store
```

## One dashboard per protected application

There are no user accounts. Each protected application has its own secret
**dashboard key** (32 random bytes, base64url, 43 characters), which the `bsecured`
tool creates the first time it builds the application and keeps in the build
directory's gitignored `.bsecured/` (the original project is left untouched). A
developer with several applications has one dashboard link per application.
Internally the server calls whatever a key opens a *project*: one project per
protected application.

* The server never stores the key — only `project_id`, the first 32 hex characters
  of `SHA-256(key)`. It cannot hand the key back, and reading the server's memory
  does not recover it.
* A protected binary carries a **device id and its signing seed**, never the
  dashboard key. Extracting it lets someone send reports, not read them.
* A report never names its project. The server takes the project from the device
  that signed it, so a key pulled from one binary cannot inject reports into
  another developer's dashboard.
* The dashboard runs on the developer's computer, not on this server. The local
  page gets the key from its own `/config.json` and sends it to this server in an
  `Authorization: Bearer` header, so the key never appears in a link, in browser
  history, or in this server's logs. **The server serves no web pages at all.**
* Losing the key loses access to the project. There is no recovery, by design.

## Endpoints

| Method | Path | Auth | Purpose |
| :--- | :--- | :--- | :--- |
| POST | `/v1/devices` | dashboard key | Register a device under the key's project, or re-key one already in it |
| POST | `/v1/reports` | device signature | Ingest one report |
| GET | `/v1/reports` | dashboard key | The project's recent reports, newest first |
| GET | `/v1/stream` | dashboard key | The project's new reports, as Server-Sent Events |
| GET | `/healthz` | none | Liveness: `{"ok":true,"store":"memory"}` |

**Cross-origin reads.** `GET` requests are accepted from pages on the loopback
address (`localhost`, `127.0.0.1`, `[::1]`, any port), which is where the local
dashboard runs. That setting only lets the browser deliver the responses; the
dashboard key in the header is what protects them. Browsers may not call `POST`
endpoints cross-origin, so a page can never register devices or send reports.

`POST /v1/devices` takes `{"device_id": "...", "public_key": "<base64, 32 bytes>"}`
and returns `409 device_id_taken` if the id already belongs to another project.

## Report protocol

The contract the C++ guard must meet. `scripts/send_report.py` is its executable
reference.

```
POST /v1/reports
Content-Type: application/json
X-BSec-Signature: <base64 Ed25519 detached signature over the exact body bytes>

{"v":1,"device_id":"dev-endpoint-01","build_id":"bsec-4f2a91",
 "detected_at":"2026-10-08T14:03:12.301Z","threat_type":"MITM_PIN_FAILURE",
 "evidence":{"observed_spki":"…","system_trust_ok":true,"issuer":"…","proxy_env":null}}
```

* **Sign the bytes you send.** The server verifies over the raw body and never
  re-serialises it — the stored JSON does not even keep your key order. Signatures
  are verified with Node's built-in `crypto` (Ed25519), no external dependency.
* **Keys.** The guard holds a 32-byte seed, derives its keypair with libsodium's
  `crypto_sign_seed_keypair()`, and signs with `crypto_sign_detached()`.
* **`detected_at`** is UTC with `Z` or an explicit offset. It is the client's clock,
  so it is stored as evidence; `received_at` on the server orders everything.
* **Evidence** is a flat object of at most 32 string/number/boolean/null values.

| Evidence field | Meaning |
| :--- | :--- |
| `observed_spki` | base64 SHA-256 of the presented leaf certificate's SubjectPublicKeyInfo |
| `system_trust_ok` | whether the chain validated against the operating system's trust store |
| `issuer` | the leaf certificate's issuer |
| `proxy_env` | the proxy environment variable in effect, or null |

| Status | Body | Meaning |
| :--- | :--- | :--- |
| 200 | `{"report_id", "received_at"}` | Stored. Time send-to-here as the round trip |
| 400 | `{"error": "malformed"}` | Not a valid report |
| 401 | `{"error": "rejected"}` | Unregistered device or bad signature — one answer for both on purpose |
| 413 | `{"error": "too_large"}` | Over `BSEC_MAX_BODY_BYTES` (default 8 KiB) |

## Notes

* Viewers are grouped by project in the stream hub, so a report can only be
  offered to its own project's dashboards.
* The dashboard page (`../dashboard/index.html`) renders with `textContent` only —
  every evidence value is attacker-controlled.
* `scripts/local_dashboard.py` answers only requests addressed to its own
  `127.0.0.1:<port>`, so a web page that rebinds its domain name to the loopback
  address cannot read `/config.json`.
* The stream sets `X-Accel-Buffering: no` and `Cache-Control: no-cache`, so an
  nginx-style proxy will not buffer the live events — relevant once the server is
  hosted behind one.

## Deferred to Term 2

PostgreSQL persistence (the prototype keeps everything in memory, so a restart
clears it) and cloud hosting; replay protection (per-report nonce and seen-nonce
store) and a freshness window; incident aggregation for flood resistance; rate
limits on reports and on project and device creation; per-device enrollment on end
users' machines (the prototype registers one device key per build); and the
anti-debugging and tamper-detection guards.
