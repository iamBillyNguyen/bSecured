# bSecured guard

The runtime detection that bSecured compiles into a protected application. The
prototype ships one guard: a minimal anti-MitM check. It runs on a background
thread, and on each poll it opens a TLS connection to the bSecured server and
compares the server's certificate public-key hash (SPKI) against the one built
into the binary. A mismatch means something is sitting between the application
and the server; the guard signs a report with the build's device key and sends
it to the server.

The guard is detection-only. It never blocks the application and never crashes
it: every error is swallowed, and if the guard cannot start, the application
still runs.

## What a build carries

Each build is configured at compile time (the CLI fills these in; see
`include/bsecured_config.h.in`):

* the server host, port and report URL,
* the **pinned SPKI** — base64 SHA-256 of the server's expected public key,
* this build's **device id** and its **Ed25519 signing seed**,
* a CA bundle for verification (empty means the system trust store),
* the poll interval.

The binary holds the device id and the seed, never the dashboard key. Extracting
them lets someone send reports as that one device; it does not let them read any.

## How it is injected

`include/bsecured_guard.h` is force-included into every source file of the
target. It is deliberately tiny: it only places a one-line initializer that calls
`ensure_started()`. However many files include it, `std::call_once` starts the
guard exactly once. The real work — OpenSSL, libcurl, libsodium — lives in the
linked static library `libbsecured_guard.a`, not in the header, so the target's
compile cost barely moves.

## Reporting policy

Report on change. A persisting mismatch is reported once, not on every poll. When
the connection recovers (the pin matches again) the guard re-arms, so a later
mismatch is reported again. Recovery is not itself a report, because the minimal
server accepts only `MITM_PIN_FAILURE`. A send that fails leaves the guard armed,
so the next poll retries.

## Building it on its own

```bash
cmake -S guard -B guard/build \
  -DBSEC_PINNED_SPKI=<base64 sha256 spki> \
  -DBSEC_SERVER_PORT=8443 -DBSEC_REPORT_URL=https://host:8443 \
  -DBSEC_DEVICE_ID=dev-… -DBSEC_SEED_B64=<base64 seed> -DBSEC_BUILD_ID=bsec-…
cmake --build guard/build
```

The pin for a server's certificate is computed with the standard recipe:

```bash
openssl x509 -in cert.pem -pubkey -noout \
  | openssl pkey -pubin -outform der \
  | openssl dgst -sha256 -binary | openssl base64
```

`bsecured_probe` prints what one connection reveals, and `--report` sends a
report if the pin does not match — useful for the demo and for testing the check
without the full application.

```
$ bsecured_probe
connected:        yes
observed SPKI:    lzg+xJeaQetCdw524q+tw3IsTeF7I6iE6Vbi+jy+N74=
pinned SPKI:      lzg+xJeaQetCdw524q+tw3IsTeF7I6iE6Vbi+jy+N74=
pin:              MATCH
issuer:           /CN=localhost/O=bSecured Test
system trust ok:  yes
proxy env:        (none)
```

## Dependencies

`libssl`/`libcrypto` (the pin check and SPKI hash), `libcurl` (sending the
report), `libsodium` (Ed25519 signing). On Debian/Ubuntu:

```bash
sudo apt install libssl-dev libcurl4-openssl-dev libsodium-dev cmake g++
```

OpenSSL does the pin check directly rather than through libcurl, so the check
behaves the same regardless of which TLS backend the target's libcurl uses. On
the Linux target libcurl's backend is already OpenSSL, so nothing extra is
linked in practice.

## Not in the prototype

Anti-debugging and tamper detection (designed in §7.4), the post-link `.text`
digest, classifying benign interception from hostile (§6), and replay protection
(Term 2). The guard records what it observed and lets the server hold it.
