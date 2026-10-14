"""Send one signed report to a bSecured server, standing in for the C++ guard.

This is also the executable definition of the wire protocol: the guard must
produce the same kind of request.

    python scripts/send_report.py --url http://127.0.0.1:8000 \\
        --device <device_id> --seed "$(cat .bsecured/<device_id>.seed)"

`scripts/devices.py register` prints this command with the values filled in.

    --forge    sign with a random key instead of the device's; must be rejected (401)

Prints the HTTP status, the round-trip time, and the response body.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from nacl.signing import SigningKey

DEFAULT_EVIDENCE = {
    "observed_spki": "Zm9yZ2VkLXNwa2ktaGFzaC1mb3ItdGVzdGluZy1vbmx5",
    "system_trust_ok": True,
    "issuer": "mitmproxy",
    "proxy_env": None,
}


def build_report(device_id: str, build_id: str, evidence: dict) -> bytes:
    body = {
        "v": 1,
        "device_id": device_id,
        "build_id": build_id,
        "detected_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
        "threat_type": "MITM_PIN_FAILURE",
        "evidence": evidence,
    }
    return json.dumps(body, separators=(",", ":")).encode()


def send(url: str, raw: bytes, key: SigningKey) -> tuple[int, float, str]:
    signature = base64.b64encode(key.sign(raw).signature).decode()
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/reports",
        data=raw,
        method="POST",
        headers={"Content-Type": "application/json", "X-BSec-Signature": signature},
    )
    started = time.perf_counter_ns()
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            status, body = response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        status, body = error.code, error.read().decode()
    return status, (time.perf_counter_ns() - started) / 1e6, body


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--device", required=True)
    parser.add_argument("--seed", required=True, help="base64 seed, from .bsecured/<device_id>.seed")
    parser.add_argument("--build", default="bsec-dev")
    parser.add_argument("--evidence", default=json.dumps(DEFAULT_EVIDENCE))
    parser.add_argument("--forge", action="store_true")
    args = parser.parse_args()

    key = SigningKey(os.urandom(32) if args.forge else base64.b64decode(args.seed))
    raw = build_report(args.device, args.build, json.loads(args.evidence))
    status, rtt_ms, body = send(args.url, raw, key)
    print(f"{'forged' if args.forge else 'report'} status={status} rtt_ms={rtt_ms:.1f} body={body}")


if __name__ == "__main__":
    main()
