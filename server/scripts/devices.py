"""Register a device directly against the server, for testing without a build.

    python scripts/devices.py register [--url http://127.0.0.1:8000]

The `bsecured` CLI registers a device as part of building a project. This script
does the same registration on its own, so the server can be exercised with
`send_report.py` without compiling anything. It keeps its state in ./.bsecured/
(gitignored):

    .bsecured/dashboard_key     created on first use, reused afterwards
    .bsecured/<device_id>.seed  the new device's signing seed

Then open the dashboard with scripts/local_dashboard.py, and send a report with
the command this prints.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import sys
import urllib.error
import urllib.request

from nacl.signing import SigningKey

STATE = pathlib.Path(".bsecured")


def new_dashboard_key() -> str:
    # 32 random bytes, base64url without padding: 43 characters. The server
    # accepts exactly this form and stores only a hash of it.
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


def private_write(path: pathlib.Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o600)


def dashboard_key() -> str:
    STATE.mkdir(mode=0o700, exist_ok=True)
    key_file = STATE / "dashboard_key"
    if not key_file.exists():
        private_write(key_file, new_dashboard_key() + "\n")
    return key_file.read_text().strip()


def register(url: str, key: str, device_id: str, public_key: bytes) -> tuple[int, str]:
    body = json.dumps({"device_id": device_id, "public_key": base64.b64encode(public_key).decode()}).encode()
    request = urllib.request.Request(
        url.rstrip("/") + "/v1/devices",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, error.read().decode()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["register"])
    parser.add_argument("--url", default="http://127.0.0.1:8000")
    parser.add_argument("--device-id", default=f"dev-{os.urandom(4).hex()}")
    args = parser.parse_args()

    seed = os.urandom(32)
    status, body = register(args.url, dashboard_key(), args.device_id, bytes(SigningKey(seed).verify_key))
    if status != 200:
        sys.exit(f"registration failed: {status} {body}")

    seed_file = STATE / f"{args.device_id}.seed"
    private_write(seed_file, base64.b64encode(seed).decode() + "\n")

    print(f"device:    {args.device_id}")
    print(f"seed file: {seed_file}")
    print("\nopen the dashboard:\n  .venv/bin/python scripts/local_dashboard.py"
          + ("" if args.url == "http://127.0.0.1:8000" else f" --url {args.url}"))
    print(f'\nsend a report:\n  .venv/bin/python scripts/send_report.py --url {args.url} '
          f'--device {args.device_id} --seed "$(cat {seed_file})"')


if __name__ == "__main__":
    main()
