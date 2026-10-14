"""bsecured: build a CMake application with the bSecured guard compiled in.

    python bsecured.py --in <project> [--out DIR] [--seed STRING]
                       [--build-command CMD] [--expect-pin PIN] [--no-guard]

The project at --in is only ever read. bSecured copies it into a build directory
(default: a sibling folder named "<project>-bsecured") and does everything there,
so the original project is never modified.

Each build gets its own device: a new device id and a signing key, registered with
the bSecured server under the application's dashboard key. Pass --seed to derive the
signing key from a fixed string (the same string gives the same key); the device id
is still new each build.

A guarded build pins the server's certificate: the CLI reads the server's public
key, hashes it, and compiles that hash into the binary. At runtime the guard
compares what the server presents against it and reports a mismatch. This needs
an https server, so set BSEC_SERVER_URL to the https endpoint. Use --no-guard to
build without the guard (any server), which is only useful during development.

The certificate is read over a verified connection when the server is publicly
trusted, so a man-in-the-middle at build time cannot substitute the key being
pinned. A server the system does not trust (a self-signed dev server) is trusted
on first use, and its key pin is printed; pass --expect-pin to require a known one.

The server is http://127.0.0.1:8000 unless BSEC_SERVER_URL names another. Once
the hosted server exists, its https address becomes the default.

The build directory holds the project copy and all state under .bsecured/, which
must never be committed:

    .bsecured/dashboard_key      the application's key, created on the first build
    .bsecured/<device_id>.seed   each build device's signing seed
    .bsecured/server.pem         the server certificate this build was pinned to
    .bsecured/inject.cmake       how the guard was injected
    .bsecured/project/           a fresh copy of the project (rebuilt each run)
    .bsecured/guard-build/       the compiled guard library for this build
    .bsecured/build/             the CMake build tree and compiled output
    .bsecured/build.json         what the last build was made with (no secrets)
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import pathlib
import shlex
import shutil
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urlsplit

from nacl.signing import SigningKey

DEFAULT_SERVER = "http://127.0.0.1:8000"
DEFAULT_BUILD_COMMAND = "cmake --build ."
STATE_DIR = ".bsecured"
GUARD_DIR = pathlib.Path(__file__).resolve().parents[1] / "guard"
POLL_SECONDS = 5
MIN_CMAKE_FOR_INJECTION = (3, 28)  # CMAKE_PROJECT_TOP_LEVEL_INCLUDES (3.24+); 3.28 matches Ubuntu 24.04 LTS
# Skipped when copying the project, so build trees, VCS data and bSecured's own
# state never travel into the copy.
COPY_IGNORE = shutil.ignore_patterns(".git", STATE_DIR, "build", "cmake-build-*",
                                     "__pycache__", "*.seed", ".DS_Store")


class BuildError(Exception):
    """A reason the build cannot go on, worded for the developer."""


def private_write(path: pathlib.Path, text: str) -> None:
    # Created 0600 from the start, so the secret is never briefly world-readable.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)


def new_dashboard_key() -> str:
    # 32 random bytes, base64url without padding: 43 characters. The server
    # accepts exactly this form and stores only a hash of it.
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()


def dashboard_key(state: pathlib.Path) -> str:
    key_file = state / "dashboard_key"
    if not key_file.exists():
        private_write(key_file, new_dashboard_key() + "\n")
    return key_file.read_text().strip()


def seed_from(text: str) -> bytes:
    """A 32-byte signing seed derived from any string, so --seed can be a short
    passphrase. The same string always yields the same signing key."""
    return hashlib.sha256(text.encode()).digest()


def obtain_server_cert(host: str, port: int) -> tuple[bytes, bool]:
    """The server's leaf certificate in DER form, and whether it was verified.

    A verified connection is tried first, so a man-in-the-middle at build time
    cannot substitute the certificate we are about to pin. Only when the server is
    not publicly trusted (a self-signed dev server) does this fall back to reading
    the certificate without verification — trust on first use, which the caller
    surfaces to the developer.

    Whether the certificate verified also decides what the guard's report channel
    trusts: a trusted server -> the system store, so a report can still get out
    through a proxy whose CA the system trusts (the corporate-inspection case);
    a self-signed server -> pin that exact certificate.
    """
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), True
    except (ssl.SSLError, ssl.CertificateError):
        pass  # not publicly trusted: fall back to trust on first use, below
    except OSError as error:
        raise BuildError(f"cannot reach the server at {host}:{port}: {error}") from None

    unverified = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    unverified.check_hostname = False
    unverified.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with unverified.wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), False
    except OSError as error:
        raise BuildError(f"cannot read the server certificate at {host}:{port}: {error}") from None


def spki_pin(cert_der: bytes) -> str:
    """base64 SHA-256 of the certificate's SubjectPublicKeyInfo.

    The same value the guard computes at runtime and the standard `openssl`
    pin recipe produces. openssl does the ASN.1 parse; we hash the result.
    """
    openssl = shutil.which("openssl")
    if openssl is None:
        raise BuildError("openssl is not installed or not on PATH; it is needed to compute the pin")
    pubkey = subprocess.run([openssl, "x509", "-inform", "DER", "-pubkey", "-noout"],
                            input=cert_der, capture_output=True)
    spki_der = subprocess.run([openssl, "pkey", "-pubin", "-outform", "DER"],
                              input=pubkey.stdout, capture_output=True)
    if pubkey.returncode != 0 or spki_der.returncode != 0 or not spki_der.stdout:
        raise BuildError("openssl could not read the server's public key from its certificate")
    return base64.b64encode(hashlib.sha256(spki_der.stdout).digest()).decode()


def register_device(server: str, key: str, device_id: str, public_key: bytes,
                    cafile: pathlib.Path | None, trusted: bool) -> None:
    body = json.dumps({"device_id": device_id, "public_key": base64.b64encode(public_key).decode()}).encode()
    request = urllib.request.Request(
        server + "/v1/devices",
        data=body,
        method="POST",
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {key}"},
    )
    context = None
    if server.startswith("https"):
        if trusted:
            context = ssl.create_default_context()  # verify against the system trust store
        else:
            # Trust exactly the certificate we just read. Hostname is not re-checked:
            # the pinned certificate is the identity here, not the name in it.
            context = ssl.create_default_context(cafile=str(cafile))
            context.check_hostname = False
    try:
        with urllib.request.urlopen(request, timeout=15, context=context):
            return
    except urllib.error.HTTPError as error:
        if error.code == 409:
            raise BuildError(f"device id {device_id} already belongs to another application; use another seed") from None
        raise BuildError(f"the server refused the device: {error.code} {error.read().decode(errors='replace')}") from None
    except urllib.error.URLError as error:
        # A binary whose device is not registered would have every report
        # rejected, and nobody would notice. Better to stop here.
        raise BuildError(f"cannot reach the bSecured server at {server}: {error.reason}") from None


def warn_if_committable(state: pathlib.Path) -> None:
    git = shutil.which("git")
    if git is None:
        return
    parent = state.parent
    inside = subprocess.run([git, "-C", str(parent), "rev-parse", "--is-inside-work-tree"], capture_output=True)
    if inside.returncode != 0:
        return
    ignored = subprocess.run([git, "-C", str(parent), "check-ignore", "-q", str(state)])
    if ignored.returncode != 0:
        print(f"warning: {state} holds secrets (keys, seeds) and is not gitignored; add it before committing",
              file=sys.stderr)


def require_cmake() -> str:
    cmake = shutil.which("cmake")
    if cmake is None:
        raise BuildError("cmake is not installed or not on PATH")
    return cmake


def cmake_version(cmake: str) -> tuple[int, ...]:
    out = subprocess.run([cmake, "--version"], capture_output=True, text=True).stdout
    for token in out.split():
        if token[:1].isdigit():
            return tuple(int(n) for n in token.split(".")[:3] if n.isdigit())
    return (0,)


def build_guard(cmake: str, state: pathlib.Path, cfg: dict[str, str]) -> list[str]:
    """Build the guard static library on its own, and return the exact libraries
    needed to link it into a program — the guard archive plus its dependencies,
    as CMake resolved them for this platform.

    The guard is built separately, not as a subdirectory of the target, because
    the file that injects it runs while the target's first project() call is still
    enabling the compiler: a nested project() there is a recursive-call error, and
    find_package() cannot run yet either. Building here, where the compiler is
    ready, keeps all of that out of the injected file.
    """
    guard_build = state / "guard-build"
    shutil.rmtree(guard_build, ignore_errors=True)  # clean build: config changes every run
    defs = [f"-D{name}={value}" for name, value in cfg.items()]
    # Unix Makefiles so the resolved link line is written to a link.txt we can read.
    run_cmake(cmake, ["-S", str(GUARD_DIR), "-B", str(guard_build), "-G", "Unix Makefiles",
                      "-DCMAKE_BUILD_TYPE=Release", *defs], "building the guard")
    run_cmake(cmake, ["--build", str(guard_build)], "building the guard")

    link_txt = guard_build / "CMakeFiles" / "bsecured_probe.dir" / "link.txt"
    if not link_txt.is_file():
        raise BuildError("could not read the guard's resolved libraries (no link.txt)")
    tokens = shlex.split(link_txt.read_text())
    # link.txt is: c++ <flags> <objects> -o bsecured_probe <libraries...>
    after_output = tokens.index("-o") + 2  # skip "-o" and the executable name
    archive = guard_build / "libbsecured_guard.a"
    return [str(archive) if pathlib.Path(t).name == archive.name else t for t in tokens[after_output:]]


def write_inject_cmake(state: pathlib.Path, link_libs: list[str]) -> pathlib.Path:
    """The file CMake includes during the target's first project() call, before any
    target is defined. It only sets directory properties — no project(), no
    find_package() — so it is safe at that early point: it force-includes the guard
    header into every target compiled afterwards and links the pre-built guard. The
    target's own CMakeLists.txt is never touched.
    """
    def q(value: str) -> str:
        return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'

    libs = " ".join(q(lib) for lib in link_libs)
    lines = [
        "# Generated by bsecured. Do not edit; rebuilt on every run.",
        "# Injects the bSecured guard into this build without changing the target.",
        f"include_directories({q(str(GUARD_DIR / 'include'))})",
        "add_compile_options(-include bsecured_guard.h)",
        f"link_libraries({libs})",
        "",
    ]
    path = state / "inject.cmake"
    path.write_text("\n".join(lines))
    return path


def verify_injection(build_dir: pathlib.Path, root: pathlib.Path) -> int:
    """Confirm the force-include reached the target's own sources. Returns how
    many were checked. Silent non-injection is the failure §7.2 guards against."""
    db_path = build_dir / "compile_commands.json"
    if not db_path.is_file():
        raise BuildError("cannot verify injection: CMake did not produce compile_commands.json")
    entries = json.loads(db_path.read_text())
    checked = 0
    for entry in entries:
        source = pathlib.Path(entry["file"]).resolve()
        if root not in source.parents or GUARD_DIR in source.parents:
            continue  # only the target's own sources, not the guard's
        command = entry.get("command", "") or " ".join(entry.get("arguments", []))
        if "bsecured_guard.h" not in command:
            raise BuildError(f"the guard was not injected into {source.name}; aborting rather than ship it unprotected")
        checked += 1
    if checked == 0:
        raise BuildError("no target source files were found to verify the guard against")
    return checked


def run_cmake(cmake: str, args: list[str], what: str) -> None:
    if subprocess.run([cmake, *args]).returncode != 0:
        raise BuildError(f"{what} failed; see the CMake output above")


def run_build_command(command: str, build_dir: pathlib.Path) -> None:
    argv = shlex.split(command)
    if not argv:
        raise BuildError("--build-command is empty")
    try:
        completed = subprocess.run(argv, cwd=build_dir)
    except FileNotFoundError:
        raise BuildError(f"build command not found: {argv[0]}") from None
    if completed.returncode != 0:
        raise BuildError(f"the build command `{command}` failed; see its output above")


def build(src: pathlib.Path, seed_text: str | None, server: str, inject_guard: bool,
          expect_pin: str | None, build_command: str, out: pathlib.Path | None) -> None:
    src = src.resolve()
    if not (src / "CMakeLists.txt").is_file():
        raise BuildError(f"{src} has no CMakeLists.txt; point --in at the project's root folder")
    cmake = require_cmake()

    parts = urlsplit(server)
    host = parts.hostname or "127.0.0.1"
    port = parts.port or (443 if parts.scheme == "https" else 80)

    if inject_guard:
        if parts.scheme != "https":
            raise BuildError(
                f"a guarded build pins the server certificate, so it needs an https server, not {server!r}.\n"
                "        Set BSEC_SERVER_URL to the https endpoint, or pass --no-guard to build without the guard.")
        if cmake_version(cmake) < MIN_CMAKE_FOR_INJECTION:
            need = ".".join(map(str, MIN_CMAKE_FOR_INJECTION))
            raise BuildError(f"guard injection needs CMake >= {need}; found an older cmake")

    # The project at --in is only ever read. A build directory (default: a sibling
    # named "<project>-bsecured") holds a fresh copy of the project and all bSecured
    # state, so the original project is never modified.
    workspace = (out or src.parent / f"{src.name}-bsecured").resolve()
    if src == workspace or src in workspace.parents:
        raise BuildError("the build directory must be outside the project folder")
    state = workspace / STATE_DIR
    state.mkdir(parents=True, mode=0o700, exist_ok=True)  # persists across builds: holds the dashboard key
    warn_if_committable(state)

    project = state / "project"
    shutil.rmtree(project, ignore_errors=True)
    shutil.copytree(src, project, ignore=COPY_IGNORE)

    # The server certificate: pinned for the guard, and trusted for the https calls.
    # A publicly-trusted server is verified and reported to over the system store (so
    # a report can escape through a system-trusted proxy); a self-signed one is read
    # on first use and pinned, with its key fingerprint shown.
    cafile: pathlib.Path | None = None
    pin = ""
    report_ca = ""
    trusted = False
    if parts.scheme == "https":
        cert_der, trusted = obtain_server_cert(host, port)
        cafile = state / "server.pem"
        cafile.write_text(ssl.DER_cert_to_PEM_cert(cert_der))
        pin = spki_pin(cert_der)
        report_ca = "" if trusted else str(cafile)
        if expect_pin and expect_pin != pin:
            raise BuildError(f"the server's key pin is {pin}, not the --expect-pin value; refusing to build")
        if not trusted:
            print(f"warning: {host}:{port} is not publicly trusted; trusting its certificate on first use",
                  file=sys.stderr)
            print(f"         server key pin: {pin}", file=sys.stderr)
            if not expect_pin:
                print("         pass --expect-pin <pin> to require exactly this key next time", file=sys.stderr)
    elif expect_pin:
        raise BuildError("--expect-pin needs an https server")

    seed = seed_from(seed_text) if seed_text else os.urandom(32)
    public_key = bytes(SigningKey(seed).verify_key)
    # A new device on every build, even when --seed reuses a signing key.
    device_id = f"dev-{os.urandom(8).hex()}"
    build_id = f"bsec-{os.urandom(3).hex()}"

    register_device(server, dashboard_key(state), device_id, public_key, cafile, trusted)
    seed_file = state / f"{device_id}.seed"
    private_write(seed_file, base64.b64encode(seed).decode() + "\n")

    build_dir = state / "build"
    shutil.rmtree(build_dir, ignore_errors=True)  # clean build: no stale cache or compile_commands
    checked = 0
    if inject_guard:
        link_libs = build_guard(cmake, state, {
            "BSEC_SERVER_HOST": host,
            "BSEC_SERVER_PORT": str(port),
            "BSEC_REPORT_URL": server,
            "BSEC_PINNED_SPKI": pin,
            "BSEC_DEVICE_ID": device_id,
            "BSEC_BUILD_ID": build_id,
            "BSEC_SEED_B64": base64.b64encode(seed).decode(),
            "BSEC_CA_FILE": report_ca,
            "BSEC_POLL_SECONDS": str(POLL_SECONDS),
        })
        inject = write_inject_cmake(state, link_libs)
        run_cmake(cmake, ["-S", str(project), "-B", str(build_dir),
                          "-DCMAKE_BUILD_TYPE=Release",
                          f"-DCMAKE_PROJECT_TOP_LEVEL_INCLUDES={inject}",
                          "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"], "configure")
        checked = verify_injection(build_dir, project)
    else:
        run_cmake(cmake, ["-S", str(project), "-B", str(build_dir), "-DCMAKE_BUILD_TYPE=Release"], "configure")
    run_build_command(build_command, build_dir)

    manifest = {
        "build_id": build_id,
        "device_id": device_id,
        "server": server,
        "source": str(src),
        "public_key_sha256": hashlib.sha256(public_key).hexdigest(),
        "built_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "guard_injected": inject_guard,
        "pinned_spki": pin if inject_guard else None,
        "poll_seconds": POLL_SECONDS if inject_guard else None,
    }
    (state / "build.json").write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"\nbuild:   {build_id}")
    print(f"device:  {device_id}  (registered with {server})")
    print(f"source:  {src}  (unchanged)")
    print(f"built:   {build_dir}")
    if inject_guard:
        print(f"guard:   injected into {checked} source file(s); pinned to the server certificate")
    else:
        print("guard:   not injected (--no-guard)")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="bsecured", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"The server is $BSEC_SERVER_URL, or {DEFAULT_SERVER} if it is unset.")
    parser.add_argument("--in", dest="src", type=pathlib.Path, required=True, metavar="DIR",
                        help="the project root holding the top-level CMakeLists.txt (read only; never modified)")
    parser.add_argument("--out", dest="out", type=pathlib.Path, default=None, metavar="DIR",
                        help="the build directory (default: a sibling folder named <project>-bsecured)")
    parser.add_argument("--seed", help="any string; the signing key is derived from it (random if omitted)")
    parser.add_argument("--build-command", dest="build_command", default=DEFAULT_BUILD_COMMAND, metavar="CMD",
                        help=f"command run in the build tree to compile (default: {DEFAULT_BUILD_COMMAND!r})")
    parser.add_argument("--expect-pin", help="refuse to build unless the server's key pin matches this value")
    parser.add_argument("--no-guard", action="store_true", help="build without the guard (development only)")
    args = parser.parse_args(argv)

    server = (os.environ.get("BSEC_SERVER_URL") or DEFAULT_SERVER).rstrip("/")
    try:
        build(args.src, args.seed, server, inject_guard=not args.no_guard,
              expect_pin=args.expect_pin, build_command=args.build_command, out=args.out)
    except BuildError as error:
        print(f"bsecured: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
