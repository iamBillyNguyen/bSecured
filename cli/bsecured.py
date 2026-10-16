"""bsecured: build a CMake application with the bSecured guard compiled in.

    python bsecured.py --in <project> [--out DIR] [--seed STRING] [--build-command CMD]
    python bsecured.py dashboard [DIR]      # open a built application's live dashboard
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
DASHBOARD_PAGE = pathlib.Path(__file__).resolve().parents[1] / "dashboard" / "index.html"
POLL_SECONDS = 5
MIN_CMAKE_FOR_INJECTION = (3, 28)  # CMAKE_PROJECT_TOP_LEVEL_INCLUDES (3.24+); 3.28 matches Ubuntu 24.04 LTS

# Skipped when copying the project, so build trees, VCS data and bSecured's own
# state never travel into the copy.
COPY_IGNORE = shutil.ignore_patterns(".git", STATE_DIR, "build", "cmake-build-*",
                                     "__pycache__", "*.seed", ".DS_Store")

# Raised to stop the build with a message worded for the developer.
class BuildError(Exception):
    pass

# Write text to a file that is private (mode 0600) from the moment it is created,
# so the secret is never briefly world-readable.
def private_write(path: pathlib.Path, text: str) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(text)

# A new dashboard key: 32 random bytes as base64url without padding (43 characters).
# The server accepts exactly this form and stores only a hash of it.
def new_dashboard_key() -> str:
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode()

# Read the application's dashboard key from the state folder, creating it on first use.
def dashboard_key(state: pathlib.Path) -> str:
    key_file = state / "dashboard_key"
    if not key_file.exists():
        private_write(key_file, new_dashboard_key() + "\n")
    return key_file.read_text().strip()

# A 32-byte signing seed derived from any string, so --seed can be a short passphrase.
# The same string always yields the same signing key.
def seed_from(text: str) -> bytes:
    return hashlib.sha256(text.encode()).digest()

# Return the server's leaf certificate in DER form, and whether it verified.
def obtain_server_cert(host: str, port: int) -> tuple[bytes, bool]:
    try:
        with socket.create_connection((host, port), timeout=15) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=host) as tls:
                return tls.getpeercert(binary_form=True), True
    except (ssl.SSLError, ssl.CertificateError):
        pass  # Not publicly trusted: fall back to trust on first use, below
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


# base64 SHA-256 of the certificate's SubjectPublicKeyInfo, same value the guard
# computes at runtime and the standard openssl pin recipe produces. openssl does the
# ASN.1 parse; we hash the result.
def spki_pin(cert_der: bytes) -> str:
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


# Register this build's device (its id and public key) with the server under the
# application's dashboard key, so the server will accept the device's signed reports.
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
            context = ssl.create_default_context()  # Verify against the system trust store
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


# Warn if the state folder (which holds keys and seeds) sits in a git work tree but is
# not gitignored, so its secrets are not committed by accident.
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


# Return the path to cmake, or stop the build if it is not installed.
def require_cmake() -> str:
    cmake = shutil.which("cmake")
    if cmake is None:
        raise BuildError("cmake is not installed or not on PATH")
    return cmake


# Read cmake's version as a tuple of integers, e.g. (3, 28, 3).
def cmake_version(cmake: str) -> tuple[int, ...]:
    out = subprocess.run([cmake, "--version"], capture_output=True, text=True).stdout
    for token in out.split():
        if token[:1].isdigit():
            return tuple(int(n) for n in token.split(".")[:3] if n.isdigit())
    return (0,)


# Build the guard static library on its own, and return the exact libraries needed to
# link it into a program — the guard archive plus its dependencies, as CMake resolved
# them for this platform.
def build_guard(cmake: str, state: pathlib.Path, cfg: dict[str, str]) -> list[str]:
    guard_build = state / "guard-build"
    shutil.rmtree(guard_build, ignore_errors=True)  # Clean build: config changes every run
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
    after_output = tokens.index("-o") + 2  # Skip "-o" and the executable name
    archive = guard_build / "libbsecured_guard.a"
    return [str(archive) if pathlib.Path(t).name == archive.name else t for t in tokens[after_output:]]


# Write the file CMake includes during the target's first project() call, before any
# target is defined. It only sets directory properties — no project(), no find_package()
def write_inject_cmake(state: pathlib.Path, link_libs: list[str]) -> pathlib.Path:
    # Quote a value as a CMake string literal.
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


# Confirm the force-include reached the target's own sources, and return how many were checked.
def verify_injection(build_dir: pathlib.Path, root: pathlib.Path) -> int:
    db_path = build_dir / "compile_commands.json"
    if not db_path.is_file():
        raise BuildError("cannot verify injection: CMake did not produce compile_commands.json")
    entries = json.loads(db_path.read_text())
    checked = 0
    for entry in entries:
        source = pathlib.Path(entry["file"]).resolve()
        if root not in source.parents or GUARD_DIR in source.parents:
            continue  # Only the target's own sources, not the guard's
        command = entry.get("command", "") or " ".join(entry.get("arguments", []))
        if "bsecured_guard.h" not in command:
            raise BuildError(f"the guard was not injected into {source.name}; aborting rather than ship it unprotected")
        checked += 1
    if checked == 0:
        raise BuildError("no target source files were found to verify the guard against")
    return checked


# Run cmake with the given arguments, stopping the build if it fails.
def run_cmake(cmake: str, args: list[str], what: str) -> None:
    if subprocess.run([cmake, *args]).returncode != 0:
        raise BuildError(f"{what} failed; see the CMake output above")


# Run the user's build command in the build tree, stopping the build if it fails.
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


# Copy the project, pin the server, build and inject the guard, register the device, and
# write the build manifest. The project at --in is only read; everything happens in the
# build directory.
def build(src: pathlib.Path, seed_text: str | None, server: str, build_command: str,
          out: pathlib.Path | None, inject_guard: bool = True) -> None:
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
                "        Set BSEC_SERVER_URL to the https endpoint.")
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
    state.mkdir(parents=True, mode=0o700, exist_ok=True)  # Persists across builds: holds the dashboard key
    warn_if_committable(state)

    project = state / "project"
    shutil.rmtree(project, ignore_errors=True)
    shutil.copytree(src, project, ignore=COPY_IGNORE)

    # The server certificate: pinned for the guard, and trusted for the https calls.
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
        if not trusted:
            print(f"warning: {host}:{port} is not publicly trusted; trusting its certificate on first use",
                  file=sys.stderr)
            print(f"         server key pin: {pin}", file=sys.stderr)

    seed = seed_from(seed_text) if seed_text else os.urandom(32)
    public_key = bytes(SigningKey(seed).verify_key)
    # A new device on every build, even when --seed reuses a signing key.
    device_id = f"dev-{os.urandom(8).hex()}"
    build_id = f"bsec-{os.urandom(3).hex()}"

    register_device(server, dashboard_key(state), device_id, public_key, cafile, trusted)
    seed_file = state / f"{device_id}.seed"
    private_write(seed_file, base64.b64encode(seed).decode() + "\n")

    build_dir = state / "build"
    shutil.rmtree(build_dir, ignore_errors=True)  # Clean build: no stale cache or compile_commands
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
        print("guard:   not injected")

    print("\nTo watch for detections live, open this application's dashboard:")
    print(f"    {sys.executable} {sys.argv[0]} dashboard {shlex.quote(os.path.relpath(workspace))}")


# Serve this application's dashboard on loopback and open it in a browser.
# The page is served on 127.0.0.1 only and is handed the server address and the dashboard
# key through /config.json, so the key never appears in a link or in browser history.
def serve_dashboard(server_url: str, key: str, port: int, open_browser: bool) -> None:
    import http.server
    import socketserver
    import webbrowser

    class LoopbackServer(http.server.HTTPServer):
        def server_bind(self) -> None:
            # Skip the reverse-DNS lookup HTTPServer does here: it can stall for
            # seconds and the name is never used.
            socketserver.TCPServer.server_bind(self)
            self.server_name, self.server_port = "127.0.0.1", self.server_address[1]

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if self.headers.get("Host") not in self.server.allowed_hosts:
                self.send_error(403)
                return
            if self.path == "/":
                body, content_type = self.server.page, "text/html; charset=utf-8"
            elif self.path == "/config.json":
                body, content_type = self.server.config, "application/json"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args) -> None:
            pass  # Keep the terminal quiet

    httpd = LoopbackServer(("127.0.0.1", port), Handler)
    bound = httpd.server_address[1]
    httpd.page = DASHBOARD_PAGE.read_bytes()
    httpd.config = json.dumps({"server_url": server_url.rstrip("/"), "dashboard_key": key}).encode()
    httpd.allowed_hosts = {f"127.0.0.1:{bound}", f"localhost:{bound}"}

    url = f"http://127.0.0.1:{bound}/"
    print(f"dashboard: {url}   (Ctrl+C to stop)", flush=True)
    if open_browser:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


# Open a built application's live dashboard. DIR is the build directory holding
# .bsecured/ (default: the current folder). The dashboard reads from the server the
# build registered with, unless --url overrides.
def dashboard_command(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="bsecured dashboard",
        description="Open a built application's live dashboard in a browser.")
    parser.add_argument("dir", nargs="?", type=pathlib.Path, default=pathlib.Path("."), metavar="DIR",
                        help="the build directory holding .bsecured/ (default: the current folder)")
    parser.add_argument("--url", default=None, metavar="URL",
                        help="the bSecured server to read from (default: the one this build used)")
    parser.add_argument("--port", type=int, default=0, help="loopback port to serve on (0 picks a free one)")
    parser.add_argument("--no-browser", action="store_true", help="print the URL but do not open a browser")
    args = parser.parse_args(argv)

    state = args.dir / STATE_DIR
    key_file = state / "dashboard_key"
    if not key_file.exists():
        print(f"bsecured: no {key_file}; run a build first, or pass the build directory "
              f"(the folder holding {STATE_DIR}/)", file=sys.stderr)
        return 1

    # Read from the server this build registered with; --url overrides, then the
    # environment, then the default.
    server = args.url
    manifest = state / "build.json"
    if server is None and manifest.exists():
        try:
            server = json.loads(manifest.read_text()).get("server")
        except (OSError, ValueError):
            server = None
    server = (server or os.environ.get("BSEC_SERVER_URL") or DEFAULT_SERVER).rstrip("/")

    serve_dashboard(server, key_file.read_text().strip(), args.port, not args.no_browser)
    return 0


# Entry point: route the 'dashboard' subcommand, otherwise parse the build arguments
# and run a guarded build.
def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "dashboard":
        return dashboard_command(argv[1:])

    parser = argparse.ArgumentParser(
        prog="bsecured", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"The server is $BSEC_SERVER_URL, or {DEFAULT_SERVER} if it is unset.\n"
               "Run 'bsecured dashboard [DIR]' to open a built application's live dashboard.")
    parser.add_argument("--in", dest="src", type=pathlib.Path, required=True, metavar="DIR",
                        help="the project root holding the top-level CMakeLists.txt (read only; never modified)")
    parser.add_argument("--out", dest="out", type=pathlib.Path, default=None, metavar="DIR",
                        help="the build directory (default: a sibling folder named <project>-bsecured)")
    parser.add_argument("--seed", help="any string; the signing key is derived from it (random if omitted)")
    parser.add_argument("--build-command", dest="build_command", default=DEFAULT_BUILD_COMMAND, metavar="CMD",
                        help=f"command run in the build tree to compile (default: {DEFAULT_BUILD_COMMAND!r})")
    args = parser.parse_args(argv)

    server = (os.environ.get("BSEC_SERVER_URL") or DEFAULT_SERVER).rstrip("/")
    try:
        build(args.src, args.seed, server, build_command=args.build_command, out=args.out)
    except BuildError as error:
        print(f"bsecured: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
