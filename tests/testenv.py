"""
Shared test infrastructure for VMODEM tests.

Provides DOSBoxTestEnv for creating isolated DOS environments,
helper functions for telnet protocol handling, and the test runner.
"""

import argparse
import os
import random
import shutil
import socket
import subprocess
import sys
import tempfile
import time

# Paths relative to this script
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SRC_DIR = os.path.join(SCRIPT_DIR, "..", "src")
DOSENV_DIR = os.path.join(SCRIPT_DIR, "..", "..", "dosenv")
DOSBOX_CONF = os.path.join(SCRIPT_DIR, "dosbox-test.conf")

# DOSBox-X binary - try several locations
DOSBOX_CANDIDATES = [
    os.path.join(SCRIPT_DIR, "..", "..", "dosbox-x-src", "src", "dosbox-x"),
    shutil.which("dosbox-x") or "",
]

HOST = "127.0.0.1"
PORT = 2323
VERBOSE = False


def set_verbose(v):
    global VERBOSE
    VERBOSE = v


def is_verbose():
    return VERBOSE


def find_dosbox():
    for path in DOSBOX_CANDIDATES:
        if path and os.path.isfile(path) and os.access(path, os.X_OK):
            return os.path.abspath(path)
    raise FileNotFoundError(
        "dosbox-x not found. Checked: " + ", ".join(DOSBOX_CANDIDATES)
    )


def log(msg):
    print(f"  [{msg}]")


def vlog(msg):
    if VERBOSE:
        print(f"  [DEBUG] {msg}")


class DOSBoxTestEnv:
    """Creates an isolated temporary DOS environment per test."""

    def __init__(self):
        self.tmpdir = None
        self.proc = None
        self.xvfb = None
        self.drive_c = None

    def setup(self, autoexec_lines):
        """Create isolated temp dir with copies of all required DOS files."""
        self.tmpdir = tempfile.mkdtemp(prefix="vmodem_test_")
        self.drive_c = os.path.join(self.tmpdir, "C")
        os.makedirs(self.drive_c)

        # Copy packet drivers (only NE2000.COM needed)
        pkt_dir = os.path.join(self.drive_c, "packet")
        os.makedirs(pkt_dir)
        ne2k_src = os.path.join(DOSENV_DIR, "packet", "NE2000.COM")
        if os.path.exists(ne2k_src):
            shutil.copy2(ne2k_src, os.path.join(pkt_dir, "NE2000.COM"))
        else:
            raise FileNotFoundError(f"Missing {ne2k_src}")

        # Copy mTCP DHCP binary and create fresh config
        mtcp_dir = os.path.join(self.drive_c, "mtcp")
        os.makedirs(mtcp_dir)
        dhcp_src = os.path.join(DOSENV_DIR, "mtcp", "dhcp.exe")
        if os.path.exists(dhcp_src):
            shutil.copy2(dhcp_src, os.path.join(mtcp_dir, "dhcp.exe"))
        with open(os.path.join(mtcp_dir, "MTCP.CFG"), "w") as f:
            f.write("packetint 0x60\nhostname vmodem-dos\n")

        # Copy test executables
        vm_dir = os.path.join(self.drive_c, "vmodem")
        os.makedirs(vm_dir)
        for exe in ["vmodem.exe", "comtest.exe", "vmodctl.exe"]:
            src = os.path.join(SRC_DIR, exe)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(vm_dir, exe))
            else:
                raise FileNotFoundError(f"Missing {src} — run wmake first")

        # Build autoexec lines
        bat_lines = [
            "@ECHO OFF",
            f"mount c {self.drive_c}",
            "c:",
            "SET MTCPCFG=C:\\MTCP\\MTCP.CFG",
            "C:\\PACKET\\NE2000.COM 0x60 3 0x300",
            "C:\\MTCP\\DHCP.EXE",
            "CD \\VMODEM",
        ] + autoexec_lines

        # Write a dosbox-x config with our autoexec
        self.conf_path = os.path.join(self.tmpdir, "test.conf")
        with open(DOSBOX_CONF, "r") as src:
            conf = src.read()
        # Replace autoexec section
        conf = conf.split("[autoexec]")[0]
        conf += "[autoexec]\n"
        for line in bat_lines:
            conf += line + "\n"
        with open(self.conf_path, "w") as f:
            f.write(conf)

        vlog(f"Test env: {self.tmpdir}")
        vlog(f"Drive C: {self.drive_c}")

    def start(self, timeout=60):
        """Start DOSBox-X (headless via Xvfb if available)."""
        dosbox = find_dosbox()
        env = os.environ.copy()

        # Try Xvfb for headless — use a random display to avoid conflicts
        try:
            display_num = random.randint(50, 199)
            self.xvfb = subprocess.Popen(
                ["Xvfb", f":{display_num}", "-screen", "0", "1024x768x24",
                 "-nolisten", "tcp"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(0.5)
            if self.xvfb.poll() is not None:
                # Xvfb failed to start (display taken?), try another
                display_num = random.randint(200, 299)
                self.xvfb = subprocess.Popen(
                    ["Xvfb", f":{display_num}", "-screen", "0", "1024x768x24",
                     "-nolisten", "tcp"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                time.sleep(0.5)
            env["DISPLAY"] = f":{display_num}"
            vlog(f"Using Xvfb :{display_num}")
        except FileNotFoundError:
            vlog("Xvfb not found, using current DISPLAY")

        self.dosbox_log = os.path.join(self.tmpdir, "dosbox.log")
        self._dosbox_logf = open(self.dosbox_log, "w")
        self.proc = subprocess.Popen(
            [dosbox, "-conf", self.conf_path, "-exit"],
            stdout=self._dosbox_logf,
            stderr=subprocess.STDOUT,
            env=env,
        )
        vlog(f"DOSBox-X PID: {self.proc.pid}")

    def wait_for_listen(self, timeout=45):
        """Wait until the VMODEM TCP listener is accepting connections.
        WARNING: This consumes a connection. Only use for non-network tests."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                s = socket.create_connection((HOST, PORT), timeout=1)
                s.close()
                vlog("TCP listener is up")
                return True
            except (ConnectionRefusedError, OSError, socket.timeout):
                time.sleep(0.5)
        return False

    def wait_for_comtest_ready(self, timeout=90):
        """Wait for COMTEST.RDY flag file to appear.
        COMTEST writes this file and closes it before starting its wait loop.
        Unlike COMTEST.LOG, this is immediately visible to the host because
        DOSBox-X flushes on fclose()."""
        rdy_path = os.path.join(self.drive_c, "vmodem", "COMTEST.RDY")
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc and self.proc.poll() is not None:
                vlog("DOSBox-X exited before COMTEST was ready")
                return False
            if os.path.exists(rdy_path):
                try:
                    size = os.path.getsize(rdy_path)
                    if size > 0:
                        with open(rdy_path, "r") as f:
                            content = f.read().strip()
                        vlog(f"COMTEST ready: {content}")
                        return True
                except IOError:
                    pass
            time.sleep(0.5)
        return False

    def wait_for_exit(self, timeout=30):
        """Wait for DOSBox-X to exit."""
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()

    def read_comtest_log(self):
        """Read COMTEST.LOG from the guest C: drive."""
        log_path = os.path.join(self.drive_c, "vmodem", "COMTEST.LOG")
        if os.path.exists(log_path):
            with open(log_path, "r") as f:
                return f.read()
        return None

    def cleanup(self, preserve=False):
        """Stop DOSBox-X and remove temp files."""
        if hasattr(self, '_dosbox_logf') and self._dosbox_logf:
            self._dosbox_logf.close()
        if self.proc and self.proc.poll() is None:
            self.proc.kill()  # SIGKILL — DOSBox-X prompts on SIGTERM
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass
        if self.xvfb and self.xvfb.poll() is None:
            self.xvfb.kill()
            try:
                self.xvfb.wait(timeout=3)
            except subprocess.TimeoutExpired:
                pass
        if self.tmpdir and not preserve:
            shutil.rmtree(self.tmpdir, ignore_errors=True)
        elif self.tmpdir and preserve:
            vlog(f"Preserved temp dir: {self.tmpdir}")


def parse_comtest_log(log_text):
    """Parse COMTEST.LOG, return list of (status, name, detail) tuples."""
    results = []
    if not log_text:
        return results
    for line in log_text.strip().split("\n"):
        line = line.strip()
        if line.startswith("PASS:") or line.startswith("FAIL:"):
            parts = line.split(":", 1)
            status = parts[0].strip()
            rest = parts[1].strip() if len(parts) > 1 else ""
            # rest is "TEST_NAME detail..."
            tokens = rest.split(None, 1)
            name = tokens[0] if tokens else "UNKNOWN"
            detail = tokens[1] if len(tokens) > 1 else ""
            results.append((status, name, detail))
    return results


def strip_telnet_iac(data):
    """Remove telnet IAC sequences from data."""
    result = b""
    i = 0
    while i < len(data):
        if data[i] == 0xFF and i + 1 < len(data):
            cmd = data[i + 1]
            if cmd in (0xFB, 0xFC, 0xFD, 0xFE) and i + 2 < len(data):
                i += 3  # WILL/WONT/DO/DONT + option
            elif cmd == 0xFF:
                result += b"\xFF"
                i += 2
            else:
                i += 2
        else:
            result += bytes([data[i]])
            i += 1
    return result


def recv_until_connect(sock, timeout=30):
    """Receive data until CONNECT message appears, stripping telnet IAC."""
    buf = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock.settimeout(max(0.5, deadline - time.time()))
        try:
            chunk = sock.recv(1024)
            if not chunk:
                break
            buf += chunk
            clean = strip_telnet_iac(buf)
            if b"onnect" in clean.lower():
                vlog(f"Got CONNECT (raw={buf!r})")
                return True
        except socket.timeout:
            continue
    vlog(f"No CONNECT received (raw={buf!r})")
    return False


def connect_with_retries(host=HOST, port=PORT, retries=15):
    """Connect to VMODEM with retries, return socket or None."""
    sock = None
    for attempt in range(retries):
        try:
            sock = socket.create_connection((host, port), timeout=2)
            break
        except (ConnectionRefusedError, OSError):
            vlog(f"Connection attempt {attempt+1} refused, retrying...")
            time.sleep(1)
    if sock:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return sock


def wait_for_rdy(env, marker, timeout=60):
    """Wait for COMTEST.RDY to contain a specific marker string."""
    rdy_path = os.path.join(env.drive_c, "vmodem", "COMTEST.RDY")
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(rdy_path):
            try:
                with open(rdy_path, "r") as f:
                    content = f.read().strip()
                if marker in content:
                    return True
            except IOError:
                pass
        time.sleep(0.5)
    return False


def run_log_only_test(test_name, comtest_cmd, vmodem_args="/L:1:2323 /D:VMODEM.LOG",
                      min_results=1):
    """Run a simple test that only needs COMTEST.LOG results (no TCP interaction)."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            f"VMODEM {vmodem_args}",
            f"COMTEST {comtest_cmd}",
            "EXIT",
        ])
        env.start()
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print(f"FAIL: {test_name} - no COMTEST.LOG found")
            return False

        results = parse_comtest_log(log_text)
        if VERBOSE:
            print(f"  LOG:\n{log_text}")

        passed = all(r[0] == "PASS" for r in results) and len(results) >= min_results
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return passed
    finally:
        env.cleanup()
