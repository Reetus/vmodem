#!/usr/bin/env python3
"""
VMODEM automated test runner.

Launches DOSBox-X with a minimal DOS environment containing only VMODEM,
packet drivers, mTCP, and COMTEST.EXE.  Orchestrates test scenarios by:
  1. Starting DOSBox-X with a test-specific AUTOEXEC.BAT
  2. Connecting via TCP (telnet) from the Python side
  3. Reading COMTEST.LOG from the guest to verify results

Prerequisites:
  - DOSBox-X binary (dosbox-x)
  - Xvfb for headless mode (optional, falls back to visible window)
  - VMODEM.EXE, COMTEST.EXE built in ../src/
  - Packet drivers and mTCP in ../../dosenv/

Usage:
  python3 test_vmodem.py                   # run all tests
  python3 test_vmodem.py test_fossil_init  # run one test
  python3 test_vmodem.py -v                # verbose output
"""

import argparse
import os
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
    """Creates a temporary DOS environment and manages DOSBox-X lifecycle."""

    def __init__(self):
        self.tmpdir = None
        self.proc = None
        self.xvfb = None
        self.drive_c = None

    def setup(self, autoexec_lines):
        """Create temp dir with minimal DOS filesystem and AUTOEXEC.BAT."""
        self.tmpdir = tempfile.mkdtemp(prefix="vmodem_test_")
        # Use the full dosenv as drive C (it has packet drivers, mTCP, etc.)
        self.drive_c = os.path.abspath(DOSENV_DIR)

        # Copy test executables into dosenv/vmodem/
        for exe in ["vmodem.exe", "comtest.exe", "vmodctl.exe"]:
            src = os.path.join(SRC_DIR, exe)
            if os.path.exists(src):
                shutil.copy2(src, os.path.join(self.drive_c, "vmodem", exe.upper()))
            else:
                raise FileNotFoundError(f"Missing {src} — run wmake first")

        # Clean up any previous test artifacts
        for f in ["COMTEST.LOG", "COMTEST.RDY"]:
            old = os.path.join(self.drive_c, "vmodem", f)
            if os.path.exists(old):
                os.remove(old)

        # Build autoexec lines (used in conf [autoexec] section)
        bat_path = os.path.join(self.tmpdir, "AUTOEXEC.BAT")
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
        import random
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

        self.proc = subprocess.Popen(
            [dosbox, "-conf", self.conf_path, "-exit"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
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


# ---- Individual test functions ----


def test_fossil_init():
    """Test FOSSIL init returns signature 0x1954."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323",
            "COMTEST FOSSIL_INIT",
            "EXIT",
        ])
        env.start()
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_fossil_init - no COMTEST.LOG found")
            return False

        results = parse_comtest_log(log_text)
        if VERBOSE:
            print(f"  LOG:\n{log_text}")

        passed = all(r[0] == "PASS" for r in results) and len(results) > 0
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return passed
    finally:
        env.cleanup()


def test_fossil_status():
    """Test FOSSIL status word (THRE set, DCD low when no connection)."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323",
            "COMTEST FOSSIL_STATUS",
            "EXIT",
        ])
        env.start()
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_fossil_status - no COMTEST.LOG found")
            return False

        results = parse_comtest_log(log_text)
        if VERBOSE:
            print(f"  LOG:\n{log_text}")

        passed = all(r[0] == "PASS" for r in results) and len(results) > 0
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return passed
    finally:
        env.cleanup()


def test_mux_status():
    """Test MUX INT 2Fh installation check."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323",
            "COMTEST MUX_STATUS",
            "EXIT",
        ])
        env.start()
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_mux_status - no COMTEST.LOG found")
            return False

        results = parse_comtest_log(log_text)
        if VERBOSE:
            print(f"  LOG:\n{log_text}")

        passed = all(r[0] == "PASS" for r in results) and len(results) > 0
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return passed
    finally:
        env.cleanup()


def test_echo():
    """Test data echo: connect, send data, verify echo back."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323",
            "COMTEST ECHO",
            "EXIT",
        ])
        env.start()

        # Wait for COMTEST to be ready (DOSBox boot + DHCP takes ~30s)
        if not env.wait_for_comtest_ready():
            print("FAIL: test_echo - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # Connect with retries (slirp port forwarding can take a moment)
        test_data = b"HELLO_VMODEM"
        try:
            sock = None
            for attempt in range(15):
                try:
                    sock = socket.create_connection((HOST, PORT), timeout=2)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Connection attempt {attempt+1} refused, retrying...")
                    time.sleep(1)
            if sock is None:
                print("FAIL: test_echo - could not connect after retries")
                env.wait_for_exit(timeout=10)
                return False
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Drain incoming data (IAC negotiation, RING, CONNECT, IAC NOPs)
            # for up to 15 seconds, then send test data.
            # Auto-answer takes ~8 seconds (6s RING_INTERVAL + 2s handshake).
            # COMTEST starts echoing only after DCD goes high (after CONNECT).
            # We send data and look for echo in the received stream.
            pre_buf = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    pre_buf += chunk
                    clean = strip_telnet_iac(pre_buf)
                    # Stop draining once we see "onnect" (from "Connected!")
                    if b"onnect" in clean.lower():
                        vlog(f"Got connect indication")
                        break
                except socket.timeout:
                    continue

            # Brief pause for COMTEST to enter echo mode
            time.sleep(0.5)

            # Send test data
            sock.sendall(test_data)
            vlog(f"Sent: {test_data}")

            # Read echo back (strip telnet IAC)
            echoed_raw = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    echoed_raw += chunk
                    clean = strip_telnet_iac(echoed_raw)
                    if test_data in clean:
                        break
                except socket.timeout:
                    continue

            echoed = strip_telnet_iac(echoed_raw)
            vlog(f"Echoed raw: {echoed_raw!r}")
            vlog(f"Echoed clean: {echoed!r}")

            # Disconnect
            sock.close()
        except Exception as e:
            print(f"FAIL: test_echo - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        # Wait briefly for COMTEST to detect disconnect, then kill DOSBox
        # so log gets flushed via fclose
        time.sleep(5)
        env.wait_for_exit(timeout=45)

        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []
        if VERBOSE and log_text:
            print(f"  LOG:\n{log_text}")

        # Echo match is the primary test
        echo_ok = test_data in echoed
        print(f"  {'PASS' if echo_ok else 'FAIL'}: ECHO_MATCH "
              f"(sent={test_data!r}, got={echoed!r})")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        # Consider pass if echo worked (disconnect detection is secondary)
        return echo_ok
    finally:
        env.cleanup()


def test_full_cycle():
    """Test full lifecycle: connect, exchange greeting, disconnect."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323",
            "COMTEST FULL_CYCLE",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_full_cycle - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            sock = None
            for attempt in range(15):
                try:
                    sock = socket.create_connection((HOST, PORT), timeout=2)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Connection attempt {attempt+1} refused, retrying...")
                    time.sleep(1)
            if sock is None:
                print("FAIL: test_full_cycle - could not connect after retries")
                env.wait_for_exit(timeout=10)
                return False
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Wait for CONNECT, then read greeting from DOS side
            if not recv_until_connect(sock):
                print("FAIL: test_full_cycle - no CONNECT received")
                sock.close()
                env.wait_for_exit(timeout=10)
                return False

            # Read greeting from DOS side ("HELLO_FROM_DOS\r\n")
            greeting = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    greeting += chunk
                    clean = strip_telnet_iac(greeting)
                    if b"HELLO_FROM_DOS" in clean:
                        break
                except socket.timeout:
                    continue

            greeting = strip_telnet_iac(greeting)
            vlog(f"Greeting: {greeting!r}")

            # Send response
            response = b"HELLO_FROM_PYTHON\r\n"
            sock.sendall(response)
            vlog(f"Sent: {response!r}")

            time.sleep(2)
            sock.close()
        except Exception as e:
            print(f"FAIL: test_full_cycle - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_full_cycle - no COMTEST.LOG found")
            return False

        results = parse_comtest_log(log_text)
        if VERBOSE:
            print(f"  LOG:\n{log_text}")

        greeting_ok = b"HELLO_FROM_DOS" in greeting
        print(f"  {'PASS' if greeting_ok else 'FAIL'}: GREETING_RECV "
              f"(got={greeting!r})")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        passed = greeting_ok and all(r[0] == "PASS" for r in results)
        return passed
    finally:
        env.cleanup()


def test_send_text():
    """Test DOS sends text, Python receives it."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323",
            "COMTEST SEND_TEXT HELLO_WORLD",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_send_text - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        received = b""
        try:
            sock = None
            for attempt in range(15):
                try:
                    sock = socket.create_connection((HOST, PORT), timeout=2)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Connection attempt {attempt+1} refused, retrying...")
                    time.sleep(1)
            if sock is None:
                print("FAIL: test_send_text - could not connect after retries")
                env.wait_for_exit(timeout=10)
                return False
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # Read all data until we find our text or timeout.
            # Don't require CONNECT banner — just look for the sent text.
            # Auto-answer + COMTEST send can take ~10s total.
            deadline = time.time() + 45
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    received += chunk
                    clean = strip_telnet_iac(received)
                    if b"HELLO_WORLD" in clean:
                        break
                except socket.timeout:
                    continue

            sock.close()
        except Exception as e:
            print(f"FAIL: test_send_text - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if VERBOSE and log_text:
            print(f"  LOG:\n{log_text}")

        received = strip_telnet_iac(received)
        text_ok = b"HELLO_WORLD" in received
        print(f"  {'PASS' if text_ok else 'FAIL'}: TEXT_RECV "
              f"(got={received!r})")

        if log_text:
            results = parse_comtest_log(log_text)
            for status, name, detail in results:
                print(f"  {status}: {name} {detail}")
        else:
            print("  WARN: no COMTEST.LOG found")

        return text_ok
    finally:
        env.cleanup()


def test_hunt_group():
    """Test hunt group: two connections dispatched to COM1 and COM2."""
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1-2:2323",
            "COMTEST HUNT_GROUP",
            "EXIT",
        ])
        env.start()

        # Wait for COMTEST to init both ports and be ready for first connection
        if not env.wait_for_comtest_ready():
            print("FAIL: test_hunt_group - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # First connection — should be dispatched to COM1
        sock1 = None
        try:
            for attempt in range(15):
                try:
                    sock1 = socket.create_connection((HOST, PORT), timeout=2)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Conn1 attempt {attempt+1} refused, retrying...")
                    time.sleep(1)
            if sock1 is None:
                print("FAIL: test_hunt_group - could not connect (1st)")
                env.wait_for_exit(timeout=10)
                return False
            sock1.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            vlog("First connection established")

            # Drain until Connected! on sock1
            pre1 = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock1.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock1.recv(4096)
                    if not chunk:
                        break
                    pre1 += chunk
                    if b"onnect" in strip_telnet_iac(pre1).lower():
                        break
                except socket.timeout:
                    continue
            vlog(f"Sock1 pre-data: {strip_telnet_iac(pre1)!r}")

        except Exception as e:
            print(f"FAIL: test_hunt_group - TCP error (1st): {e}")
            env.wait_for_exit(timeout=10)
            return False

        # Wait for COMTEST to signal ready for second connection
        # (it writes HUNT_WAITING_DCD2 after detecting DCD on COM1)
        rdy_path = os.path.join(env.drive_c, "vmodem", "COMTEST.RDY")
        deadline = time.time() + 30
        got_dcd2_ready = False
        while time.time() < deadline:
            if os.path.exists(rdy_path):
                try:
                    with open(rdy_path, "r") as f:
                        content = f.read().strip()
                    if "DCD2" in content:
                        got_dcd2_ready = True
                        vlog("COMTEST ready for second connection")
                        break
                except IOError:
                    pass
            time.sleep(0.5)

        if not got_dcd2_ready:
            print("FAIL: test_hunt_group - COMTEST not ready for 2nd connection")
            sock1.close()
            env.wait_for_exit(timeout=10)
            return False

        # Second connection — should be dispatched to COM2
        sock2 = None
        try:
            for attempt in range(15):
                try:
                    sock2 = socket.create_connection((HOST, PORT), timeout=2)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Conn2 attempt {attempt+1} refused, retrying...")
                    time.sleep(1)
            if sock2 is None:
                print("FAIL: test_hunt_group - could not connect (2nd)")
                sock1.close()
                env.wait_for_exit(timeout=10)
                return False
            sock2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            vlog("Second connection established")

            # Drain until Connected! on sock2
            pre2 = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock2.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock2.recv(4096)
                    if not chunk:
                        break
                    pre2 += chunk
                    if b"onnect" in strip_telnet_iac(pre2).lower():
                        break
                except socket.timeout:
                    continue
            vlog(f"Sock2 pre-data: {strip_telnet_iac(pre2)!r}")

        except Exception as e:
            print(f"FAIL: test_hunt_group - TCP error (2nd): {e}")
            sock1.close()
            env.wait_for_exit(timeout=10)
            return False

        # Send different data on each socket to verify port isolation
        time.sleep(0.5)
        data1 = b"PORT_ONE"
        data2 = b"PORT_TWO"
        sock1.sendall(data1)
        sock2.sendall(data2)
        vlog(f"Sent {data1!r} on sock1, {data2!r} on sock2")

        # Read echoes
        echo1 = b""
        echo2 = b""
        deadline = time.time() + 15
        while time.time() < deadline:
            got_both = (data1 in strip_telnet_iac(echo1) and
                        data2 in strip_telnet_iac(echo2))
            if got_both:
                break
            try:
                sock1.settimeout(0.3)
                chunk = sock1.recv(1024)
                if chunk:
                    echo1 += chunk
            except (socket.timeout, OSError):
                pass
            try:
                sock2.settimeout(0.3)
                chunk = sock2.recv(1024)
                if chunk:
                    echo2 += chunk
            except (socket.timeout, OSError):
                pass

        echo1_clean = strip_telnet_iac(echo1)
        echo2_clean = strip_telnet_iac(echo2)
        vlog(f"Echo1: {echo1_clean!r}")
        vlog(f"Echo2: {echo2_clean!r}")

        # Disconnect both
        sock1.close()
        sock2.close()

        # Wait for DOSBox-X to finish
        time.sleep(5)
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if VERBOSE and log_text:
            print(f"  LOG:\n{log_text}")

        # Check results
        echo1_ok = data1 in echo1_clean
        echo2_ok = data2 in echo2_clean
        # Port isolation: sock1 should NOT see data2, sock2 should NOT see data1
        isolation_ok = data2 not in echo1_clean and data1 not in echo2_clean

        print(f"  {'PASS' if echo1_ok else 'FAIL'}: HUNT_ECHO1 "
              f"(sent={data1!r}, got={echo1_clean!r})")
        print(f"  {'PASS' if echo2_ok else 'FAIL'}: HUNT_ECHO2 "
              f"(sent={data2!r}, got={echo2_clean!r})")
        print(f"  {'PASS' if isolation_ok else 'FAIL'}: HUNT_ISOLATION "
              f"(port data not cross-contaminated)")

        if log_text:
            results = parse_comtest_log(log_text)
            for status, name, detail in results:
                print(f"  {status}: {name} {detail}")

        return echo1_ok and echo2_ok and isolation_ok
    finally:
        env.cleanup()


# ---- Test registry ----

ALL_TESTS = {
    "test_fossil_init": test_fossil_init,
    "test_fossil_status": test_fossil_status,
    "test_mux_status": test_mux_status,
    "test_echo": test_echo,
    "test_full_cycle": test_full_cycle,
    "test_send_text": test_send_text,
    "test_hunt_group": test_hunt_group,
}


def main():
    global VERBOSE

    parser = argparse.ArgumentParser(description="VMODEM automated test runner")
    parser.add_argument("tests", nargs="*", help="Specific tests to run")
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("-l", "--list", action="store_true", help="List available tests")
    args = parser.parse_args()

    VERBOSE = args.verbose

    if args.list:
        print("Available tests:")
        for name, func in ALL_TESTS.items():
            print(f"  {name}: {func.__doc__.strip()}")
        return 0

    # Verify prerequisites
    try:
        find_dosbox()
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        return 1

    for exe in ["vmodem.exe", "comtest.exe"]:
        if not os.path.exists(os.path.join(SRC_DIR, exe)):
            print(f"ERROR: {exe} not found in {SRC_DIR} — run wmake first")
            return 1

    tests_to_run = args.tests if args.tests else list(ALL_TESTS.keys())
    passed = 0
    failed = 0
    errors = []

    for name in tests_to_run:
        if name not in ALL_TESTS:
            print(f"Unknown test: {name}")
            errors.append(name)
            continue

        print(f"\n{'='*60}")
        print(f"TEST: {name}")
        print(f"{'='*60}")

        try:
            if ALL_TESTS[name]():
                print(f">> PASS: {name}")
                passed += 1
            else:
                print(f">> FAIL: {name}")
                failed += 1
                errors.append(name)
        except Exception as e:
            print(f">> ERROR: {name}: {e}")
            failed += 1
            errors.append(name)
            if VERBOSE:
                import traceback
                traceback.print_exc()

    print(f"\n{'='*60}")
    print(f"RESULTS: {passed} passed, {failed} failed out of {passed + failed}")
    if errors:
        print(f"FAILED: {', '.join(errors)}")
    print(f"{'='*60}")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
