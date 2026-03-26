#!/usr/bin/env python3
"""Test TLS 1.2 outbound connection.

Starts a local TLS echo server with a 2048-bit RSA cert on the host,
then COMTEST inside DOSBox-X connects to it via TLS 1.2 (through SLIRP
at 10.0.2.2), sends IRC NICK/USER, and reads back the echo.

Uses 2048-bit key to keep RSA modpow feasible on emulated 16-bit DOS.
"""

import os
import socket
import ssl
import subprocess
import sys
import threading
import time

from testenv import (DOSBoxTestEnv, is_verbose, parse_comtest_log,
                     set_verbose, vlog)

TLS_PORT = 9443


def _tls_echo_server(cert_path, key_path, ready_event, result):
    """Simple TLS echo server that sends a greeting then echoes."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_path, key_path)
    ctx.set_ciphers("AES128-SHA")
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TLS_PORT))
    srv.listen(1)
    srv.settimeout(600)
    ready_event.set()

    try:
        conn, addr = srv.accept()
        vlog(f"TLS server: accepted from {addr}")
        tls_conn = ctx.wrap_socket(conn, server_side=True)
        vlog("TLS server: handshake complete")

        # Send IRC-like welcome
        tls_conn.sendall(b":tlstest.local 001 vtlstest :Welcome\r\n")

        # Read and echo for a bit
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                tls_conn.settimeout(1)
                data = tls_conn.recv(4096)
                if not data:
                    break
                vlog(f"TLS server: recv {data!r}")
                result["received"] = result.get("received", b"") + data
                if b"QUIT" in data:
                    tls_conn.sendall(b":tlstest.local ERROR :Closing\r\n")
                    break
            except (socket.timeout, ssl.SSLError):
                continue

        result["ok"] = True
        tls_conn.shutdown(socket.SHUT_RDWR)
        tls_conn.close()
    except Exception as e:
        vlog(f"TLS server error: {e}")
        result["error"] = str(e)
    finally:
        srv.close()


def test_tls_irc():
    env = DOSBoxTestEnv()

    # Generate a 2048-bit test cert if needed
    key_bits = int(os.environ.get("VTLS_KEY_BITS", "2048"))
    key_path = f"/tmp/vtls_test_key_{key_bits}.pem"
    cert_path = f"/tmp/vtls_test_cert_{key_bits}.pem"
    if not os.path.exists(key_path):
        subprocess.run([
            "openssl", "req", "-x509", "-newkey", f"rsa:{key_bits}",
            "-keyout", key_path, "-out", cert_path,
            "-days", "1", "-nodes", "-subj", "/CN=tlstest.local"
        ], capture_output=True)

    server_result = {}
    server_ready = threading.Event()

    server_thread = threading.Thread(
        target=_tls_echo_server,
        args=(cert_path, key_path, server_ready, server_result))
    server_thread.daemon = True
    server_thread.start()

    if not server_ready.wait(timeout=5):
        print("FAIL: test_tls_irc - TLS server failed to start")
        return False

    try:
        # Connect to local Python TLS echo server (2048-bit RSA, fast)
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST TLS_IRC 10.0.2.2 9443",
            "EXIT",
        ])

        # TLS RSA modpow on 16-bit DOS is slow — crank cycles to max
        with open(env.conf_path, "r") as f:
            conf = f.read()
        conf = conf.replace("cycles=25000", "cycles=max")
        conf = conf.replace("[dosbox]\n", "[dosbox]\nquit warning=false\n")
        with open(env.conf_path, "w") as f:
            f.write(conf)

        env.start()
        env.wait_for_exit(timeout=600)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_tls_irc - no COMTEST.LOG found")
            if is_verbose() and env.tmpdir:
                dosbox_log = os.path.join(env.tmpdir, "dosbox.log")
                if os.path.exists(dosbox_log):
                    with open(dosbox_log) as f:
                        lines = f.readlines()
                        print(f"  DOSBox log (last 40 lines):")
                        for l in lines[-40:]:
                            print(f"    {l.rstrip()}")
                vm_dir = os.path.join(env.drive_c, "vmodem")
                if os.path.isdir(vm_dir):
                    print(f"  Files in {vm_dir}:")
                    for fn in os.listdir(vm_dir):
                        print(f"    {fn}")
            return False

        results = parse_comtest_log(log_text)
        if is_verbose():
            print(f"  COMTEST.LOG:\n{log_text}")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        # Show VTLS debug log if present
        vtls_log_path = os.path.join(env.drive_c, "vmodem", "VTLS.LOG")
        if os.path.exists(vtls_log_path):
            with open(vtls_log_path, "r") as f:
                vtls_text = f.read()
            if vtls_text:
                print(f"  VTLS.LOG:\n{vtls_text}")

        # Check server side
        server_thread.join(timeout=5)
        if is_verbose():
            vlog(f"Server result: {server_result}")

        passed = all(r[0] == "PASS" for r in results) and len(results) >= 3
        return passed
    finally:
        env.cleanup(preserve=is_verbose())


if __name__ == "__main__":
    if "-v" in sys.argv or "--verbose" in sys.argv:
        set_verbose(True)
    sys.exit(0 if test_tls_irc() else 1)
