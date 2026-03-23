#!/usr/bin/env python3
"""Test outgoing TCP connection via MUX socket API.

COMTEST inside DOSBox-X allocates a socket via MUX_SOCK_ALLOC,
connects to a Python TCP listener on the host (10.0.2.2 via SLIRP),
sends HELLO_FROM_DOS, and receives HELLO_FROM_HOST.
"""

import os
import socket
import threading
import time

from testenv import (DOSBoxTestEnv, is_verbose, parse_comtest_log,
                     vlog, wait_for_rdy)

LISTEN_PORT = 9999


def _host_server(result, ready_event):
    """TCP server that accepts one connection, exchanges greetings."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", LISTEN_PORT))
    srv.listen(1)
    srv.settimeout(60)
    ready_event.set()

    try:
        conn, addr = srv.accept()
        conn.settimeout(15)
        vlog(f"TCP_OUT server: accepted connection from {addr}")

        # Receive HELLO_FROM_DOS
        data = b""
        deadline = time.time() + 10
        while time.time() < deadline:
            try:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
                if b"HELLO_FROM_DOS" in data:
                    break
            except socket.timeout:
                continue

        vlog(f"TCP_OUT server: received {data!r}")
        result["received"] = data

        # Send response
        conn.sendall(b"HELLO_FROM_HOST\n")
        vlog("TCP_OUT server: sent HELLO_FROM_HOST")
        time.sleep(2)
        conn.close()
        result["ok"] = True
    except Exception as e:
        vlog(f"TCP_OUT server error: {e}")
        result["error"] = str(e)
    finally:
        srv.close()


def test_tcp_out():
    env = DOSBoxTestEnv()
    server_result = {}
    server_ready = threading.Event()

    # Start the host-side TCP listener in a thread
    server_thread = threading.Thread(
        target=_host_server, args=(server_result, server_ready))
    server_thread.daemon = True
    server_thread.start()

    if not server_ready.wait(timeout=5):
        print("FAIL: test_tcp_out - server failed to start")
        return False

    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST TCP_OUT 10 0 2 2 9999",
            "EXIT",
        ])
        env.start()

        # Wait for COMTEST to signal send completion first
        rdy_ok = wait_for_rdy(env, "TCPOUT_", timeout=90)
        if not rdy_ok:
            vlog("RDY not found, waiting for DOSBox-X exit...")
        env.wait_for_exit(timeout=30)
        # DOSBox-X exit flushes all file content to host

        # Read the RDY content for pass/fail
        rdy_path = os.path.join(env.drive_c, "vmodem", "COMTEST.RDY")
        rdy_content = ""
        if os.path.exists(rdy_path):
            with open(rdy_path, "r") as f:
                rdy_content = f.read().strip()

        dos_pass = "TCPOUT_PASS" in rdy_content

        # Try to read COMTEST.LOG (may be empty due to DOSBox-X caching)
        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []

        if is_verbose():
            print(f"  COMTEST.RDY: {rdy_content!r}")
            if log_text:
                print(f"  COMTEST.LOG:\n{log_text}")

        # Check server side
        server_thread.join(timeout=5)
        server_recv = server_result.get("received", b"")
        host_got_hello = b"HELLO_FROM_DOS" in server_recv

        print(f"  {'PASS' if host_got_hello else 'FAIL'}: "
              f"HOST_RECV (got={server_recv!r})")
        print(f"  {'PASS' if dos_pass else 'FAIL'}: "
              f"DOS_RESULT (rdy={rdy_content!r})")

        # Check COMTEST.LOG results if available
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        all_pass = host_got_hello and dos_pass
        for status, name, detail in results:
            if status == "FAIL":
                all_pass = False

        if not rdy_ok:
            print("FAIL: test_tcp_out - COMTEST.RDY not found (timeout)")
            return False

        return all_pass
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    from testenv import set_verbose
    if "-v" in sys.argv or "--verbose" in sys.argv:
        set_verbose(True)
    sys.exit(0 if test_tcp_out() else 1)
