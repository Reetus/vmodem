#!/usr/bin/env python3
"""Test bidirectional relay: FOSSIL incoming <-> MUX socket outgoing.

Python runs both sides:
  - TCP server on RELAY_PORT (COMTEST connects to it via MUX socket)
  - TCP client to VMODEM on port 2323 (incoming FOSSIL connection)

COMTEST bridges them: FOSSIL RX -> MUX send, MUX recv -> FOSSIL TX.

Data flow tested:
  Direction 1: Python client -> VMODEM -> FOSSIL -> COMTEST -> MUX -> Python server
  Direction 2: Python server -> MUX -> COMTEST -> FOSSIL -> VMODEM -> Python client
"""

import os
import socket
import threading
import time
import sys

from testenv import (DOSBoxTestEnv, is_verbose, parse_comtest_log,
                     set_verbose, vlog, wait_for_rdy)

RELAY_PORT = 9998


def _relay_server(result, ready_event, conn_event):
    """TCP server: accepts one connection from COMTEST's MUX socket."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", RELAY_PORT))
    srv.listen(1)
    srv.settimeout(90)
    ready_event.set()

    try:
        conn, addr = srv.accept()
        conn.settimeout(15)
        vlog(f"Relay server: accepted connection from {addr}")
        conn_event.set()

        # Send data for COMTEST to relay to Python client
        time.sleep(0.5)
        conn.sendall(b"HELLO_FROM_SERVER\n")
        vlog("Relay server: sent HELLO_FROM_SERVER")

        # Receive data that Python client sent through COMTEST
        data = b""
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                chunk = conn.recv(1024)
                if not chunk:
                    break
                data += chunk
                if b"HELLO_FROM_CLIENT" in data:
                    break
            except socket.timeout:
                continue

        vlog(f"Relay server: received {data!r}")
        result["received"] = data
        result["ok"] = b"HELLO_FROM_CLIENT" in data
        time.sleep(1)
        conn.close()
    except Exception as e:
        vlog(f"Relay server error: {e}")
        result["error"] = str(e)
    finally:
        srv.close()


def _strip_iac(data):
    """Strip telnet IAC sequences (0xFF xx xx) from raw data."""
    clean = bytearray()
    i = 0
    while i < len(data):
        if data[i] == 0xFF and i + 2 < len(data):
            i += 3
        else:
            clean.append(data[i])
            i += 1
    return clean


def test_relay():
    env = DOSBoxTestEnv()
    server_result = {}
    server_ready = threading.Event()
    server_conn = threading.Event()

    # Start the relay server in a thread
    server_thread = threading.Thread(
        target=_relay_server, args=(server_result, server_ready, server_conn))
    server_thread.daemon = True
    server_thread.start()

    if not server_ready.wait(timeout=5):
        print("FAIL: test_relay - server failed to start")
        return False

    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST RELAY 10 0 2 2 9998",
            "EXIT",
        ])
        env.start()

        # Wait for COMTEST to be ready for incoming connection
        if not wait_for_rdy(env, "RELAY_WAITING_DCD", timeout=60):
            print("FAIL: test_relay - COMTEST not ready (timeout)")
            return False

        vlog("COMTEST ready, connecting to VMODEM...")

        # Connect to VMODEM's listen port (Python client side)
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(30)
        try:
            client.connect(("127.0.0.1", 2323))
            vlog("Connected to VMODEM as client")
        except (ConnectionRefusedError, socket.timeout) as e:
            print(f"FAIL: test_relay - cannot connect to VMODEM: {e}")
            return False

        # Wait for COMTEST to connect its MUX socket to our server
        if not server_conn.wait(timeout=60):
            print("FAIL: test_relay - COMTEST did not connect to server")
            client.close()
            return False
        vlog("COMTEST connected to relay server via MUX")

        # Give relay loop a moment to stabilize
        time.sleep(1)

        # Direction 1: client -> VMODEM -> FOSSIL -> COMTEST -> MUX -> server
        client.sendall(b"HELLO_FROM_CLIENT\n")
        vlog("Client sent HELLO_FROM_CLIENT")

        # Direction 2: server already sent HELLO_FROM_SERVER
        # Read from client until we see it (mixed with RING/CONNECT text)
        client_data = b""
        client.settimeout(2)
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                chunk = client.recv(4096)
                if not chunk:
                    break
                client_data += chunk
                clean = _strip_iac(client_data)
                if b"HELLO_FROM_SERVER" in clean:
                    vlog("Client received HELLO_FROM_SERVER")
                    break
            except socket.timeout:
                continue
            except OSError:
                break

        # Keep client connection open so relay has time to finish
        # forwarding HELLO_FROM_CLIENT through VMODEM to the server.
        time.sleep(3)
        client.close()
        env.wait_for_exit(timeout=30)

        # Read results
        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []

        if is_verbose() and log_text:
            print(f"  COMTEST.LOG:\n{log_text}")

        # Strip IAC from client data for checking
        clean_data = _strip_iac(client_data).decode("ascii", errors="replace")
        vlog(f"Client received (clean): {clean_data!r}")

        # Wait for server thread
        server_thread.join(timeout=5)
        server_recv = server_result.get("received", b"")

        # Check direction 1: client -> server
        srv_got_hello = b"HELLO_FROM_CLIENT" in server_recv
        print(f"  {'PASS' if srv_got_hello else 'FAIL'}: "
              f"CLIENT_TO_SERVER (server got={server_recv!r})")

        # Check direction 2: server -> client
        cli_got_hello = "HELLO_FROM_SERVER" in clean_data
        print(f"  {'PASS' if cli_got_hello else 'FAIL'}: "
              f"SERVER_TO_CLIENT (client got HELLO_FROM_SERVER)")

        # Check COMTEST results
        all_pass = srv_got_hello and cli_got_hello
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")
            if status == "FAIL":
                all_pass = False

        return all_pass
    finally:
        env.cleanup()


if __name__ == "__main__":
    if "-v" in sys.argv or "--verbose" in sys.argv:
        set_verbose(True)
    sys.exit(0 if test_relay() else 1)
