#!/usr/bin/env python3
"""Test BBS restart race: client connects during reinit, AT init string must work."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect,
                     strip_telnet_iac, vlog, wait_for_rdy)


def test_reinit_race():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST REINIT_RACE",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_reinit_race - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # Wait for phase 1 — COMTEST wants first connection
        if not wait_for_rdy(env, "REINIT_PHASE1", timeout=30):
            print("FAIL: test_reinit_race - phase 1 not ready")
            env.wait_for_exit(timeout=10)
            return False

        # First connection (normal BBS session)
        sock1 = connect_with_retries()
        if sock1 is None:
            print("FAIL: test_reinit_race - could not connect (1st)")
            env.wait_for_exit(timeout=10)
            return False

        recv_until_connect(sock1, timeout=20)
        vlog("First connection established")

        # Send some data, wait for echo
        sock1.sendall(b"HELLO")
        time.sleep(1)
        try:
            sock1.settimeout(2)
            sock1.recv(1024)
        except socket.timeout:
            pass

        # Close first connection — COMTEST is waiting for DCD drop
        sock1.close()
        vlog("First connection closed")

        # Wait for COMTEST to deinit and signal us to connect
        if not wait_for_rdy(env, "REINIT_CONNECT_NOW", timeout=60):
            print("FAIL: test_reinit_race - COMTEST didn't signal CONNECT_NOW")
            env.wait_for_exit(timeout=10)
            return False

        vlog("COMTEST deinited, connecting second client during 'restart'...")

        # Connect new client while COMTEST is in its 10s wait window
        time.sleep(2)
        sock2 = connect_with_retries()
        if sock2 is None:
            print("FAIL: test_reinit_race - could not connect (2nd)")
            env.wait_for_exit(timeout=10)
            return False
        vlog("Second client connected (during BBS restart)")

        # Keep connection alive — COMTEST will:
        #   1. FOSSIL init (s0=0, no auto-answer)
        #   2. Send ATS0=0, get OK
        #   3. Send ATS0=1, auto-answer kicks in
        received = b""
        deadline = time.time() + 120
        while time.time() < deadline:
            try:
                sock2.settimeout(1)
                chunk = sock2.recv(1024)
                if not chunk:
                    vlog("sock2 EOF")
                    break
                received += chunk
            except socket.timeout:
                pass
            except (ConnectionResetError, BrokenPipeError, OSError):
                break

            # Check if DOSBox exited
            if env.proc and env.proc.poll() is not None:
                break

        clean = strip_telnet_iac(received)
        vlog(f"Second client received: {clean!r}")

        # The AT init string should NOT have appeared on the TCP connection
        at_leaked = (b"ATS0" in clean.upper())
        if at_leaked:
            print("  FAIL: AT commands leaked to TCP client!")

        sock2.close()

        env.wait_for_exit(timeout=120)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_reinit_race - no COMTEST.LOG")
            return False

        results = parse_comtest_log(log_text)
        if is_verbose():
            print(f"  LOG:\n{log_text}")

        vmodem_log_path = os.path.join(env.drive_c, "vmodem", "VMODEM.LOG")
        if os.path.exists(vmodem_log_path):
            with open(vmodem_log_path, "r", errors="replace") as f:
                vmodem_log = f.read()
            if vmodem_log.strip():
                vlog(f"VMODEM.LOG:\n{vmodem_log[:2000]}")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return (all(r[0] == "PASS" for r in results)
                and len(results) >= 5
                and not at_leaked)
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_reinit_race() else 1)
