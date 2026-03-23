#!/usr/bin/env python3
"""Test FOSSIL deinit triggers disconnect, port returns to LISTEN."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, vlog)


def test_dtr_disconnect():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST DTR_DISCONNECT",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_dtr_disconnect - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_dtr_disconnect - could not connect")
                env.wait_for_exit(timeout=10)
                return False

            vlog("Connected, waiting for FOSSIL deinit disconnect...")

            deadline = time.time() + 30
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        vlog("Connection closed by remote")
                        break
                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError, OSError):
                    vlog("Connection reset/broken")
                    break

            sock.close()
        except Exception as e:
            print(f"FAIL: test_dtr_disconnect - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_dtr_disconnect - no COMTEST.LOG")
            return False

        results = parse_comtest_log(log_text)
        if is_verbose():
            print(f"  LOG:\n{log_text}")

        # Show VMODEM debug log
        vmodem_log_path = os.path.join(env.drive_c, "vmodem", "VMODEM.LOG")
        if os.path.exists(vmodem_log_path):
            with open(vmodem_log_path, "r", errors="replace") as f:
                vmodem_log = f.read()
            if vmodem_log.strip():
                print(f"  VMODEM.LOG:\n{vmodem_log[:2000]}")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return all(r[0] == "PASS" for r in results) and len(results) >= 2
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_dtr_disconnect() else 1)
