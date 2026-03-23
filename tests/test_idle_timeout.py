#!/usr/bin/env python3
"""Test idle timeout disconnects and port returns to LISTEN."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect,
                     strip_telnet_iac, vlog)


def test_idle_timeout():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST IDLE_TIMEOUT",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_idle_timeout - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_idle_timeout - could not connect")
                env.wait_for_exit(timeout=10)
                return False

            recv_until_connect(sock, timeout=20)
            vlog("Connected, now idling for ~35s...")

            # Wait for idle timeout to fire (~30s) + margin
            received = b""
            deadline = time.time() + 50
            disconnected = False
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        disconnected = True
                        break
                    received += chunk
                    clean = strip_telnet_iac(received)
                    if b"idle" in clean.lower() or b"NO CARRIER" in clean:
                        vlog(f"Got idle disconnect: {clean!r}")
                        disconnected = True
                        break
                except socket.timeout:
                    continue
                except (ConnectionResetError, BrokenPipeError, OSError):
                    disconnected = True
                    break

            sock.close()
        except Exception as e:
            print(f"FAIL: test_idle_timeout - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=60)

        vmodem_log_path = os.path.join(env.drive_c, "vmodem", "VMODEM.LOG")
        if os.path.exists(vmodem_log_path):
            with open(vmodem_log_path, "r", errors="replace") as f:
                vlog(f"VMODEM.LOG:\n{f.read()[-2000:]}")

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_idle_timeout - no COMTEST.LOG")
            return False

        results = parse_comtest_log(log_text)
        if is_verbose():
            print(f"  LOG:\n{log_text}")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return all(r[0] == "PASS" for r in results) and len(results) >= 3
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_idle_timeout() else 1)
