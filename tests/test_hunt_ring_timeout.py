#!/usr/bin/env python3
"""Test hunt mode /E: ring timeout returns ports to LISTEN."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, vlog)


def test_hunt_ring_timeout():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1-2:2323 /E /D:VMODEM.LOG",
            "COMTEST HUNT_RING_TIMEOUT",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_hunt_ring_timeout - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            # Connect first client
            sock1 = connect_with_retries()
            if sock1 is None:
                print("FAIL: test_hunt_ring_timeout - client 1 could not connect")
                env.wait_for_exit(timeout=10)
                return False
            vlog("Client 1 connected")

            # Wait for COMTEST to signal first connection accepted
            rdy_path = os.path.join(env.drive_c, "vmodem", "COMTEST.RDY")
            deadline = time.time() + 60
            while time.time() < deadline:
                try:
                    with open(rdy_path) as f:
                        content = f.read().strip()
                    if content == "HUNT_RT_CONN1_OK":
                        break
                except (FileNotFoundError, IOError):
                    pass
                time.sleep(0.5)

            # Connect second client
            sock2 = connect_with_retries()
            if sock2 is None:
                print("FAIL: test_hunt_ring_timeout - client 2 could not connect")
                sock1.close()
                env.wait_for_exit(timeout=10)
                return False
            vlog("Client 2 connected")

            # Keep connections alive — drain any data but don't close
            # Ring timeout is ~60s (10 rings * 6s). Wait up to 120s.
            deadline = time.time() + 120
            while time.time() < deadline:
                for s in [sock1, sock2]:
                    try:
                        s.settimeout(0.1)
                        s.recv(1024)
                    except (socket.timeout, OSError):
                        pass
                try:
                    with open(rdy_path) as f:
                        content = f.read().strip()
                    if content == "HUNT_RT_DONE":
                        vlog("COMTEST reports ring timeout complete")
                        break
                except (FileNotFoundError, IOError):
                    pass
                time.sleep(0.5)

            sock1.close()
            sock2.close()
        except Exception as e:
            print(f"FAIL: test_hunt_ring_timeout - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=180)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_hunt_ring_timeout - no COMTEST.LOG")
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

        return all(r[0] == "PASS" for r in results) and len(results) >= 3
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_hunt_ring_timeout() else 1)
