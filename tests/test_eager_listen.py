#!/usr/bin/env python3
"""Test /E flag: connections accepted without FOSSIL init."""

import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, vlog)


def test_eager_listen():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /E /D:VMODEM.LOG",
            "COMTEST EAGER_LISTEN",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_eager_listen - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_eager_listen - could not connect")
                env.wait_for_exit(timeout=10)
                return False
            vlog("Connected with eager listen (no FOSSIL init)")

            # Keep connection alive for 15s so COMTEST can detect it
            deadline = time.time() + 15
            while time.time() < deadline:
                try:
                    sock.settimeout(0.5)
                    sock.recv(1024)
                except (socket.timeout, OSError):
                    pass

            sock.close()
        except Exception as e:
            print(f"FAIL: test_eager_listen - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        time.sleep(3)
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_eager_listen - no COMTEST.LOG")
            return False

        results = parse_comtest_log(log_text)
        if is_verbose():
            print(f"  LOG:\n{log_text}")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return all(r[0] == "PASS" for r in results) and len(results) >= 1
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_eager_listen() else 1)
