#!/usr/bin/env python3
"""Test DOS sends text, Python receives it."""

import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, strip_telnet_iac, vlog)


def test_send_text():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
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
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_send_text - could not connect after retries")
                env.wait_for_exit(timeout=10)
                return False

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
        if is_verbose() and log_text:
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


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_send_text() else 1)
