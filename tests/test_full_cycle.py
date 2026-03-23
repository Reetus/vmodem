#!/usr/bin/env python3
"""Test full lifecycle: connect, exchange greeting, disconnect."""

import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect,
                     strip_telnet_iac, vlog)


def test_full_cycle():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST FULL_CYCLE",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_full_cycle - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_full_cycle - could not connect after retries")
                env.wait_for_exit(timeout=10)
                return False

            if not recv_until_connect(sock):
                print("FAIL: test_full_cycle - no CONNECT received")
                sock.close()
                env.wait_for_exit(timeout=10)
                return False

            # Read greeting from DOS side
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
        if is_verbose():
            print(f"  LOG:\n{log_text}")

        greeting_ok = b"HELLO_FROM_DOS" in greeting
        print(f"  {'PASS' if greeting_ok else 'FAIL'}: GREETING_RECV "
              f"(got={greeting!r})")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return greeting_ok and all(r[0] == "PASS" for r in results)
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_full_cycle() else 1)
