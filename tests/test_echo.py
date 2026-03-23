#!/usr/bin/env python3
"""Test data echo: connect, send data, verify echo back."""

import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, strip_telnet_iac, vlog)


def test_echo():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST ECHO",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_echo - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        test_data = b"HELLO_VMODEM"
        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_echo - could not connect after retries")
                env.wait_for_exit(timeout=10)
                return False

            # Drain incoming data (IAC negotiation, RING, CONNECT, IAC NOPs)
            pre_buf = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(4096)
                    if not chunk:
                        break
                    pre_buf += chunk
                    clean = strip_telnet_iac(pre_buf)
                    if b"onnect" in clean.lower():
                        vlog("Got connect indication")
                        break
                except socket.timeout:
                    continue

            time.sleep(0.5)
            sock.sendall(test_data)
            vlog(f"Sent: {test_data}")

            # Read echo back
            echoed_raw = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    echoed_raw += chunk
                    clean = strip_telnet_iac(echoed_raw)
                    if test_data in clean:
                        break
                except socket.timeout:
                    continue

            echoed = strip_telnet_iac(echoed_raw)
            vlog(f"Echoed raw: {echoed_raw!r}")
            vlog(f"Echoed clean: {echoed!r}")
            sock.close()
        except Exception as e:
            print(f"FAIL: test_echo - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        time.sleep(5)
        env.wait_for_exit(timeout=45)

        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []
        if is_verbose() and log_text:
            print(f"  LOG:\n{log_text}")

        echo_ok = test_data in echoed
        print(f"  {'PASS' if echo_ok else 'FAIL'}: ECHO_MATCH "
              f"(sent={test_data!r}, got={echoed!r})")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return echo_ok
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_echo() else 1)
