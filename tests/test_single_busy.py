#!/usr/bin/env python3
"""Test single-port busy rejection: second connection gets 'engaged' message."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, HOST, PORT, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect,
                     strip_telnet_iac, vlog)


def test_single_busy():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST ECHO",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_single_busy - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # First connection — should succeed
        sock1 = connect_with_retries()
        if sock1 is None:
            print("FAIL: test_single_busy - could not connect (1st)")
            env.wait_for_exit(timeout=10)
            return False
        vlog("First connection established")
        recv_until_connect(sock1, timeout=20)

        # Give VMODEM a moment to settle into PORT_CONN
        time.sleep(2)

        # Second connection — should be accepted then rejected with busy msg
        rejection_ok = False
        sock2 = None
        try:
            for attempt in range(10):
                try:
                    sock2 = socket.create_connection((HOST, PORT), timeout=5)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Second conn attempt {attempt+1} refused, retrying...")
                    time.sleep(1)

            if sock2 is None:
                # Connection refused entirely — mTCP didn't accept
                vlog("Second connection refused (no listen socket?)")
                rejection_ok = False
            else:
                sock2.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                vlog("Second connection accepted by TCP")

                received = b""
                deadline = time.time() + 10
                while time.time() < deadline:
                    sock2.settimeout(max(0.5, deadline - time.time()))
                    try:
                        chunk = sock2.recv(1024)
                        if not chunk:
                            break
                        received += chunk
                        clean = strip_telnet_iac(received)
                        if b"engaged" in clean.lower():
                            rejection_ok = True
                            break
                        if b"ringing" in clean.lower():
                            # Got dispatched as real connection — NOT rejected
                            break
                    except socket.timeout:
                        continue
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        break

                clean = strip_telnet_iac(received)
                vlog(f"Second connection received: {clean!r}")

                if b"engaged" in clean.lower():
                    rejection_ok = True

                sock2.close()
        except Exception as e:
            vlog(f"Second connection error: {e}")

        print(f"  {'PASS' if rejection_ok else 'FAIL'}: SINGLE_BUSY_REJECT "
              f"(second connection got busy message)")

        # Verify first connection still works
        first_ok = False
        try:
            test_data = b"STILL_ALIVE"
            sock1.sendall(test_data)
            time.sleep(1)
            echoed = b""
            deadline = time.time() + 10
            while time.time() < deadline:
                sock1.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock1.recv(1024)
                    if not chunk:
                        break
                    echoed += chunk
                    if test_data in strip_telnet_iac(echoed):
                        first_ok = True
                        break
                except socket.timeout:
                    continue
            vlog(f"First connection echo: {strip_telnet_iac(echoed)!r}")
        except Exception as e:
            vlog(f"First connection error after reject: {e}")

        print(f"  {'PASS' if first_ok else 'FAIL'}: SINGLE_FIRST_ALIVE "
              f"(first connection still works after reject)")

        # Dump VMODEM.LOG
        vmodem_log_path = os.path.join(env.drive_c, "vmodem", "VMODEM.LOG")
        if os.path.exists(vmodem_log_path):
            with open(vmodem_log_path, "r", errors="replace") as f:
                vlog(f"VMODEM.LOG:\n{f.read()[-2000:]}")

        sock1.close()
        time.sleep(3)
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if is_verbose() and log_text:
            print(f"  LOG:\n{log_text}")

        return rejection_ok and first_ok
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_single_busy() else 1)
