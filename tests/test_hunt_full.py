#!/usr/bin/env python3
"""Test hunt group rejects 3rd connection when all ports busy."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, HOST, PORT, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect,
                     strip_telnet_iac, vlog, wait_for_rdy)


def test_hunt_full():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1-2:2323 /D:VMODEM.LOG",
            "COMTEST HUNT_FULL",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_hunt_full - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # First connection -> COM1
        sock1 = None
        try:
            sock1 = connect_with_retries()
            if sock1 is None:
                print("FAIL: test_hunt_full - could not connect (1st)")
                env.wait_for_exit(timeout=10)
                return False
            vlog("First connection established")
            recv_until_connect(sock1, timeout=20)
        except Exception as e:
            print(f"FAIL: test_hunt_full - TCP error (1st): {e}")
            env.wait_for_exit(timeout=10)
            return False

        if not wait_for_rdy(env, "DCD2", timeout=30):
            print("FAIL: test_hunt_full - COMTEST not ready for 2nd connection")
            sock1.close()
            env.wait_for_exit(timeout=10)
            return False

        # Second connection -> COM2
        sock2 = None
        try:
            sock2 = connect_with_retries()
            if sock2 is None:
                print("FAIL: test_hunt_full - could not connect (2nd)")
                sock1.close()
                env.wait_for_exit(timeout=10)
                return False
            vlog("Second connection established")
            recv_until_connect(sock2, timeout=20)
        except Exception as e:
            print(f"FAIL: test_hunt_full - TCP error (2nd): {e}")
            sock1.close()
            env.wait_for_exit(timeout=10)
            return False

        if not wait_for_rdy(env, "BOTH_BUSY", timeout=30):
            print("FAIL: test_hunt_full - COMTEST didn't signal BOTH_BUSY")
            sock1.close()
            sock2.close()
            env.wait_for_exit(timeout=10)
            return False

        # Third connection — should be REJECTED
        rejection_ok = False
        try:
            sock3 = None
            for attempt in range(5):
                try:
                    sock3 = socket.create_connection((HOST, PORT), timeout=2)
                    break
                except (ConnectionRefusedError, OSError):
                    vlog(f"Conn3 attempt {attempt+1} refused, retrying...")
                    time.sleep(1)
            if sock3 is None:
                vlog("Third connection refused (acceptable)")
                rejection_ok = True
            else:
                sock3.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                vlog("Third connection accepted, checking for rejection...")

                received = b""
                deadline = time.time() + 10
                while time.time() < deadline:
                    sock3.settimeout(max(0.5, deadline - time.time()))
                    try:
                        chunk = sock3.recv(1024)
                        if not chunk:
                            break
                        received += chunk
                        clean = strip_telnet_iac(received)
                        if b"engaged" in clean.lower():
                            rejection_ok = True
                            break
                        if b"connected" in clean.lower() or b"ringing" in clean.lower():
                            break
                    except socket.timeout:
                        continue
                    except (ConnectionResetError, BrokenPipeError, OSError):
                        break

                clean = strip_telnet_iac(received)
                vlog(f"Third connection received: {clean!r}")
                if b"engaged" in clean.lower():
                    rejection_ok = True
                elif b"connected" not in clean.lower() and b"ringing" not in clean.lower():
                    vlog("Third connection got no connect message (SLIRP silent reject)")
                    rejection_ok = True
                sock3.close()
        except Exception as e:
            vlog(f"Third connection error: {e}")
            rejection_ok = True

        print(f"  {'PASS' if rejection_ok else 'FAIL'}: HUNT_REJECTION "
              f"(third connection rejected)")

        vmodem_log_path = os.path.join(env.drive_c, "vmodem", "VMODEM.LOG")
        if os.path.exists(vmodem_log_path):
            with open(vmodem_log_path, "r", errors="replace") as f:
                vlog(f"VMODEM.LOG:\n{f.read()[-2000:]}")

        sock1.close()
        sock2.close()

        time.sleep(3)
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if is_verbose() and log_text:
            print(f"  LOG:\n{log_text}")

        if log_text:
            results = parse_comtest_log(log_text)
            for status, name, detail in results:
                print(f"  {status}: {name} {detail}")
            comtest_ok = all(r[0] == "PASS" for r in results)
        else:
            comtest_ok = False
            print("  WARN: no COMTEST.LOG")

        return rejection_ok and comtest_ok
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_hunt_full() else 1)
