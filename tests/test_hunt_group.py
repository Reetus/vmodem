#!/usr/bin/env python3
"""Test hunt group: two connections dispatched to COM1 and COM2."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, strip_telnet_iac, vlog,
                     wait_for_rdy)


def test_hunt_group():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1-2:2323 /D:VMODEM.LOG",
            "COMTEST HUNT_GROUP",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_hunt_group - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # First connection — should be dispatched to COM1
        sock1 = None
        try:
            sock1 = connect_with_retries()
            if sock1 is None:
                print("FAIL: test_hunt_group - could not connect (1st)")
                env.wait_for_exit(timeout=10)
                return False
            vlog("First connection established")

            # Drain until Connected! on sock1
            pre1 = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock1.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock1.recv(4096)
                    if not chunk:
                        break
                    pre1 += chunk
                    if b"onnect" in strip_telnet_iac(pre1).lower():
                        break
                except socket.timeout:
                    continue
            vlog(f"Sock1 pre-data: {strip_telnet_iac(pre1)!r}")

        except Exception as e:
            print(f"FAIL: test_hunt_group - TCP error (1st): {e}")
            env.wait_for_exit(timeout=10)
            return False

        # Wait for COMTEST to signal ready for second connection
        if not wait_for_rdy(env, "DCD2", timeout=30):
            print("FAIL: test_hunt_group - COMTEST not ready for 2nd connection")
            sock1.close()
            env.wait_for_exit(timeout=10)
            return False
        vlog("COMTEST ready for second connection")

        # Second connection — should be dispatched to COM2
        sock2 = None
        try:
            sock2 = connect_with_retries()
            if sock2 is None:
                print("FAIL: test_hunt_group - could not connect (2nd)")
                sock1.close()
                env.wait_for_exit(timeout=10)
                return False
            vlog("Second connection established")

            # Drain until Connected! on sock2
            pre2 = b""
            deadline = time.time() + 15
            while time.time() < deadline:
                sock2.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock2.recv(4096)
                    if not chunk:
                        break
                    pre2 += chunk
                    if b"onnect" in strip_telnet_iac(pre2).lower():
                        break
                except socket.timeout:
                    continue
            vlog(f"Sock2 pre-data: {strip_telnet_iac(pre2)!r}")

        except Exception as e:
            print(f"FAIL: test_hunt_group - TCP error (2nd): {e}")
            sock1.close()
            env.wait_for_exit(timeout=10)
            return False

        # Send different data on each socket to verify port isolation
        time.sleep(0.5)
        data1 = b"PORT_ONE"
        data2 = b"PORT_TWO"
        sock1.sendall(data1)
        sock2.sendall(data2)
        vlog(f"Sent {data1!r} on sock1, {data2!r} on sock2")

        # Read echoes
        echo1 = b""
        echo2 = b""
        deadline = time.time() + 15
        while time.time() < deadline:
            got_both = (data1 in strip_telnet_iac(echo1) and
                        data2 in strip_telnet_iac(echo2))
            if got_both:
                break
            try:
                sock1.settimeout(0.3)
                chunk = sock1.recv(1024)
                if chunk:
                    echo1 += chunk
            except (socket.timeout, OSError):
                pass
            try:
                sock2.settimeout(0.3)
                chunk = sock2.recv(1024)
                if chunk:
                    echo2 += chunk
            except (socket.timeout, OSError):
                pass

        echo1_clean = strip_telnet_iac(echo1)
        echo2_clean = strip_telnet_iac(echo2)
        vlog(f"Echo1: {echo1_clean!r}")
        vlog(f"Echo2: {echo2_clean!r}")

        sock1.close()
        sock2.close()

        time.sleep(5)
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if is_verbose() and log_text:
            print(f"  LOG:\n{log_text}")

        echo1_ok = data1 in echo1_clean
        echo2_ok = data2 in echo2_clean
        isolation_ok = data2 not in echo1_clean and data1 not in echo2_clean

        print(f"  {'PASS' if echo1_ok else 'FAIL'}: HUNT_ECHO1 "
              f"(sent={data1!r}, got={echo1_clean!r})")
        print(f"  {'PASS' if echo2_ok else 'FAIL'}: HUNT_ECHO2 "
              f"(sent={data2!r}, got={echo2_clean!r})")
        print(f"  {'PASS' if isolation_ok else 'FAIL'}: HUNT_ISOLATION "
              f"(port data not cross-contaminated)")

        if log_text:
            results = parse_comtest_log(log_text)
            for status, name, detail in results:
                print(f"  {status}: {name} {detail}")

        return echo1_ok and echo2_ok and isolation_ok
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_hunt_group() else 1)
