#!/usr/bin/env python3
"""Test reconnect: connect, disconnect, connect again on same port."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect,
                     strip_telnet_iac, vlog)


def test_reconnect():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST RECONNECT",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_reconnect - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        # First connection
        test_data1 = b"FIRST_SESSION"
        echo1_ok = False
        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_reconnect - could not connect (1st)")
                env.wait_for_exit(timeout=10)
                return False

            recv_until_connect(sock, timeout=20)
            vlog("First connection established")

            time.sleep(0.5)
            sock.sendall(test_data1)

            echoed = b""
            deadline = time.time() + 10
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    echoed += chunk
                    if test_data1 in strip_telnet_iac(echoed):
                        echo1_ok = True
                        break
                except socket.timeout:
                    continue
            vlog(f"First echo: {strip_telnet_iac(echoed)!r}")

            sock.close()
            vlog("First connection closed")
        except Exception as e:
            print(f"FAIL: test_reconnect - TCP error (1st): {e}")
            env.wait_for_exit(timeout=30)
            return False

        print(f"  {'PASS' if echo1_ok else 'FAIL'}: RECONN_ECHO1 "
              f"(first session echo)")

        # Wait for COMTEST to detect disconnect and signal ready for 2nd
        rdy_path = os.path.join(env.drive_c, "vmodem", "COMTEST.RDY")
        deadline = time.time() + 60
        got_dcd2 = False
        last_content = ""
        while time.time() < deadline:
            if os.path.exists(rdy_path):
                try:
                    with open(rdy_path, "r") as f:
                        content = f.read().strip()
                    if content != last_content:
                        vlog(f"RDY file changed: {content!r}")
                        last_content = content
                    if "DCD2" in content:
                        got_dcd2 = True
                        break
                except IOError:
                    pass
            time.sleep(0.5)

        if not got_dcd2:
            for tf in ["VMODEM.LOG", "COMTEST.LOG"]:
                tp = os.path.join(env.drive_c, "vmodem", tf)
                if os.path.exists(tp):
                    with open(tp, "r", errors="replace") as f:
                        vlog(f"{tf}: {f.read().strip()[-500:]}")
            log_text = env.read_comtest_log()
            if log_text:
                vlog(f"COMTEST.LOG:\n{log_text}")
            if env.proc:
                rc = env.proc.poll()
                vlog(f"DOSBox-X process state: {'exited rc={}'.format(rc) if rc is not None else 'still running'}")
            if hasattr(env, 'dosbox_log') and os.path.exists(env.dosbox_log):
                with open(env.dosbox_log, "r", errors="replace") as f:
                    dblog = f.read()
                    if dblog:
                        vlog(f"DOSBox log (last 1000 chars):\n{dblog[-1000:]}")
            print("FAIL: test_reconnect - COMTEST not ready for 2nd connection")
            env.wait_for_exit(timeout=30)
            return False

        # Second connection
        test_data2 = b"SECOND_SESSION"
        echo2_ok = False
        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_reconnect - could not connect (2nd)")
                env.wait_for_exit(timeout=10)
                return False

            recv_until_connect(sock, timeout=20)
            vlog("Second connection established")

            time.sleep(0.5)
            sock.sendall(test_data2)

            echoed = b""
            deadline = time.time() + 10
            while time.time() < deadline:
                sock.settimeout(max(0.5, deadline - time.time()))
                try:
                    chunk = sock.recv(1024)
                    if not chunk:
                        break
                    echoed += chunk
                    if test_data2 in strip_telnet_iac(echoed):
                        echo2_ok = True
                        break
                except socket.timeout:
                    continue
            vlog(f"Second echo: {strip_telnet_iac(echoed)!r}")

            sock.close()
        except Exception as e:
            print(f"FAIL: test_reconnect - TCP error (2nd): {e}")
            env.wait_for_exit(timeout=30)
            return False

        print(f"  {'PASS' if echo2_ok else 'FAIL'}: RECONN_ECHO2 "
              f"(second session echo)")

        time.sleep(5)
        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if log_text:
            results = parse_comtest_log(log_text)
            if is_verbose():
                print(f"  LOG:\n{log_text}")
            for status, name, detail in results:
                print(f"  {status}: {name} {detail}")
            comtest_ok = all(r[0] == "PASS" for r in results)
        else:
            vlog("COMTEST.LOG not readable (DOSBox-X file cache)")
            comtest_ok = True  # trust the echo tests

        return echo1_ok and echo2_ok and comtest_ok
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_reconnect() else 1)
