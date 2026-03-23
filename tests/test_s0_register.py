#!/usr/bin/env python3
"""Test S0 auto-answer register: S0=0 prevents answer, S0=1 enables it."""

import os
import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, vlog, wait_for_rdy)


def test_s0_register():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST S0_REGISTER",
            "EXIT",
        ])
        env.start()

        # Wait for phase 1 — COMTEST has set S0=0
        if not wait_for_rdy(env, "PHASE1", timeout=90):
            print("FAIL: test_s0_register - COMTEST phase 1 not ready")
            env.wait_for_exit(timeout=10)
            return False

        vlog("Phase 1: S0=0 set, connecting...")

        # Connect — should NOT get auto-answered (S0=0)
        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_s0_register - could not connect")
                env.wait_for_exit(timeout=10)
                return False
            vlog("TCP connected, waiting for phase 2...")

            # Wait for phase 2 — COMTEST has set S0=1
            rdy_path = os.path.join(env.drive_c, "vmodem", "COMTEST.RDY")
            deadline = time.time() + 60
            phase2_ready = False
            while time.time() < deadline:
                if os.path.exists(rdy_path):
                    try:
                        with open(rdy_path, "r") as f:
                            content = f.read().strip()
                        if "PHASE2" in content:
                            phase2_ready = True
                            break
                    except IOError:
                        pass
                # Keep draining data from socket
                try:
                    sock.settimeout(0.3)
                    sock.recv(1024)
                except (socket.timeout, OSError):
                    pass
                time.sleep(0.3)

            if not phase2_ready:
                vlog("Phase 2 not reached — checking if COMTEST already done")

            # Keep connection open for auto-answer
            time.sleep(15)
            sock.close()
        except Exception as e:
            print(f"FAIL: test_s0_register - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_s0_register - no COMTEST.LOG")
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
    sys.exit(0 if test_s0_register() else 1)
