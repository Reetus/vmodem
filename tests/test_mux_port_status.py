#!/usr/bin/env python3
"""Test MUX_STATUS shows CONN mode and correct remote IP:port."""

import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, recv_until_connect, vlog)


def test_mux_port_status():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST MUX_PORT_STATUS",
            "EXIT",
        ])
        env.start()

        if not env.wait_for_comtest_ready():
            print("FAIL: test_mux_port_status - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        try:
            sock = connect_with_retries()
            if sock is None:
                print("FAIL: test_mux_port_status - could not connect")
                env.wait_for_exit(timeout=10)
                return False

            recv_until_connect(sock, timeout=20)
            vlog("Connected, COMTEST checking MUX_STATUS...")

            time.sleep(10)
            sock.close()
        except Exception as e:
            print(f"FAIL: test_mux_port_status - TCP error: {e}")
            env.wait_for_exit(timeout=30)
            return False

        env.wait_for_exit(timeout=60)

        log_text = env.read_comtest_log()
        if not log_text:
            print("FAIL: test_mux_port_status - no COMTEST.LOG")
            return False

        results = parse_comtest_log(log_text)
        if is_verbose():
            print(f"  LOG:\n{log_text}")

        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")

        return all(r[0] == "PASS" for r in results) and len(results) >= 4
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_mux_port_status() else 1)
