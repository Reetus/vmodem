#!/usr/bin/env python3
"""Test TTYPE (Terminal Type) negotiation.

Flow:
  1. Start DOSBox-X with VMODEM + COMTEST TTYPE_QUERY
  2. Connect via TCP as a telnet client
  3. VMODEM sends DO TTYPE during IAC negotiation
  4. We respond WILL TTYPE, then when prompted with SB TTYPE SEND,
     respond SB TTYPE IS "ANSI"
  5. COMTEST queries MUX_PORT_TTYPE and verifies "ANSI"
"""

import socket
import time

from testenv import (DOSBoxTestEnv, is_verbose, connect_with_retries,
                     parse_comtest_log, vlog, wait_for_rdy)

# Telnet protocol bytes
IAC  = 0xFF
WILL = 0xFB
WONT = 0xFC
DO   = 0xFD
DONT = 0xFE
SB   = 0xFA
SE   = 0xF0

TELOPT_TTYPE = 24
TELOPT_NAWS  = 31

TEST_TTYPE = b"ANSI"


def handle_telnet_negotiation(sock, timeout=10):
    """Read IAC negotiation from VMODEM and respond.

    Specifically:
      - Reply DO to WILL offers (ECHO, SGA)
      - Reply WILL TTYPE when we see DO TTYPE
      - Handle SB TTYPE SEND SE by replying SB TTYPE IS "ANSI" SE
      - Reply WONT to any other DO requests
    """
    buf = b""
    ttype_sent = False
    deadline = time.time() + timeout

    while time.time() < deadline:
        sock.settimeout(max(0.2, deadline - time.time()))
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf += chunk
        except socket.timeout:
            if ttype_sent:
                break
            continue

        # Process IAC sequences in buffer
        while len(buf) >= 2:
            if buf[0] != IAC:
                buf = buf[1:]
                continue

            cmd = buf[1]

            if cmd == IAC:
                buf = buf[2:]
                continue

            if cmd in (WILL, WONT, DO, DONT):
                if len(buf) < 3:
                    break
                opt = buf[2]
                buf = buf[3:]

                if cmd == WILL:
                    vlog(f"Server WILL {opt}, responding DO")
                    sock.sendall(bytes([IAC, DO, opt]))
                elif cmd == DO:
                    if opt == TELOPT_TTYPE:
                        vlog("Server DO TTYPE, responding WILL")
                        sock.sendall(bytes([IAC, WILL, TELOPT_TTYPE]))
                    elif opt == TELOPT_NAWS:
                        vlog("Server DO NAWS, responding WONT")
                        sock.sendall(bytes([IAC, WONT, TELOPT_NAWS]))
                    else:
                        vlog(f"Server DO {opt}, responding WONT")
                        sock.sendall(bytes([IAC, WONT, opt]))
                elif cmd in (DONT, WONT):
                    pass

            elif cmd == SB:
                # Subnegotiation — find IAC SE
                se_pos = buf.find(bytes([IAC, SE]), 2)
                if se_pos < 0:
                    break  # need more data
                sb_data = buf[2:se_pos]
                buf = buf[se_pos + 2:]

                if len(sb_data) >= 2 and sb_data[0] == TELOPT_TTYPE and sb_data[1] == 0x01:
                    # TTYPE SEND — reply with IS "ANSI"
                    vlog(f"Server SB TTYPE SEND, responding IS \"{TEST_TTYPE.decode()}\"")
                    reply = bytes([IAC, SB, TELOPT_TTYPE, 0x00]) + TEST_TTYPE + bytes([IAC, SE])
                    sock.sendall(reply)
                    ttype_sent = True
                else:
                    vlog(f"Server SB {sb_data[0] if sb_data else '?'}, ignoring")
            else:
                buf = buf[2:]

        if ttype_sent and len(buf) < 3:
            time.sleep(0.3)
            sock.settimeout(0.5)
            try:
                extra = sock.recv(4096)
                buf += extra
            except socket.timeout:
                pass
            break

    return ttype_sent


def test_ttype():
    env = DOSBoxTestEnv()
    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST TTYPE_QUERY",
            "EXIT",
        ])
        env.start()

        if not wait_for_rdy(env, "TTYPE_WAITING_DCD"):
            print("FAIL: test_ttype - COMTEST did not reach ready state")
            env.wait_for_exit(timeout=10)
            return False

        sock = connect_with_retries()
        if sock is None:
            print("FAIL: test_ttype - could not connect")
            env.wait_for_exit(timeout=10)
            return False

        ttype_ok = handle_telnet_negotiation(sock)
        if not ttype_ok:
            print("FAIL: test_ttype - VMODEM did not negotiate TTYPE")
            sock.close()
            env.wait_for_exit(timeout=10)
            return False

        vlog("TTYPE negotiation complete, waiting for COMTEST to query...")

        if not wait_for_rdy(env, "TTYPE_DONE", timeout=30):
            print("FAIL: test_ttype - COMTEST did not finish query")
            sock.close()
            env.wait_for_exit(timeout=10)
            return False

        sock.close()
        env.wait_for_exit(timeout=45)

        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []
        if is_verbose() and log_text:
            print(f"  LOG:\n{log_text}")

        passed = True
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")
            if status == "FAIL":
                passed = False

        if not results:
            print("FAIL: test_ttype - no COMTEST.LOG results")
            return False

        return passed
    finally:
        env.cleanup()


if __name__ == "__main__":
    import sys
    sys.exit(0 if test_ttype() else 1)
