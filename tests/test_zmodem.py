#!/usr/bin/env python3
"""Test ZMODEM file transfer: COMTEST sends file via FOSSIL, Python receives via TCP.

Flow:
  COMTEST (ZMODEM sender) -> FOSSIL -> VMODEM -> TCP -> Python (ZMODEM receiver)

COMTEST sends a known test file.  Python receives it via ZMODEM protocol
and verifies the content matches.
"""

import os
import socket
import sys
import time

from testenv import (DOSBoxTestEnv, is_verbose, parse_comtest_log,
                     set_verbose, vlog, wait_for_rdy)

# ---- ZMODEM constants ----

ZPAD = 0x2A   # '*'
ZDLE = 0x18
ZHEX = 0x42   # 'B'
ZBIN = 0x41   # 'A'

ZRQINIT = 0
ZRINIT  = 1
ZFILE   = 4
ZFIN    = 8
ZRPOS   = 9
ZDATA   = 10
ZEOF    = 11

ZCRCE = 0x68   # frame ends, header follows
ZCRCG = 0x69   # frame continues
ZCRCQ = 0x6A   # frame continues, ZACK expected
ZCRCW = 0x6B   # frame ends, wait for response

CANFDX = 0x01  # receiver capability: full duplex

# ---- CRC-16 CCITT ----

def _build_crc16_table():
    table = []
    for i in range(256):
        crc = i << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
        table.append(crc)
    return table

_CRC16_TAB = _build_crc16_table()

def _crc16_update(crc, byte):
    return ((crc << 8) ^ _CRC16_TAB[((crc >> 8) ^ byte) & 0xFF]) & 0xFFFF

def _crc16(data):
    """CRC-16 CCITT over data, finalized with two zero bytes."""
    crc = 0
    for b in data:
        crc = _crc16_update(crc, b)
    crc = _crc16_update(_crc16_update(crc, 0), 0)
    return crc

# ---- ZMODEM receiver ----

class ZModemReceiver:
    """Minimal ZMODEM receiver over a raw TCP socket (with telnet IAC stripping)."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()
        self.files = {}
        self._tel_state = 0   # telnet IAC filter state

    def _raw_recv(self, timeout=30):
        """Receive from socket, strip telnet IAC sequences, append to buf."""
        self.sock.settimeout(max(timeout, 0.5))
        try:
            data = self.sock.recv(4096)
            if not data:
                return False
        except socket.timeout:
            return False

        i = 0
        while i < len(data):
            b = data[i]
            i += 1
            if self._tel_state == 0:
                if b == 0xFF:
                    self._tel_state = 1
                else:
                    self.buf.append(b)
            elif self._tel_state == 1:
                if b == 0xFF:
                    self.buf.append(0xFF)
                    self._tel_state = 0
                elif b in (0xFB, 0xFC, 0xFD, 0xFE):
                    self._tel_state = 2  # WILL/WONT/DO/DONT + 1 byte
                elif b == 0xFA:
                    self._tel_state = 3  # SB ... IAC SE
                else:
                    self._tel_state = 0
            elif self._tel_state == 2:
                self._tel_state = 0
            elif self._tel_state == 3:
                if b == 0xFF:
                    self._tel_state = 4
            elif self._tel_state == 4:
                self._tel_state = 0 if b == 0xF0 else 3
        return True

    def _get_byte(self, timeout=30):
        deadline = time.time() + timeout
        while not self.buf:
            remaining = deadline - time.time()
            if remaining <= 0:
                return -1
            self._raw_recv(min(remaining, 5))
        b = self.buf[0]
        del self.buf[0]
        return b

    def _wait_for_zpad(self, timeout=60):
        """Wait for ZPAD ZPAD ZDLE, return the encoding byte (ZHEX/ZBIN)."""
        deadline = time.time() + timeout
        state = 0
        while time.time() < deadline:
            b = self._get_byte(deadline - time.time())
            if b < 0:
                return -1
            if state == 0:
                state = 1 if b == ZPAD else 0
            elif state == 1:
                if b == ZPAD:
                    state = 1
                elif b == ZDLE:
                    state = 2
                else:
                    state = 0
            elif state == 2:
                return b
        return -1

    def _recv_hex_header(self, timeout=30):
        """Read hex header after ** ZDLE ZHEX.  Returns (type, pos)."""
        deadline = time.time() + timeout
        hexchars = []
        while len(hexchars) < 14 and time.time() < deadline:
            b = self._get_byte(deadline - time.time())
            if b < 0:
                return -1, 0
            ch = chr(b)
            if ch in '0123456789abcdefABCDEF':
                hexchars.append(ch)
            elif ch in '\r\n':
                continue

        if len(hexchars) < 14:
            return -1, 0

        # Consume trailing CR/LF/XON
        while True:
            b = self._get_byte(2)
            if b < 0:
                break
            if b in (0x0D, 0x0A, 0x11):
                continue
            self.buf.insert(0, b)
            break

        hex_str = ''.join(hexchars)
        hdr_bytes = bytes.fromhex(hex_str[:10])
        crc_recv = int(hex_str[10:14], 16)
        crc_calc = _crc16(hdr_bytes)

        if crc_calc != crc_recv:
            vlog(f"Hex CRC mismatch: calc={crc_calc:04x} recv={crc_recv:04x}")
            return -2, 0

        ftype = hdr_bytes[0]
        pos = (hdr_bytes[1] | (hdr_bytes[2] << 8) |
               (hdr_bytes[3] << 16) | (hdr_bytes[4] << 24))
        return ftype, pos

    def _recv_bin16_header(self, timeout=30):
        """Read binary CRC-16 header after ** ZDLE ZBIN."""
        deadline = time.time() + timeout
        hdr = []
        for _ in range(5):
            b = self._get_byte(deadline - time.time())
            if b < 0:
                return -1, 0
            if b == ZDLE:
                b = self._get_byte(deadline - time.time())
                if b < 0:
                    return -1, 0
                b ^= 0x40
            hdr.append(b)

        crc_bytes = []
        for _ in range(2):
            b = self._get_byte(deadline - time.time())
            if b < 0:
                return -1, 0
            if b == ZDLE:
                b = self._get_byte(deadline - time.time())
                if b < 0:
                    return -1, 0
                b ^= 0x40
            crc_bytes.append(b)

        crc_recv = (crc_bytes[0] << 8) | crc_bytes[1]
        crc_calc = _crc16(bytes(hdr))
        if crc_calc != crc_recv:
            return -2, 0

        ftype = hdr[0]
        pos = hdr[1] | (hdr[2] << 8) | (hdr[3] << 16) | (hdr[4] << 24)
        return ftype, pos

    def recv_header(self, timeout=60):
        """Receive any header.  Returns (type, pos)."""
        enc = self._wait_for_zpad(timeout)
        if enc < 0:
            return -1, 0
        if enc == ZHEX:
            return self._recv_hex_header(timeout)
        if enc == ZBIN:
            return self._recv_bin16_header(timeout)
        vlog(f"Unknown header encoding: {enc:#x}")
        return -1, 0

    def recv_data_subpacket(self, timeout=30):
        """Receive ZDLE-escaped data subpacket.
        Returns (data_bytes, frame_end_type) or (None, -1)."""
        deadline = time.time() + timeout
        data = bytearray()

        while time.time() < deadline:
            b = self._get_byte(deadline - time.time())
            if b < 0:
                return None, -1

            if b == ZDLE:
                b2 = self._get_byte(deadline - time.time())
                if b2 < 0:
                    return None, -1
                if b2 in (ZCRCE, ZCRCG, ZCRCQ, ZCRCW):
                    # End of subpacket - verify CRC
                    crc = 0
                    for byte in data:
                        crc = _crc16_update(crc, byte)
                    crc = _crc16_update(crc, b2)
                    crc = _crc16_update(_crc16_update(crc, 0), 0)

                    crc_bytes = []
                    for _ in range(2):
                        c = self._get_byte(deadline - time.time())
                        if c < 0:
                            return None, -1
                        if c == ZDLE:
                            c = self._get_byte(deadline - time.time())
                            if c < 0:
                                return None, -1
                            c ^= 0x40
                        crc_bytes.append(c)

                    crc_recv = (crc_bytes[0] << 8) | crc_bytes[1]
                    if crc != crc_recv:
                        vlog(f"Data CRC mismatch: calc={crc:04x} recv={crc_recv:04x}")
                        return None, -2

                    return bytes(data), b2
                else:
                    data.append(b2 ^ 0x40)
            else:
                data.append(b)

        return None, -1

    def send_hex_header(self, ftype, pos=0):
        """Send a hex header to the remote."""
        hdr = bytes([ftype,
                     pos & 0xFF,
                     (pos >> 8) & 0xFF,
                     (pos >> 16) & 0xFF,
                     (pos >> 24) & 0xFF])
        crc = _crc16(hdr)

        out = bytes([ZPAD, ZPAD, ZDLE, ZHEX])
        out += hdr.hex().encode('ascii')
        out += f"{crc:04x}".encode('ascii')
        out += b'\r\n'
        if ftype != ZFIN:
            out += bytes([0x11])
        self.sock.sendall(out)

    def receive_file(self, timeout=60):
        """Run full ZMODEM receive session.  Returns {filename: data}."""
        deadline = time.time() + timeout

        # Wait for ZRQINIT
        while time.time() < deadline:
            ftype, pos = self.recv_header(deadline - time.time())
            vlog(f"Header: type={ftype} pos={pos}")
            if ftype == ZRQINIT:
                break
            if ftype < 0:
                vlog(f"Failed waiting for ZRQINIT (got {ftype})")
                return {}

        # Send ZRINIT
        self.send_hex_header(ZRINIT, CANFDX)
        vlog("Sent ZRINIT")

        while time.time() < deadline:
            ftype, pos = self.recv_header(deadline - time.time())
            vlog(f"Header: type={ftype} pos={pos}")

            if ftype == ZFIN:
                self.send_hex_header(ZFIN)
                vlog("Session complete (ZFIN)")
                # Wait for "OO" and give sender time to receive our ZFIN
                time.sleep(2)
                break

            if ftype == ZRQINIT:
                self.send_hex_header(ZRINIT, CANFDX)
                continue

            if ftype != ZFILE:
                vlog(f"Expected ZFILE, got {ftype}")
                continue

            # Read file info subpacket
            fileinfo, fe = self.recv_data_subpacket(30)
            if fileinfo is None:
                vlog("Failed to receive ZFILE data subpacket")
                return self.files

            # Parse: filename\0size[ date ...]\0
            parts = fileinfo.split(b'\x00')
            filename = parts[0].decode('ascii', errors='replace')
            filesize = 0
            if len(parts) > 1 and parts[1]:
                try:
                    filesize = int(parts[1].split(b' ')[0])
                except ValueError:
                    pass
            vlog(f"File: {filename!r}, size={filesize}")

            # Send ZRPOS 0
            self.send_hex_header(ZRPOS, 0)
            vlog("Sent ZRPOS 0")

            # Receive ZDATA + subpackets
            ftype, pos = self.recv_header(30)
            if ftype != ZDATA:
                vlog(f"Expected ZDATA, got {ftype}")
                return self.files

            file_data = bytearray()
            while True:
                chunk, fe = self.recv_data_subpacket(30)
                if chunk is None:
                    vlog("Failed to receive data subpacket")
                    break
                file_data.extend(chunk)
                vlog(f"Data: {len(chunk)} bytes, end={fe:#x}")
                if fe in (ZCRCE, ZCRCW):
                    break

            self.files[filename] = bytes(file_data)

            # Wait for ZEOF
            ftype, pos = self.recv_header(30)
            if ftype == ZEOF:
                vlog(f"ZEOF at pos={pos}")
            else:
                vlog(f"Expected ZEOF, got {ftype}")

            # Send ZRINIT (ready for next file)
            self.send_hex_header(ZRINIT, CANFDX)
            vlog("Sent ZRINIT (next file)")

        return self.files


# ---- Test ----

# 256-byte binary file: every byte value 0x00-0xFF.
# Exercises ZDLE escaping (0x10, 0x11, 0x13, 0x18, 0x90, 0x91, 0x93, 0xFF)
# and telnet IAC transparency (0xFF).
EXPECTED_DATA = bytes(range(256))
EXPECTED_FILENAME = "TEST.BIN"


def test_zmodem():
    env = DOSBoxTestEnv()

    try:
        env.setup([
            "VMODEM /L:1:2323 /D:VMODEM.LOG",
            "COMTEST ZMODEM_SEND",
            "EXIT",
        ])
        env.start()

        if not wait_for_rdy(env, "ZMODEM_WAITING_DCD", timeout=60):
            print("FAIL: test_zmodem - COMTEST not ready (timeout)")
            return False

        vlog("COMTEST ready, connecting...")

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(30)
        try:
            sock.connect(("127.0.0.1", 2323))
            vlog("Connected to VMODEM")
        except Exception as e:
            print(f"FAIL: test_zmodem - connect failed: {e}")
            return False

        # Give COMTEST time to detect DCD and start ZMODEM
        time.sleep(2)

        # Run ZMODEM receive
        zr = ZModemReceiver(sock)
        files = zr.receive_file(timeout=60)

        # Keep socket open briefly so sender can finish ZFIN handshake
        time.sleep(2)
        sock.close()
        env.wait_for_exit(timeout=30)

        # Read COMTEST results
        log_text = env.read_comtest_log()
        results = parse_comtest_log(log_text) if log_text else []

        if is_verbose() and log_text:
            print(f"  COMTEST.LOG:\n{log_text}")

        # Verify file
        got_file = EXPECTED_FILENAME in files
        data_match = files.get(EXPECTED_FILENAME, b"") == EXPECTED_DATA

        print(f"  {'PASS' if got_file else 'FAIL'}: FILE_RECEIVED"
              f" (files: {list(files.keys())})")
        recv_data = files.get(EXPECTED_FILENAME, b"")
        print(f"  {'PASS' if data_match else 'FAIL'}: DATA_MATCH"
              f" ({len(recv_data)}/{len(EXPECTED_DATA)} bytes)")

        if not data_match and EXPECTED_FILENAME in files:
            # Show first difference
            for i in range(min(len(recv_data), len(EXPECTED_DATA))):
                if recv_data[i] != EXPECTED_DATA[i]:
                    print(f"    First diff at offset {i}: "
                          f"got {recv_data[i]:#04x}, "
                          f"expected {EXPECTED_DATA[i]:#04x}")
                    break
            if len(recv_data) != len(EXPECTED_DATA):
                print(f"    Length: got {len(recv_data)}, "
                      f"expected {len(EXPECTED_DATA)}")

        all_pass = got_file and data_match
        for status, name, detail in results:
            print(f"  {status}: {name} {detail}")
            if status == "FAIL":
                all_pass = False

        return all_pass
    finally:
        env.cleanup()


if __name__ == "__main__":
    if "-v" in sys.argv or "--verbose" in sys.argv:
        set_verbose(True)
    sys.exit(0 if test_zmodem() else 1)
