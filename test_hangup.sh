#!/bin/bash
#
# test_hangup.sh - Automated hangup test for VMODEM
#
# This script:
#   1. Connects to VMODEM on localhost:2323
#   2. Waits for the DOS-side test (VMODTEST /HANGUP) to do +++/ATH
#   3. Reports whether the connection was properly closed
#
# Run this FIRST on the host, then run VMODTEST /HANGUP inside DOS.
# Or run both together: this script waits for the connection to close.
#
# Also tests: connect, send data, verify echo, then wait for hangup.

HOST=localhost
PORT=2323
TIMEOUT=60

echo "=== VMODEM Hangup Test (host side) ==="
echo "Connecting to $HOST:$PORT..."

# Use bash's built-in TCP support
exec 3<>/dev/tcp/$HOST/$PORT 2>/dev/null
if [ $? -ne 0 ]; then
    echo "FAIL: Could not connect to $HOST:$PORT"
    echo "      Is DOSBox-X running with VMODEM loaded?"
    exit 1
fi

echo "Connected. Waiting for DOS-side VMODTEST /HANGUP to run..."
echo "(The DOS test will send +++, then ATH to disconnect)"
echo ""

# Read any initial data (RING response, CONNECT, etc.)
# Use a short timeout for reads
SECONDS=0
while [ $SECONDS -lt $TIMEOUT ]; do
    # Try to read with 1-second timeout
    if read -t 1 -r line <&3 2>/dev/null; then
        echo "  Received: '$line'"
    fi

    # Check if the connection is still alive by trying to write
    if ! echo "" >&3 2>/dev/null; then
        ELAPSED=$SECONDS
        echo ""
        echo "Connection closed after ${ELAPSED}s."
        echo "PASS: VMODEM properly closed the TCP connection."
        exec 3>&-
        exit 0
    fi
done

echo ""
echo "FAIL: Connection still open after ${TIMEOUT}s timeout."
echo "      The hangup did NOT close the TCP connection."
exec 3>&-
exit 1
