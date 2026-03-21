#!/bin/bash
#
# test_bbs_answer.sh - Automated test: restart DOSBox-X, connect, verify BBS sends data
#
# Iterates: deploy, restart DOSBox-X, wait for boot, connect to port 2323,
# check if BBS sends any data after connection. If not, dump the log and iterate.

set -e

DOSBOX_CONF="/home/reetus/dosdev/dosbox-x.conf"
DOSBOX_BIN="dosbox-x"
LOG_FILE="/home/reetus/dosdev/dosenv/vmodem/VMODEM.LOG"
VMODEM_SRC="/home/reetus/dosdev/vmodem"
VMODEM_DST="/home/reetus/dosdev/dosenv/vmodem"
PORT=2323
BOOT_TIMEOUT=45
CONNECT_WAIT=30
MAX_ITERATIONS=1

# Kill all DOSBox-X instances before starting
echo "[0] Killing all DOSBox-X instances..."
pkill -f "dosbox-x" 2>/dev/null || true
sleep 2
pkill -9 -f "dosbox-x" 2>/dev/null || true
sleep 1
echo "    Done."

for ITER in $(seq 1 $MAX_ITERATIONS); do
    echo ""
    echo "============================================"
    echo "  Iteration $ITER / $MAX_ITERATIONS"
    echo "============================================"
    echo ""

    # Step 1: Deploy latest binary
    echo "[1] Deploying latest binary..."
    cp "$VMODEM_SRC/vmodem.exe" "$VMODEM_DST/VMODEM.EXE"
    echo "    Done."

    # Step 2: Kill existing DOSBox-X
    echo "[2] Killing existing DOSBox-X..."
    pkill -f "dosbox-x" 2>/dev/null || true
    sleep 2
    if pgrep -f "dosbox-x" >/dev/null 2>&1; then
        pkill -9 -f "dosbox-x" 2>/dev/null || true
        sleep 1
    fi
    echo "    Done."

    # Step 3: Clear old log
    echo "[3] Clearing old log file..."
    rm -f "$LOG_FILE"
    echo "    Done."

    # Step 4: Start DOSBox-X
    echo "[4] Starting DOSBox-X..."
    cd /home/reetus/dosdev
    $DOSBOX_BIN -conf "$DOSBOX_CONF" &>/dev/null &
    DOSBOX_PID=$!
    echo "    PID=$DOSBOX_PID"

    # Step 5: Wait for VMODEM to boot
    # Don't use TCP probe — that creates a flash connection triggering RING/NO CARRIER.
    # Just wait for the process to settle and the port to appear.
    echo "[5] Waiting ${BOOT_TIMEOUT}s for DOSBox-X + BBS to boot..."
    sleep $BOOT_TIMEOUT
    echo "    Done."

    # Step 6: Connect and check for data from BBS
    echo "[6] Connecting to port $PORT, waiting ${CONNECT_WAIT}s for BBS data..."
    RECEIVED=""
    TMPFILE=$(mktemp /tmp/vmodem_test.XXXXXX)
    timeout $CONNECT_WAIT bash -c '
        exec 3<>/dev/tcp/localhost/'"$PORT"'
        # Brief pause for connection setup
        sleep 3
        # Send a CR to prompt the BBS
        echo -ne "\r" >&3
        sleep 5
        # Send another CR
        echo -ne "\r" >&3
        sleep 10
        # Capture raw data from fd 3
        timeout 5 cat <&3 > '"$TMPFILE"' 2>/dev/null || true
        exec 3>&-
    ' 2>/dev/null || true
    if [ -s "$TMPFILE" ]; then
        RECEIVED="yes"
    else
        RECEIVED=""
    fi

    echo ""
    if [ -n "$RECEIVED" ]; then
        echo "PASS: BBS sent data!"
        echo "Received (hex):"
        xxd "$TMPFILE" | head -10
        echo ""
        echo "--- VMODEM.LOG ---"
        cat -v "$LOG_FILE" 2>/dev/null | head -10
        echo ""
        echo "============================================"
        echo "  SUCCESS on iteration $ITER"
        echo "============================================"
        exit 0
    fi

    echo "FAIL: No data received from BBS."
    if [ -f "$TMPFILE" ]; then
        echo "Tmp file size: $(stat -c%s "$TMPFILE" 2>/dev/null || echo 0)"
        xxd "$TMPFILE" 2>/dev/null | head -5
    fi
    echo ""

    # Step 7: Dump log for analysis
    echo "--- VMODEM.LOG (hex) ---"
    xxd "$LOG_FILE" 2>/dev/null | head -20
    echo ""
    echo "--- VMODEM.LOG (printable) ---"
    cat -v "$LOG_FILE" 2>/dev/null | head -10
    echo ""
    echo "--- End of iteration $ITER ---"
    echo ""

done

echo "============================================"
echo "  FAIL: No success after $MAX_ITERATIONS iterations"
echo "============================================"
exit 1
