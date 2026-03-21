#!/bin/bash
#
# test_fossil_log.sh - Automated test: restart DOSBox-X, verify F: entries in log
#
# Tests that FOSSIL function calls (F:04, F:1B, etc.) appear in VMODEM.LOG.
# Kills any running DOSBox-X, starts fresh, waits for boot, connects to
# trigger FOSSIL activity, then checks the log file.

set -e

DOSBOX_CONF="/home/reetus/dosdev/dosbox-x.conf"
DOSBOX_BIN="dosbox-x"
LOG_FILE="/home/reetus/dosdev/dosenv/vmodem/VMODEM.LOG"
PORT=2323
BOOT_TIMEOUT=30
RESULT=0

echo "=== VMODEM FOSSIL Log Test ==="
echo ""

# Step 1: Ensure latest binaries are deployed
echo "[1] Deploying latest binaries..."
cp /home/reetus/dosdev/vmodem/vmodem.exe /home/reetus/dosdev/dosenv/vmodem/VMODEM.EXE
cp /home/reetus/dosdev/vmodem/vmodtest.exe /home/reetus/dosdev/dosenv/vmodem/VMODTEST.EXE
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

# Step 5: Wait for VMODEM to start listening
echo "[5] Waiting for VMODEM to boot (port $PORT)..."
ELAPSED=0
while [ $ELAPSED -lt $BOOT_TIMEOUT ]; do
    if timeout 1 bash -c "echo '' > /dev/tcp/localhost/$PORT" 2>/dev/null; then
        echo "    Port $PORT is open after ${ELAPSED}s."
        break
    fi
    sleep 1
    ELAPSED=$((ELAPSED + 1))
done

if [ $ELAPSED -ge $BOOT_TIMEOUT ]; then
    echo "    FAIL: Port $PORT not open after ${BOOT_TIMEOUT}s."
    kill $DOSBOX_PID 2>/dev/null
    exit 1
fi

# Give RA (BBS) a moment to initialize and send its AT commands
sleep 3

# Step 6: Check log file exists
echo "[6] Checking log file..."
if [ ! -f "$LOG_FILE" ]; then
    echo "    FAIL: $LOG_FILE does not exist."
    RESULT=1
else
    LOG_SIZE=$(stat -c%s "$LOG_FILE" 2>/dev/null || echo 0)
    echo "    Log file exists, size=$LOG_SIZE bytes."
fi

# Step 7: Connect to trigger FOSSIL activity (RING, ATA, CONNECT)
echo "[7] Connecting to VMODEM to trigger FOSSIL calls..."
timeout 5 bash -c '
exec 3<>/dev/tcp/localhost/'"$PORT"'
sleep 3
exec 3>&-
' 2>/dev/null || true
echo "    Connection test done."

# Wait for log flush
sleep 3

# Step 8: Read and analyze the log
echo "[8] Analyzing log file..."
echo ""

if [ ! -f "$LOG_FILE" ]; then
    echo "FAIL: Log file still does not exist."
    RESULT=1
else
    echo "--- Raw log (hex) ---"
    xxd "$LOG_FILE" | head -20
    echo ""

    echo "--- Log contents (printable) ---"
    cat -v "$LOG_FILE" | head -20
    echo ""
    echo "---"
    echo ""

    # Check for F: entries
    if grep -qP 'F:[0-9A-F]{2}' "$LOG_FILE" 2>/dev/null; then
        echo "PASS: Found F: entries in log!"
        echo ""
        echo "F: entries found:"
        grep -oP 'F:[0-9A-F]{2}' "$LOG_FILE" | sort | uniq -c | sort -rn
    else
        echo "FAIL: No F: entries found in log."
        echo ""
        echo "Log contains these recognizable entries:"
        grep -oP '\[AT:[^\]]+\]|\[RING\]|\[CONNECT\]|\[NO CARRIER\]|\[DTR-IO\]' "$LOG_FILE" 2>/dev/null || echo "(none)"
        RESULT=1
    fi
fi

echo ""
echo "=== Test result: $([ $RESULT -eq 0 ] && echo 'PASS' || echo 'FAIL') ==="
exit $RESULT
