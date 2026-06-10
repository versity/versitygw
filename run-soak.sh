#!/bin/bash

make

# Define paths and commands
DIR_PFX="/tmp"
SC_DIR="$DIR_PFX/sc"
GW_DIR="$DIR_PFX/gw"
GW_BIN="./versitygw"

ITERATIONS=100

# 1. Clean and recreate directories
rm -rf "$SC_DIR" "$GW_DIR"
mkdir -p "$SC_DIR" "$GW_DIR"

# 2. Start the background process and capture its PID
echo "Starting background gateway..."
$GW_BIN -a test -s test posix --sidecar "$SC_DIR" "$GW_DIR" &
BG_PID=$!

# 3. Setup trap to ensure the background process is ALWAYS killed on exit
cleanup() {
    echo "Cleaning up background process (PID: $BG_PID)..."
    if kill -0 "$BG_PID" 2>/dev/null; then
        kill "$BG_PID"
        wait "$BG_PID" 2>/dev/null
    fi
}
trap cleanup EXIT

# Give the background process a brief moment to initialize
sleep 2

# 4. Run the foreground test n times
echo "Starting $ITERATIONS iterations of the racey success test..."
for i in $(seq 1 $ITERATIONS); do
    echo "Iteration $i/$ITERATIONS..."
    
    $GW_BIN test -a test -s test -e http://127.0.0.1:7070 CompleteMultipartUpload_racey_success
    #$GW_BIN test -a test -s test -e http://127.0.0.1:7070 CompleteMultipartUpload_racey_data_integrity
    TEST_STATUS=$?
    
    if [ $TEST_STATUS -ne 0 ]; then
        echo "Test failed on iteration $i with exit code $TEST_STATUS."
        exit $TEST_STATUS
    fi
done

echo "All $ITERATIONS iterations passed successfully!"
