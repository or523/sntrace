#!/bin/bash
set -e

echo "Building project..."
make clean all

echo "Running test..."
OUTPUT=$(./sntrace ./dummy_prog 2>&1)
echo "$OUTPUT"

echo "Verifying output..."
if echo "$OUTPUT" | grep -q "Syscall: write"; then
    echo "SUCCESS: Found 'Syscall: write'"
else
    echo "FAILURE: Did not find 'Syscall: write'"
    exit 1
fi

if echo "$OUTPUT" | grep -q "Hello from dummy!"; then
    echo "SUCCESS: Found dummy program output"
else
    echo "FAILURE: Did not find dummy program output"
    exit 1
fi

if echo "$OUTPUT" | grep -q 'Syscall: write (.*, "\\x'; then
    echo "SUCCESS: Found hex-dumped buffer in write"
else
    echo "FAILURE: Did not find hex-dumped buffer in write"
    exit 1
fi

echo "All tests passed!"

