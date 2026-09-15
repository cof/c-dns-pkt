#!/bin/sh

# Paths setup
BUILD_DIR="${BUILD_DIR:-build}"
SCRIPT_NAME=$(basename "$0" .sh)
TEST_LOG="${BUILD_DIR}/${SCRIPT_NAME}.log"

PCAP_DIR="tests/pcaps"
EXPECT_DIR="tests/expect"

TOTAL_TESTS=0
PASSED_TESTS=0

mkdir -p "$BUILD_DIR" || exit 1
> "$TEST_LOG"

echo "Running readpcap"
for pcap_file in $PCAP_DIR/*.pcap $PCAP_DIR/*.pcapng; do
    what=readpcap
    base_file=$(basename "$pcap_file")
    expect_file=$EXPECT_DIR/$base_file.$what
    output_file=$BUILD_DIR/$base_file.$what
    [ -e $expect_file ] || continue
    test_name=$base_file
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    ./dns-inspect $what --file $pcap_file > $output_file 2>/dev/null
    diff -u $expect_file $output_file >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        RESULT="PASS"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        RESULT="FAIL"
    fi
    echo "[TEST] $test_name... $RESULT"
done

echo "Running tracepcap"
for pcap_file in $PCAP_DIR/*.pcap $PCAP_DIR/*.pcapng; do
    what=tracepcap
    base_file=$(basename "$pcap_file")
    expect_file=$EXPECT_DIR/$base_file.$what
    output_file=$BUILD_DIR/$base_file.$what
    [ -e $expect_file ] || continue
    test_name=$base_file
    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    ./dns-inspect $what --file $pcap_file > $output_file 2>/dev/null
    diff -u $expect_file $output_file >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        RESULT="PASS"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        RESULT="FAIL"
    fi
    echo "[TEST] $test_name... $RESULT"
done

echo "${PASSED_TESTS}/${TOTAL_TESTS} tests passed"

[ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ] || exit 1
