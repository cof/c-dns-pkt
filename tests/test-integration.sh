#!/bin/bash
echo "Running integration"

BUILD_DIR="${BUILD_DIR:-build}"
SCRIPT_NAME=$(basename "$0" .sh)
TEST_LOG="${BUILD_DIR}/${SCRIPT_NAME}.log"
TEST_PCAP="${BUILD_DIR}/${SCRIPT_NAME}.pcap"

mkdir -p $BUILD_DIR || exit 1
> "$TEST_LOG"

TOTAL_TESTS=0
PASSED_TESTS=0

# check test-name gen-mode exit_status [args]
check() {
    local test_name=$1
    local gen_mode=$2
    local expect_status=$3
    shift 3
    
    TOTAL_TESTS=$((TOTAL_TESTS + 1))

    rm -f $TEST_PCAP
    ./dns-gen $gen_mode "$@" --output $TEST_PCAP >>$TEST_LOG 2>&1
    exit_code=$?
    if [ $exit_code -eq 0 ]; then
        ./dns-inspect readpcap --file $TEST_PCAP >>$TEST_LOG 2>&1
        exit_code=$?
    fi
    
    if [ $exit_code -eq $expect_status ]; then
        RESULT="PASS"
        PASSED_TESTS=$((PASSED_TESTS + 1))
    else
        RESULT="FAIL"
    fi

    echo "[TEST] $test_name... $RESULT"
}

# exit codes 
BAD_LABEL=4
BAD_PDU=5

# postive cases
check "Simple A query" resp 0 --id 0x1234 --name test.local --answer 192.168.1.1
check "Response with compression" resp 0 \
    --id 0x1234 --name  example.com --answer www.example.com --answer mail.example.com --answer api.dev.example.com 
check "Multiple answers" resp 0 --id 0x1234 --name test.local --answer 192.168.1.1 --answer 172.168.0.1

# label tests
check "Reject oversized label" resp $BAD_LABEL \
    --id 0x1234 --name "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.com" --answer 192.168.1.1

# fuzz tests
check "Truncated Header" fuzz $BAD_PDU --type hdr-trunc
check "Invalid compression pointer (loop)" fuzz $BAD_PDU --type qd-cmploop 
check "Invalid compression pointer (range)" fuzz $BAD_PDU --type qd-badjmp 
check "Invalid OPCODE" fuzz $BAD_PDU --type hdr-opcode 
check "Invalid RCODE" fuzz $BAD_PDU --type hdr-rcode 

echo "${PASSED_TESTS}/${TOTAL_TESTS} tests passed"

[ "$PASSED_TESTS" -eq "$TOTAL_TESTS" ] || exit 1
