#!/bin/bash
GEN_NAME="./dns-gen"
INSPECT_NAME="./dns-inspect"
BUILD_DIR=build
TEST_LOG="$BUILD_DIR/test.log"
GEN_RESP="$GEN_NAME response"
GEN_FUZZ="$GEN_NAME fuzz"
CHK_RESP="$INSPECT_NAME readpcap --file"
TEST_PCAP="$BUILD_DIR/test.pcap"
BAD_PDU=4
BAD_LABEL=5
mkdir -p ${BUILD_DIR} || exit 1

TEST_NAME="Simple A query"
$GEN_RESP --id 0x1234 --name test.local --answer 192.168.1.1 --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq 0 ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Response with compression"
$GEN_RESP --id 0x1234 --name  example.com \
    --answer www.example.com --answer mail.example.com --answer api.dev.example.com \
    --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq 0 ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Multiple answers"
$GEN_RESP --id 0x1234 --name test.local --answer 192.168.1.1 --answer 172.168.0.1 --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq 0 ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Reject oversized label"
$GEN_RESP --id 0x1234  --name "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA.com" --answer 192.168.1.1 --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq $BAD_LABEL ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Truncated Header"
$GEN_FUZZ --type hdr-trunc --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq $BAD_PDU ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Invalid compression pointer (loop)"
$GEN_FUZZ --type qd-cmploop  --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq $BAD_PDU ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Invalid compression pointer (range)"
$GEN_FUZZ --type qd-badjmp  --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq $BAD_PDU ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Invalid OPCODE"
$GEN_FUZZ --type hdr-opcode  --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq $BAD_PDU ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Invalid RCODE"
$GEN_FUZZ --type hdr-rcode  --output $TEST_PCAP 1>$TEST_LOG 2>&1 &&
$CHK_RESP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq $BAD_PDU ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"
