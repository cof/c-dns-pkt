#!/bin/bash
GEN_NAME="./dns-gen"
INS_NAME="./dns-inspect"
BUILD_DIR=build
TEST_LOG="$BUILD_DIR/test.log"
GEN_RSP="$GEN_NAME response"
CHK_RSP="$INS_NAME readpcap --file"
TEST_PCAP="$BUILD_DIR/test.pcap"
mkdir -p ${BUILD_DIR} || exit 1

TEST_NAME="Simple A query"
$GEN_RSP --id 0x1234 --name test.local --answer 192.168.1.1 --output $TEST_PCAP 1>$TEST_LOG 2>&1
$CHK_RSP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq 0 ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"

TEST_NAME="Multiple answers"
$GEN_RSP --id 0x1234 --name test.local --answer 192.168.1.1 --answer 172.168.0.1 --output $TEST_PCAP 1>$TEST_LOG 2>&1
$CHK_RSP $TEST_PCAP 1>>$TEST_LOG 2>&1
[[ $? -eq 0 ]] && RESULT="PASS" || RESULT="FAIL"
echo "[TEST] $TEST_NAME... $RESULT"
