#!/bin/bash

# make temp dirs
rm -rf /tmp/gw
mkdir /tmp/gw
rm -rf /tmp/covdata
mkdir /tmp/covdata
rm -rf /tmp/https.covdata
mkdir /tmp/https.covdata
rm -rf /tmp/versioning.covdata
mkdir /tmp/versioning.covdata
rm -rf /tmp/versioning.https.covdata
mkdir /tmp/versioning.https.covdata
rm -rf /tmp/noacl.covdata
mkdir /tmp/noacl.covdata

rm -rf /tmp/versioningdir
mkdir /tmp/versioningdir

# setup tls certificate and key
ECHO "Generating TLS certificate and key in the cert.pem and key.pem files"

openssl genpkey -algorithm RSA -out key.pem -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key key.pem -out cert.pem -days 365 -subj "/C=US/ST=California/L=San Francisco/O=Versity/OU=Software/CN=versity.com"

ECHO "Running the sdk test over http"
# run server in background not versioning-enabled
# port: 7070(default)
GOCOVERDIR=/tmp/covdata ./versitygw -a user -s pass --iam-dir /tmp/gw posix /tmp/gw &
GW_PID=$!

sleep 1

# check if gateway process is still running
if ! kill -0 $GW_PID; then
	echo "server no longer running"
	exit 1
fi

# run tests
# full flow tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7070 full-flow --parallel; then
	echo "full flow tests failed"
	kill $GW_PID
	exit 1
fi
# posix tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7070 posix; then
	echo "posix tests failed"
	kill $GW_PID
	exit 1
fi
# iam tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7070 iam; then
	echo "iam tests failed"
	kill $GW_PID
	exit 1
fi

kill $GW_PID

ECHO "Running the sdk test over https"

# run server in background with TLS certificate
# port: 7071(default)
GOCOVERDIR=/tmp/https.covdata ./versitygw --cert "$PWD/cert.pem" --key "$PWD/key.pem" -p :7071 -a user -s pass --iam-dir /tmp/gw posix /tmp/gw &
GW_HTTPS_PID=$!

sleep 1

# check if https gateway process is still running
if ! kill -0 $GW_HTTPS_PID; then
	echo "server no longer running"
	exit 1
fi

# run tests
# full flow tests
if ! ./versitygw test --allow-insecure -a user -s pass -e https://127.0.0.1:7071 full-flow --parallel; then
	echo "full flow tests failed"
	kill $GW_HTTPS_PID
	exit 1
fi
# posix tests
if ! ./versitygw test --allow-insecure -a user -s pass -e https://127.0.0.1:7071 posix; then
	echo "posix tests failed"
	kill $GW_HTTPS_PID
	exit 1
fi
# iam tests
if ! ./versitygw test --allow-insecure -a user -s pass -e https://127.0.0.1:7071 iam; then
	echo "iam tests failed"
	kill $GW_HTTPS_PID
	exit 1
fi

kill $GW_HTTPS_PID

ECHO "Running the sdk test over http against the versioning-enabled gateway"
# run server in background versioning-enabled
# port: 7072
GOCOVERDIR=/tmp/versioning.covdata ./versitygw -p :7072 -a user -s pass --iam-dir /tmp/gw posix --versioning-dir /tmp/versioningdir /tmp/gw &
GW_VS_PID=$!

# wait a second for server to start up
sleep 1

# check if versioning-enabled gateway process is still running
if ! kill -0 $GW_VS_PID; then
	echo "versioning-enabled server no longer running"
	exit 1
fi

# run tests
# full flow tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7072 full-flow -vs --parallel; then
	echo "versioning-enabled full-flow tests failed"
	kill $GW_VS_PID
	exit 1
fi
# posix tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7072 posix -vs; then
	echo "versiongin-enabled posix tests failed"
	kill $GW_VS_PID
	exit 1
fi

# kill off server
kill $GW_VS_PID

ECHO "Running the sdk test over https against the versioning-enabled gateway"
# run server in background versioning-enabled
# port: 7073
GOCOVERDIR=/tmp/versioning.https.covdata ./versitygw --cert "$PWD/cert.pem" --key "$PWD/key.pem" -p :7073 -a user -s pass --iam-dir /tmp/gw posix --versioning-dir /tmp/versioningdir /tmp/gw &
GW_VS_HTTPS_PID=$!

# wait a second for server to start up
sleep 1

# check if versioning-enabled gateway process is still running
if ! kill -0 $GW_VS_HTTPS_PID; then
	echo "versioning-enabled server no longer running"
	exit 1
fi

# run tests
# full flow tests
if ! ./versitygw test --allow-insecure -a user -s pass -e https://127.0.0.1:7073 full-flow -vs --parallel; then
	echo "versioning-enabled full-flow tests failed"
	kill $GW_VS_HTTPS_PID
	exit 1
fi
# posix tests
if ! ./versitygw test --allow-insecure -a user -s pass -e https://127.0.0.1:7073 posix -vs; then
	echo "versiongin-enabled posix tests failed"
	kill $GW_VS_HTTPS_PID
	exit 1
fi

# kill off server
kill $GW_VS_HTTPS_PID

ECHO "Running No ACL integration tests"
# run server in background versioning-enabled
# port: 7073
GOCOVERDIR=/tmp/noacl.covdata ./versitygw -p :7074 -a user -s pass -noacl --iam-dir /tmp/gw posix /tmp/gw &
GW_NO_ACL_PID=$!

# wait a second for server to start up
sleep 1

# check if noacl gateway process is still running
if ! kill -0 $GW_NO_ACL_PID; then
	echo "noacl server no longer running"
	exit 1
fi

if ! ./versitygw test --allow-insecure -a user -s pass -e http://127.0.0.1:7074 noacl; then
	echo "No ACL integration tests failed"
	kill $GW_NO_ACL_PID
	exit 1
fi

# kill off server
kill $GW_NO_ACL_PID

exit 0

# -----------------------------------------------------------------------------
# Coverage Reports (Go 1.20+ Runtime Coverage)
#
# The servers above were started with GOCOVERDIR=<dir>, which causes Go to write
# raw coverage artifacts into those directories (covmeta + covcounters.* files).
# These raw files must be processed with "go tool covdata" to generate
# human-readable coverage reports.
#
# You may generate *per-environment* coverage or a *merged full-suite* report.
#
# -----------------------------------------------------------------------------
# 1) INDIVIDUAL COVERAGE REPORTS
#
# Example for a single environment (e.g. /tmp/covdata):
#
#   go tool covdata percent -i=/tmp/covdata
#   go tool covdata textfmt -i=/tmp/covdata -o /tmp/profile.txt
#   go tool cover -html=/tmp/profile.txt
#
# Repeat using:
#   /tmp/covdata
#   /tmp/https.covdata
#   /tmp/versioning.covdata
#   /tmp/versioning.https.covdata
#   /tmp/noacl.covdata
#
# This gives you coverage metrics isolated per test suite / server mode.
#
# -----------------------------------------------------------------------------
# 2) MERGED COVERAGE REPORT (RECOMMENDED)
#
# If you want a unified report combining all environments:
#
#   go tool covdata merge \
#     -i=/tmp/covdata,/tmp/https.covdata,/tmp/versioning.covdata,/tmp/versioning.https.covdata,/tmp/noacl.covdata \
#     -o /tmp/allcovdata
#
#   go tool covdata percent -i=/tmp/allcovdata
#   go tool covdata textfmt -i=/tmp/allcovdata -o /tmp/all_profile.txt
#   go tool cover -html=/tmp/all_profile.txt
#
# This produces the full aggregate coverage across all HTTP/HTTPS,
# versioning-enabled, non-versioning, and no-ACL test runs.
#
# -----------------------------------------------------------------------------
