#!/bin/bash

# make temp dirs
rm -rf /tmp/gw
mkdir /tmp/gw
rm -rf /tmp/covdata
mkdir /tmp/covdata
rm -rf /tmp/versioing.covdata
mkdir /tmp/versioning.covdata
rm -rf /tmp/versioningdir
mkdir /tmp/versioningdir

# run server in background not versioning-enabled
# port: 7070(default)
GOCOVERDIR=/tmp/covdata ./versitygw -a user -s pass --iam-dir /tmp/gw posix /tmp/gw &
GW_PID=$!

sleep 1

# check if versioning-enabled gateway process is still running
if ! kill -0 $GW_PID; then
	echo "server no longer running"
	exit 1
fi

# run tests
# full flow tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7070 full-flow; then
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

# run server in background versioning-enabled
# port: 7071
GOCOVERDIR=/tmp/versioning.covdata ./versitygw -p :7071 -a user -s pass --iam-dir /tmp/gw posix --versioning-dir /tmp/versioningdir /tmp/gw &
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
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7071 full-flow -vs; then
	echo "versioning-enabled full-flow tests failed"
	kill $GW_VS_PID
	exit 1
fi
# posix tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7071 posix -vs; then
	echo "versiongin-enabled posix tests failed"
	kill $GW_VS_PID
	exit 1
fi

# kill off server
kill $GW_VS_PID

exit 0

# if the above binary was built with -cover enabled (make testbin),
# then the following can be used for code coverage reports:
# go tool covdata percent -i=/tmp/covdata
# go tool covdata textfmt -i=/tmp/covdata -o profile.txt
# go tool cover -html=profile.txt

