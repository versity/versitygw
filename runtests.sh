#!/bin/bash

# make temp dirs
mkdir /tmp/gw
rm -rf /tmp/covdata
mkdir /tmp/covdata

# run server in background
GOCOVERDIR=/tmp/covdata ./versitygw -a user -s pass posix /tmp/gw &
GW_PID=$!

# wait a second for server to start up
sleep 1

# check if server is still running
if ! kill -0 $GW_PID; then
	echo "server no longer running"
	exit 1
fi

# run tests
if ! ./versitygw test -a user -s pass -e http://127.0.0.1:7070 full-flow; then
	echo "tests failed"
	kill $GW_PID
	exit 1
fi

# kill off server
kill $GW_PID
exit 0

# if the above binary was built with -cover enabled (make testbin),
# then the following can be used for code coverage reports:
# go tool covdata percent -i=/tmp/covdata
# go tool covdata textfmt -i=/tmp/covdata -o profile.txt
# go tool cover -html=profile.txt

