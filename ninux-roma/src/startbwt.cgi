#!/bin/sh

cat <<EOF
Content-type: text/javascript



EOF

lockFile="/var/lock/bwtclient.lock"

start()
{
	[ -f ${lockFile} ] ||
	{
		echo "running" > $lockFile

		duration="15" # Per test duration in seconds
		server="localhost"
		pvOutOption="-f -a"

		param="$(echo $QUERY_STRING | tr '&' '\n' | grep -m 1 '^server=')"

		temp="$(echo ${param:7} | grep '^[a-zA-Z0-9.:]\+$')"
		[ ${#temp} -gt 0 ] && server=${temp}

		echo "" > /tmp/bwtsimc
		echo "" > /tmp/bwtsims
		echo "" > /tmp/bwtasims
		echo "" > /tmp/bwtasimc

		port=5000
		((yes $(seq -s , 1 260) | pv $pvOutOption 2> /tmp/bwtsimc | nc ${server} ${port} | pv $pvOutOption 2> /tmp/bwtsims 1>/dev/null)&)
		sleep $duration
		kill $(pgrep -f "nc ${server} ${port}")
		sleep 2

		port=5001
		((yes $(seq -s , 1 260) | pv -q -L 10 | nc ${server} ${port} | pv $pvOutOption 2> /tmp/bwtasims 1>/dev/null)&)
		sleep $duration
		kill $(pgrep -f "nc ${server} ${port}")
		sleep 2

		port=5002
		((yes $(seq -s , 1 260) | pv $pvOutOption 2> /tmp/bwtasimc | nc ${server} ${port} 1>/dev/null)&)
		sleep $duration
		kill $(pgrep -f "nc ${server} ${port}")
		sleep 2

		rm -rf $lockFile
	}
}

((start)&)
