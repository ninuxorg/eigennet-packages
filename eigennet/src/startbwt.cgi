#!/bin/sh

cat <<EOF
Content-type: text/javascript



EOF

lockFile="/var/run/bwtclient.lock"

duration="15" # Per test duration in seconds
server="localhost"

[ -f ${lockFile} ] ||
{
	echo "running" > $lockFile

	param="$(echo $QUERY_STRING | tr '&' '\n' | grep -m 1 '^server=')"

	temp="$(echo ${param:7} | grep -q '^[a-zA-Z0-9.:]\+$')"
	[ ${#temp} -gt 0 ] && server=${temp}

	rm /tmp/bwtsimc /tmp/bwtsims /tmp/bwtsims /tmp/bwtasimc &> /dev/null || true

	port=5000
	sleep $((($duration*0)+0)) && yes $(seq -s , 1 260) | pv -c -f -a 2> /tmp/bwtsimc | nc ${server} ${port} | pv -c -f -a 2> /tmp/bwtsims 1>/dev/null &
	sleep $((($duration*1)+0)) && kill $(pgrep -f "nc ${server} ${port}") &

	port=5001
	sleep $((($duration*1)+4)) && nc ${server} ${port} | pv -c -f -a 2> /tmp/bwtasims 1>/dev/null &
	sleep $((($duration*2)+4)) && kill $(pgrep -f "nc ${server} ${port}") &

	port=5002
	sleep $((($duration*2)+8)) && yes $(seq -s , 1 260) | pv -c -f -a 2> /tmp/bwtasimc | nc ${server} ${port} &
	sleep $((($duration*3)+8)) && kill $(pgrep -f "nc ${server} ${port}") &

	sleep $((($duration*3)+9)) && rm -rf $lockFile &
}