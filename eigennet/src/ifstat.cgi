#!/bin/sh

cat <<EOF
Content-type: text/plain

EOF
echo "Interface rx_bytes tx_bytes rx_packets tx_packets"
for ifName in $(ls /sys/class/net)
do
	statPath="/sys/class/net/${ifName}/statistics/"
	echo "${ifName} $(cat ${statPath}/rx_bytes) $(cat ${statPath}/tx_bytes) $(cat ${statPath}/rx_packets) $(cat ${statPath}/tx_packets)"
done

echo
