#!/bin/sh

get_links()
{
	if [ $# -eq 1 ]
	then MAX_LINKS=$1
	else MAX_LINKS=100
	fi

	echo "
	$( for IF_NAME in $(ls /sys/class/net | grep '^ath')
	do
	wlanconfig $IF_NAME list station | awk '{if (NR!=1) {printf "%s\t%s\n", $6, $1}}' 
	done

	for IF_NAME in $(ls /sys/class/net | grep '^wlan')
	do
	PHY=$(cat /sys/class/net/${IF_NAME}/phy80211/name)
	for STATION in $(ls /sys/kernel/debug/ieee80211/${PHY}/netdev:${IF_NAME}/stations)
	do
		echo -e "$(cat /sys/kernel/debug/ieee80211/${PHY}/netdev:${IF_NAME}/stations/$STATION/last_signal)\t${STATION}"
	done
	done )
	" | sort -n -r | grep : | head -n ${MAX_LINKS}
}
