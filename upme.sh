#!/bin/sh /etc/rc.common

config_load eigennet

	local cpu=$(cat /proc/cpuinfo |grep type | awk '{ printf "%.4s\n",$5 }')
	local wget_info=$(opkg info wget | grep Status | awk '{ print $4 }')
	local ip4_gw_lan		; config_get	ip4_gw_lan		network		"ip4_gw_lan"
	local gtw=$(ip -4 r s | grep default)

	if [ -n "$gtw" ]
		then
			echo "The default gateway is: $gtw"
		else
			if [ -n "$ip4_gw_lan" ]
				then
					echo "The default gateway will be setting: ${ip4_gw_lan}"
					ip -4 r a default via ${ip4_gw_lan} dev br-lan
					local gtw=$(ip -4 r s | grep default)
					echo "The default gateway is set correctly"
				else
					echo "Insert the IP of the default gateway and press [ENTER]"
					read gtw
					ip -4 r a default via ${gtw} dev br-lan
					local gtw=$(ip -4 r s | grep default)
					echo "The default gateway is set correctly"
			fi
	fi

	[ $cpu = AR23 ] &&
	{
		local path=ATHEROS
	}

	[ $cpu = AR71 ] || [ $cpu = AR72 ] || [ $cpu = AR91 ] || [ $cpu = AR93 ] &&
	{
		local path=UBNT_M
	}

cp /etc/opkg.conf /etc/opkg.bak
rm -rf /etc/opkg.conf
touch /etc/opkg.conf
cat > /etc/opkg.conf << EOF
src/gz customized_adjustment http://cleopatra.ninux.org/arka_backfire/eigennet-packages-arka/${path}/packages/
dest root /
dest ram /tmp
lists_dir ext /var/opkg-lists
option overlay_root /overlay
EOF

sleep 1s
echo "Checking the internet connection ...."

if ping -q -c 3 8.8.8.8 >/dev/null 5>/dev/null; then
	echo "Internet connection is ok"
	sleep 2s
	echo "Search if wget is installed"
	sleep 2s
	echo "Update packages"
	opkg update
	sleep 2s
	[ -z $wget_info ] || [ $wget_info = not-installed ] &&
	{
		sleep 2s
		echo wget will be installed
		sleep 2s
		opkg install wget
		sleep 2s
	}
	sleep 2s
	echo "Updating in progress ...."
	rm -rf /etc/init.d/eigennet
	sleep 1s
	wget --no-check-certificate https://raw.github.com/arkanet/eigennet-packages/roma/eigennet/src/eigennet.sh -O /etc/init.d/eigennet
	chmod +x /etc/init.d/eigennet
	uci set eigennet.general.bootmode=1
	uci set eigennet.olsrd.enable=0
	uci commit eigennet
	sleep 2s
	echo "Update complete, rebooting in 5 seconds ...."
	sleep 1s
	echo "4"
	sleep 1s
	echo "3"
	sleep 1s
	echo "2"
	sleep 1s
	echo "1"
	sleep 1s
	echo "Rebooting"
	sleep 1s
	sync
	sleep 2s
	reboot
else
	sleep 2s
	echo ""
	echo "The device seems not correctly connected to the internet"
	echo "Connect the device to the internet or"
	echo "Check your internet connection and tray again"
	echo ""
fi

exit 0

