#!/bin/sh /etc/rc.common

config_load eigennet

	local cpu=$(cat /proc/cpuinfo |grep type | awk '{ printf "%.4s\n",$5 }')
	local wget_info=$(opkg info wget | grep Status | awk '{ print $4 }')
	local ip4_gw_lan	; config_get	ip4_gw_lan	network	"ip4_gw_lan"
	local gtw=$(ip -4 r s | grep default)

	if [ -n "$gtw" ]
		then
			echo "The default gateway is: $gtw"
		else
			if [ -n "$ip4_gw_lan" ]
				then
					echo "The default gateway will be set to: ${ip4_gw_lan}"
					ip -4 r a default via ${ip4_gw_lan} dev br-lan
					local gtw=$(ip -4 r s | grep default)
					echo "The default gateway is set to: ${gtw}"
				else
					echo "Insert the IP of the default gateway and press [ENTER]"
					read gtw
					ip -4 r a default via ${gtw} dev br-lan
					local gtw=$(ip -4 r s | grep default)
					echo "The default gateway is set to: ${gtw}"
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

mv /etc/opkg.conf /etc/opkg.bak
touch /etc/opkg.conf
cat > /etc/opkg.conf << EOF
src/gz attitude_adjustment http://downloads.openwrt.org/snapshots/trunk/ar71xx/packages
src/gz customized_adjustment http://cleopatra.ninux.org/arka_backfire/eigennet-packages-arka/${path}/packages
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
		echo "wget in not found, so will be installed"
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
	echo "Do you want enable OLSRd at next reboot ? [1 for enable or 0 for disable] [ENTER]"
	while read olsrd_enable; do
		[ $olsrd_enable -eq 1 ] &&
		{
			olsrd_enable=$olsrd_enable
			echo "OLSRd will be enabled at next reboot"
			uci set eigennet.olsrd.enable=${olsrd_enable}
			break
		}

		[ $olsrd_enable -eq 0 ] &&
		{
			olsrd_enable=$olsrd_enable
			echo "OLSRd will be disabled at next reboot"
			uci set eigennet.olsrd.enable=${olsrd_enable}
			break
		}

		[ $enable_disable > 1 ] || [ -z $enable_disable ] &&
		{
			echo "$enable_disable is not accepted, try again"
			echo "Insert 1 for enable or 0 for disable OLSRd at next reboot"
			continue
		}
	done
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

