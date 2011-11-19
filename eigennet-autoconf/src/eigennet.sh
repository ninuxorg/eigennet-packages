#!/bin/sh /etc/rc.common

<<COPYRIGHT

Copyright (C) 2010-2011 Gioacchino Mazzurco <gmazzurco89@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this file.  If not, see <http://www.gnu.org/licenses/>.

COPYRIGHT

START=99
STOP=10

CONF_DIR="/etc/config/"

config_load eigennet

config_get debugLevel             general        "debugLevel"
config_get bootmode               general        "bootmode"

#[Doc]
#[Doc] Print mystring if mydebuglevel is greater or equal then debulLevel 
#[Doc]
#[Doc] usage: eigenDebug mydebuglevel mystring 
#[Doc]
#[Doc] example: eigenDebug 2 "setting autorized keys"
#[Doc]
eigenDebug()
{
	[ $1 -ge $debugLevel ] &&
	{
		echo "Debug: $@" >> /tmp/eigenlog
	}
}

#[Doc]
#[Doc] Del given uci interface from network file 
#[Doc]
#[Doc] usage:
#[Doc] del_interface uci_interface_name
#[Doc]
#[Doc] example:
#[Doc] del_interface lan0
#[Doc]
del_interface()
{
	uci del network.$1
}

#[Doc]
#[Doc] Return MAC of given interface
#[Doc]
#[Doc] usage:
#[Doc] get_mac ifname
#[Doc]
#[Doc] example:
#[Doc] get_mac eth0
#[Doc]
get_mac()
{
	ifname=${1}
	ifbase=$(echo $ifname | sed -e 's/[0-9]*$//')

	if [ $ifbase == "wifi" ]
		then
			mac=$(ifconfig $ifname | sed -n 1p | awk '{print $5}' | cut -c-17 | sed -e 's/-/:/g')
		elif [ $ifbase == "radio" ] ; then
				mac=$(cat /sys/class/ieee80211/$(echo ${ifname} | sed 's/radio/phy/g')/addresses)
		elif [ $ifbase == "phy" ] ; then
				mac=$(cat /sys/class/ieee80211/${ifname}/addresses)
		else
			mac=$(ifconfig $ifname | sed -n 1p | awk '{print $5}')
	fi

	echo $mac | tr '[a-z]' ['A-Z']
}

#[Doc]
#[Doc] Return given mac in ipv6 like format
#[Doc]
#[Doc] usage:
#[Doc] mac6ize mac_address
#[Doc]
#[Doc] example:
#[Doc] mac6ize ff:ff:ff:ff:ff:ff
#[Doc]
mac6ize()
{
	echo $1 | awk -F: '{print $1$2":"$3$4":"$5$6}' | tr '[a-z]' ['A-Z']
}

#[Doc]
#[Doc] Return physical interface list
#[Doc]
#[Doc] usage:
#[Doc] scan_devices
#[Doc]
scan_devices()
{
	eth=""
	radio=""
	wifi=""

	# Getting wired interfaces
	eth=$(cat /proc/net/dev | sed -n -e 's/:.*//' -e 's/[ /t]*//' -e '/^eth[0-9]$/p')

	# Getting ath9k interfaces
	if [ -e /lib/wifi/mac80211.sh ] && [ -e /sys/class/ieee80211/ ]
		then
			radio=$(ls /sys/class/ieee80211/ | sed -n -e '/^phy[0-9]$/p' | sed -e 's/^phy/radio/')
	fi

	# Getting madwifi interfaces
	if [ -e /lib/wifi/madwifi.sh ]
		then
			cd /proc/sys/dev/
			wifi=$(ls | grep wifi)
	fi

	echo "${eth} ${radio} ${wifi}" | sed 's/ /\n/g' | sed '/^$/d'
}

configureNetwork()
{
	local accept_clients        ; config_get_bool accept_clients    network     "accept_clients"
	local firewallEnabled       ; config_get_bool firewallEnabled   network     "firewall"
	local mesh6Prefix           ; config_get mesh6Prefix            network     "mesh6Prefix"
	local ip6gw                 ; config_get ip6gw                  network     "ip6gw"
	local resolvers             ; config_get resolvers              network     "resolvers"

	local wifi_clients          ; config_get_bool wifi_clients      wireless    "wifi_clients"
	local wifi_mesh             ; config_get_bool wifi_mesh         wireless    "wifi_mesh"
	local ath9k_clients         ; config_get_bool ath9k_clients     wireless    "wifi_clients"
	local ath9k_mesh            ; config_get_bool ath9k_mesh        wireless    "wifi_mesh"
	local madwifi_clients       ; config_get_bool madwifi_clients   wireless    "wifi_clients"
	local madwifi_mesh          ; config_get_bool madwifi_mesh      wireless    "wifi_mesh"
	local countrycode           ; config_get countrycode            wireless    "countrycode"
	local mesh2channel          ; config_get mesh2channel           wireless    "mesh2channel"
	local mesh5channel          ; config_get mesh5channel           wireless    "mesh5channel"
	local meshSSID              ; config_get meshSSID               wireless    "meshSSID"
	local meshBSSID             ; config_get meshBSSID              wireless    "meshBSSID"
	local meshMcastRate         ; config_get meshMcastRate          wireless    "meshMcastRate"
	local apSSID                ; config_get apSSID                 wireless    "apSSID"
	local apKEY                 ; config_get apKEY                  wireless    "apKEY"
	local apMaxClients          ; config_get apMaxClients           wireless    "apMaxClients"

	local eth_mesh              ; config_get_bool eth_mesh          wired       "eth_mesh"
	local eth_clients           ; config_get_bool eth_clients       wired       "eth_clients"

	if [ $firewallEnabled -eq 0 ]
		then
			/etc/init.d/firewall disable
		else
			/etc/init.d/firewall enable
	fi

	echo "
#Automatically generated for EigenNet

$(cat /etc/sysctl.conf | grep -v net.ipv4.ip_forward | grep -v net.ipv6.conf.all.forwarding | grep -v net.ipv6.conf.all.autoconf)

net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.autoconf=0
" > /etc/sysctl.conf

	echo "#Automatically generated for EigenNet" > $CONF_DIR/wireless

	echo "#Automatically generated for EigenNet
config 'mesh' 'bat0'" > $CONF_DIR/batman-adv

	rm -rf /etc/resolv.conf
	for dns in $resolvers
	do
		echo nameserver $dns >> /etc/resolv.conf
	done
	/etc/init.d/dnsmasq disable

	config_load network
	config_foreach del_interface interface

	uci set network.loopback=interface
	uci set network.loopback.ifname=lo
	uci set network.loopback.proto=static
	uci set network.loopback.ipaddr="127.0.0.1"
	uci set network.loopback.netmask="255.0.0.0"
	uci set network.loopback.ip6addr="0::1/128"

	uci set batman-adv.bat0.fragmentation=0

	if [ $accept_clients -eq 1 ]
		then
			uci set network.clients=interface
			uci set network.clients.proto=static
			uci set network.clients.type=bridge
			uci add_list network.clients.ifname="bat0"
			#Assuming that we have eth0 onboard
			uci set network.clients.ip6addr=$mesh6Prefix$(mac6ize $(get_mac eth0))/64
			uci set network.clients.ip6gw=$ip6gw
			uci set network.clients.ipaddr=192.168.1.21
			uci set network.clients.netmask=255.255.255.0
		else
			uci set network.bat0=interface
			uci set network.bat0.proto=static
			uci set network.bat0.ifname="bat0"
			#Assuming that we have eth0 onboard
			uci set network.bat0.ip6addr=$mesh6Prefix$(mac6ize $(get_mac eth0))/64
			uci set network.bat0.ip6gw=$ip6gw
			uci set network.bat0.ipaddr=192.168.1.21
			uci set network.bat0.netmask=255.255.255.0
	fi

	for device in $(scan_devices)
	do
		devtype=$(echo $device | sed -e 's/[0-9]*$//')
		devindex=$(echo $device | sed -e 's/.*\([0-9]\)/\1/')

		case $devtype in
			"eth")
				if [ $accept_clients -eq 1 ] && [ $eth_clients -eq 1 ]
				then
				{
					uci add_list network.clients.ifname=$device
				} && [ $eth_mesh -eq 1 ] &&
				{
					uci add_list batman-adv.bat0.interfaces="clients"
				}
				else
				{
					uci set network.$device=interface
					uci set network.$device.ifname=$device
					uci set network.$device.proto=static
					uci set network.$device.ip6addr=eeab:$((10 + $devindex))::1/64
					uci set network.$device.ipaddr=192.168.$((10 + $devindex)).21
					uci set network.$device.netmask=255.255.255.0
				} && [ $eth_mesh -eq 1 ] &&
				{
					uci add_list batman-adv.bat0.interfaces="$device"
				}
				fi
			;;

			"wifi")
				uci set wireless.$device=wifi-device
				uci set wireless.$device.type=atheros
				uci set wireless.$device.channel=$mesh2channel
				uci set wireless.$device.disabled=0
				uci set wireless.$device.country=$countrycode

				[ $madwifi_mesh -eq 1 ] &&
				{
					uci set wireless.mesh$device=wifi-iface
					uci set wireless.mesh$device.device=$device
					uci set wireless.mesh$device.network=nmesh$device
					uci set wireless.mesh$device.sw_merge=1
					uci set wireless.mesh$device.mode=adhoc
					uci set wireless.mesh$device.bssid=$meshBSSID
					uci set wireless.mesh$device.ssid=$meshSSID
					uci set wireless.mesh$device.encryption=none
					uci set wireless.mesh$device.mcast_rate=$meshMcastRate

					uci set network.nmesh$device=interface
					uci set network.nmesh$device.proto=static
					uci set network.nmesh$device.mtu=1528
					uci set network.nmesh$device.ip6addr=eeab:$((20 + $devindex))::1/64
					uci set network.nmesh$device.ipaddr=192.168.$((20 + $devindex)).21
					uci set network.nmesh$device.netmask=255.255.255.0

					uci add_list batman-adv.bat0.interfaces="nmesh$device"
				}

				[ $accept_clients -eq 1 ] && [ $madwifi_clients -eq 1 ] &&
				{
					uci set wireless.ap$device=wifi-iface
					uci set wireless.ap$device.device=$device
					uci set wireless.ap$device.network=clients
					uci set wireless.ap$device.sw_merge=1
					uci set wireless.ap$device.mode=ap
					uci set wireless.ap$device.ssid=$apSSID
					[ ${#apKEY} -lt 8 ] &&
					{
						uci set wireless.ap$device.encryption=none
					} ||
					{
						uci set wireless.ap$device.encryption=psk
						uci set wireless.ap$device.key=$apKEY
					}
					uci set wireless.ap$device.maxassoc=$apMaxClients
				}
			;;

			"radio")
				uci set wireless.$device=wifi-device
				uci set wireless.$device.type=mac80211
				uci set wireless.$device.macaddr=$(get_mac $device)
				uci set wireless.$device.channel=$mesh2channel
				uci set wireless.$device.disabled=0
				uci set wireless.$device.country=$countrycode

				[ $ath9k_mesh -eq 1 ] &&
				{
					uci set wireless.mesh$device=wifi-iface
					uci set wireless.mesh$device.device=$device
					uci set wireless.mesh$device.network=nmesh$device
					uci set wireless.mesh$device.sw_merge=1
					uci set wireless.mesh$device.mode=adhoc
					uci set wireless.mesh$device.bssid=$meshBSSID
					uci set wireless.mesh$device.ssid=$meshSSID
					uci set wireless.mesh$device.encryption=none
					uci set wireless.mesh$device.mcast_rate=$meshMcastRate

					uci set network.nmesh$device=interface
					uci set network.nmesh$device.proto=static
					uci set network.nmesh$device.mtu=1528
					uci set network.nmesh$device.ip6addr=eeab:$((30 + $devindex))::1/64
					uci set network.nmesh$device.ipaddr=192.168.$((30 + $devindex)).21
					uci set network.nmesh$device.netmask=255.255.255.0

					uci add_list batman-adv.bat0.interfaces="nmesh$device"
				}

				[ $accept_clients -eq 1 ] && [ $ath9k_clients -eq 1 ] && 
				{
					uci set wireless.ap$device=wifi-iface
					uci set wireless.ap$device.device=$device
					uci set wireless.ap$device.network=clients
					uci set wireless.ap$device.sw_merge=1
					uci set wireless.ap$device.mode=ap
					uci set wireless.ap$device.ssid=$apSSID
					[ ${#apKEY} -lt 8 ] &&
					{
						uci set wireless.ap$device.encryption=none
					} ||
					{
						uci set wireless.ap$device.encryption=psk
						uci set wireless.ap$device.key=$apKEY
					}
					uci set wireless.ap$device.maxassoc=$apMaxClients
				}
			;;
		esac
	done
}

configureSNMP()
{
	local enabled               ; config_get_bool enabled           snmp        "enabled"
	local community             ; config_get      community         snmp        "community"
	local accept_clients        ; config_get_bool accept_clients    network     "accept_clients"
	local ath9k_clients         ; config_get_bool ath9k_clients     wireless    "wifi_clients"
	local ath9k_mesh            ; config_get_bool ath9k_mesh        wireless    "wifi_mesh"
	local madwifi_clients       ; config_get_bool madwifi_clients   wireless    "wifi_clients"
	local madwifi_mesh          ; config_get_bool madwifi_mesh      wireless    "wifi_mesh"
	local eth_mesh              ; config_get_bool eth_mesh          wired       "eth_mesh"
	local eth_clients           ; config_get_bool eth_clients       wired       "eth_clients"

	echo "#Automatically generated for eigenNet
config 'mini_snmpd' 'snmp'
	option enabled	0
" > $CONF_DIR/mini_snmpd

	[ $enabled -eq 1 ] &&
	{
		uci set mini_snmpd.snmp.enabled=1
		uci set mini_snmpd.snmp.community="$community"
		uci set mini_snmpd.snmp.ipv6=1

		if [ $accept_clients -eq 1 ] 
			then
				uci set mini_snmpd.snmp.interfaces="clients"
			else
				uci set mini_snmpd.snmp.interfaces="bat0"
		fi

		for device in $(scan_devices)
		do
			devtype=$(echo $device | sed -e 's/[0-9]*$//')
			devindex=$(echo $device | sed -e 's/.*\([0-9]\)/\1/')

			case $devtype in
				"eth")
					[ $eth_mesh -eq 1 ] && [ $eth_clients -eq 0 ] && uci add_list mini_snmpd.snmp.interfaces="$device"
				;;
				"wifi")
					[ $madwifi_mesh -eq 1 ] && uci add_list mini_snmpd.snmp.interfaces="nmesh$device"
				;;
				"radio")
					[ $ath9k_mesh -eq 1 ] && uci add_list mini_snmpd.snmp.interfaces="nmesh$device"
				;;
			esac
		done
	}
}

start()
{
	eigenDebug 0 "Starting"

	[ $bootmode -eq 0 ] &&
	{
		sleep 61s

		uci set eigennet.general.bootmode=1
		uci commit eigennet

		reboot

		return 0
	}

	[ $bootmode -eq 1 ] &&
	{
		sleep 10s

		local sshAuthorizedKeys	; config_get sshAuthorizedKeys		network		sshAuthorizedKeys
		echo "$sshAuthorizedKeys" > "/etc/dropbear/authorized_keys" 

		configureNetwork
		configureSNMP

		uci set eigennet.general.bootmode=2

		uci commit

		sleep 2s
		reboot

		return 0
	}

	[ $bootmode -ge 2 ] &&
	{
		sysctl -w net.ipv4.ip_forward=1
		sysctl -w net.ipv6.conf.all.forwarding=1
		sysctl -w net.ipv6.conf.all.autoconf=0

		local accept_clients        ; config_get_bool accept_clients         network     "accept_clients"
		local eth_mesh              ; config_get_bool eth_mesh               wired       "eth_mesh"
		local eth_clients           ; config_get_bool eth_clients            wired       "eth_clients"
		if [ $accept_clients -eq 1 ] && [ $eth_mesh -eq 1 ] && [ $eth_clients -eq 1 ]
			then
				ip link set dev br-clients up
				ip link set mtu 1378 dev br-clients
			else
				ip link set dev bat0 up
				ip link set mtu 1350 dev bat0
		fi

		return 0
	}
}

stop()
{
	eigenDebug 0 "Stopping"
}

restart()
{
	stop
	sleep 2s
	start
}
