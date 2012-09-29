#!/bin/sh /etc/rc.common

<<COPYRIGHT

Copyright (C) 2010-2012 Gioacchino Mazzurco <gmazzurco89@gmail.com>

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

START=95
STOP=10

CONF_DIR="/etc/config/"
PKG_NAME="eigennet"

config_load eigennet

config_get debugLevel general "debugLevel" 0

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
#[Doc] Check if given package is installed
#[Doc]
#[Doc] usage:
#[Doc] is_package_installed package_name
#[Doc]
#[Doc] example:
#[Doc] is_package_installed eigennet-autoconf
#[Doc]
is_package_installed()
{
	opkg status "$1" | grep Status | grep installed &> /dev/null
	return $?
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
#[Doc] Del given uci wifi-iface interface from wireless file 
#[Doc]
#[Doc] usage:
#[Doc] del_wifi_iface uci_wifi-iface
#[Doc]
#[Doc] example:
#[Doc] del_wifi_iface wifiap0
#[Doc]
del_wifi_iface()
{
	uci del wireless.$1
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
	local accept_clients        ; config_get_bool accept_clients    network     "accept_clients"   1

	local mesh6Prefix           ; config_get mesh6Prefix            network     "ip6prefix"        "2001:470:ca42:ee:ab:"
	local ip6addr               ; config_get ip6addr                network     "ip6addr"
	local ip6gw                 ; config_get ip6gw                  network     "ip6gw"

	local ipaddr                ; config_get ipaddr                 network     "ipaddr"           "192.168.1.21"
	local netmask               ; config_get netmask                network     "netmask"          "255.255.255.0"
	local gateway               ; config_get gateway                network     "gateway"

	local hostName              ; config_get hostName               network     "hostname"         "OpenWrt"
	local resolvers             ; config_get resolvers              network     "resolvers"

	local wifi_clients          ; config_get_bool wifi_clients      wireless    "wifi_clients"     0
	local wifi_mesh             ; config_get_bool wifi_mesh         wireless    "wifi_mesh"        1
	local ath9k_clients         ; config_get_bool ath9k_clients     wireless    "wifi_clients"     0
	local ath9k_mesh            ; config_get_bool ath9k_mesh        wireless    "wifi_mesh"        1
	local madwifi_clients       ; config_get_bool madwifi_clients   wireless    "wifi_clients"     0
	local madwifi_mesh          ; config_get_bool madwifi_mesh      wireless    "wifi_mesh"        1
	local countrycode           ; config_get countrycode            wireless    "countrycode"
	local mesh2channel          ; config_get mesh2channel           wireless    "wifi_channel"
	local meshSSID              ; config_get meshSSID               wireless    "meshSSID"         "www.ninux.org"
	local meshBSSID             ; config_get meshBSSID              wireless    "meshBSSID"        "02:aa:bb:cc:dd:ee"
	local meshMcastRate         ; config_get meshMcastRate          wireless    "meshMcastRate"
	local apSSID                ; config_get apSSID                 wireless    "apSSID"
	local apKEY                 ; config_get apKEY                  wireless    "apKEY"
	local apMaxClients          ; config_get apMaxClients           wireless    "apMaxClients"

	local eth_mesh              ; config_get_bool eth_mesh          wired       "eth_mesh"         1
	local eth_clients           ; config_get_bool eth_clients       wired       "eth_clients"      1

	uci set system.@system[0].hostname=$hostName

	/etc/init.d/firewall disable

	echo -e "$(cat /etc/sysctl.conf | grep -v net.ipv6.conf.all.autoconf) \n net.ipv6.conf.all.autoconf=0" > /etc/sysctl.conf

	echo "config 'mesh' 'bat0'" > $CONF_DIR/batman-adv

	rm -rf /etc/resolv.conf
	for dns in $resolvers
	do
		echo nameserver $dns >> /etc/resolv.conf
	done
	/etc/init.d/dnsmasq disable

	config_load wireless
	config_foreach del_wifi_iface wifi-iface

	config_load network
	config_foreach del_interface interface

	uci set network.loopback=interface
	uci set network.loopback.ifname=lo
	uci set network.loopback.proto=static
	uci set network.loopback.ipaddr="127.0.0.1"
	uci set network.loopback.netmask="255.0.0.0"
	uci set network.loopback.ip6addr="0::1/128"

	uci set batman-adv.bat0.fragmentation=1
	uci set batman-adv.bat0.gw_mode="client"

	if [ $accept_clients -eq 1 ]
		then
			uci set network.clients=interface
			uci set network.clients.proto=static
			uci set network.clients.type=bridge
			uci add_list network.clients.ifname="bat0"
			if [ "void$ip6addr" == "void" ]
				then
					#Assuming that we have eth0 onboard
					uci set network.clients.ip6addr=$mesh6Prefix$(mac6ize $(get_mac eth0))/64
				else
					uci set network.clients.ip6addr=$ip6addr
			fi
			uci set network.clients.ip6gw=$ip6gw
			uci set network.clients.ipaddr=$ipaddr
			uci set network.clients.netmask=$netmask
			uci set network.clients.gateway=$gateway
		else
			uci set network.bat0=interface
			uci set network.bat0.proto=static
			uci set network.bat0.ifname="bat0"
			if [ "void$ip6addr" == "void" ]
				then
					#Assuming that we have eth0 onboard
					uci set network.bat0.ip6addr=$mesh6Prefix$(mac6ize $(get_mac eth0))/64
				else
					uci set network.bat0.ip6addr=$ip6addr
			fi
			uci set network.bat0.ip6gw=$ip6gw
			uci set network.bat0.ipaddr=$ipaddr
			uci set network.bat0.netmask=$netmask
			uci set network.bat0.gateway=$gateway
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
					uci set network.$device.ip6addr=eeab:$(mac6ize $(get_mac $device))::1/64
					uci set network.$device.ipaddr=192.168.$((10 + $devindex)).21
					uci set network.$device.netmask=255.255.255.0
				} && [ $eth_mesh -eq 1 ] &&
				{
					uci add_list batman-adv.bat0.interfaces="$device"
				}
				fi
			;;

			"wifi")
				uci set wireless.$device.channel=$mesh2channel
				uci set wireless.$device.disabled=0
				uci set wireless.$device.txpower=30
#				uci set wireless.$device.country=$countrycode

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
					uci set network.nmesh$device.ip6addr=eeab:$(mac6ize $(get_mac $device))::1/64
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
				uci set wireless.$device.channel=$mesh2channel
				uci set wireless.$device.disabled=0
				uci set wireless.$device.txpower=30
#				uci set wireless.$device.country=$countrycode ## Seems newer hardware doest permit change country

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
					uci set network.nmesh$device.ip6addr=eeab:$(mac6ize $(get_mac $device))::1/64
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

configureFirewall()
{
	is_package_installed $PKG_NAME-firewall &&
	{
		local firewallEnabled       ; config_get_bool firewallEnabled   firewall     "enabled"         0
		local disabledModDir="/etc/eigennet/firewall-disabled-modules.d/"
		local enabledModDir="/etc/modules.d/"
		local ebtablesModulesExp="*ebtables*"

		if [ ${firewallEnabled} -eq 0 ] 
			then
				[ -d "${disabledModDir}" ] || mkdir -p "${disabledModDir}"
				cd "${enabledModDir}"
				ls ${ebtablesModulesExp} &> /dev/null && mv ${ebtablesModulesExp} "${disabledModDir}"
			else
				[ -d "${disabledModDir}" ] || mkdir -p "${disabledModDir}"
				cd "${disabledModDir}"
				ls ${ebtablesModulesExp} &> /dev/null && mv ${ebtablesModulesExp} "${enabledModDir}"
		fi
	}
}

configureUhttpd()
{
	is_package_installed uhttpd &&
	{
		local pointingEnabled           ; config_get_bool pointingEnabled       pointing         "enabled"                0
		local bwClientEnabled           ; config_get_bool bwClientEnabled       bwtestclient     "enabled"                0
		local httpInfoEnabled           ; config_get_bool httpInfoEnabled       httpinfo         "enabled"                0

		if [ $pointingEnabled -eq 0 ] && [ $bwClientEnabled -eq 0 ] && [ $httpInfoEnabled -eq 0 ]
			then
				/etc/init.d/uhttpd disable &> /dev/null || true
			else
				/etc/init.d/uhttpd enable
				uci set      uhttpd.main.listen_http="0.0.0.0:80"
				uci add_list uhttpd.main.listen_http="[::]:80"
		fi
	}
}

configureHttpInfo()
{
	is_package_installed $PKG_NAME-httpinfo &&
	{
		local httpInfoEnabled           ; config_get_bool httpInfoEnabled       httpinfo         "enabled"                0
		if [ $httpInfoEnabled eq 1 ]
			then
				chmod 777 /www/cgi-bin/getdBm.cgi
				chmod 777 /www/cgi-bin/ifstat.cgi
			else
				chmod 750 /www/cgi-bin/getdBm.cgi
				chmod 750 /www/cgi-bin/ifstat.cgi
		fi
	}
}

configurePointing()
{
	is_package_installed $PKG_NAME-pointing-webui &&
	{
		local pointingEnabled           ; config_get_bool pointingEnabled       pointing         "enabled"                0

		[ $pointingEnabled -eq 1 ] && chmod 777 /www/cgi-bin/pointing.cgi
		[ $pointingEnabled -eq 0 ] && chmod 750 /www/cgi-bin/pointing.cgi
	}
}

configureBWTestClient()
{
	is_package_installed $PKG_NAME-bwtest-webui &&
	{
		local bwClientEnabled           ; config_get_bool bwClientEnabled       bwtestclient     "enabled"                0

		[ $bwClientEnabled -eq 1 ] && chmod 777 /www/cgi-bin/bwtclient.cgi && chmod 777 /www/cgi-bin/startbwt.cgi
		[ $bwClientEnabled -eq 0 ] && chmod 750 /www/cgi-bin/bwtclient.cgi && chmod 750 /www/cgi-bin/startbwt.cgi
	}
}

configureDropbear()
{
	local sshEnabled                ; config_get_bool sshEnabled            sshserver         "enabled"               1
	local passwdAuth                ; config_get_bool passwdAuth            sshserver         "passwdAuth"            0
	local sshAuthorizedKeys         ; config_get      sshAuthorizedKeys     sshserver         "sshAuthorizedKeys"

	if [ $sshEnabled -eq 1 ]
		then
			/etc/init.d/dropbear enable
			echo "$sshAuthorizedKeys" > "/etc/dropbear/authorized_keys" 
			uci set dropbear.@dropbear[0].PasswordAuth=$passwdAuth
			uci set dropbear.@dropbear[0].RootPasswordAuth=$passwdAuth
		else
			/etc/init.d/dropbear disable
	fi
}

start()
{
	eigenDebug 0 "Starting"

	config_get bootmode general "bootmode" 1

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

		configureBWTestClient
		configureUhttpd
		configurePointing
		configureDropbear
		configureNetwork
		configureFirewall

		uci set eigennet.general.bootmode=2

		uci commit

		sleep 2s
		reboot

		return 0
	}

	[ $bootmode -ge 2 ] &&
	{
		sysctl -w net.ipv6.conf.all.autoconf=0

		local accept_clients
		config_get_bool accept_clients network "accept_clients"  1
		[ $accept_clients -eq 1 ] && ip link set dev br-clients up

		ip link set dev bat0 up

		batman-adv restart #added as workaround of batman-adv eth hotplug bug

		is_package_installed $PKG_NAME-firewall &&
		{
			local isolateDHCP     ; config_get_bool isolateDHCP       firewall     "isolateDHCP"      0
			local firewallEnabled ; config_get_bool firewallEnabled   firewall     "enabled"          0
			local accept_clients  ; config_get_bool accept_clients    network      "accept_clients"   1
			local eth_clients     ; config_get_bool eth_clients       wired        "eth_clients"      1
			local wifi_clients    ; config_get_bool wifi_clients      wireless     "wifi_clients"     0
			[ ${isolateDHCP} -eq 1 ] && [ ${firewallEnabled} -eq 1 ] &&
			[ ${accept_clients} ] && $( [ ${eth_clients} -eq 1 ] || [ ${wifi_clients} -eq 1 ] ) &&
			{
				ebtables -A FORWARD --out-if bat0 --protocol IPv4 --ip-protocol udp --ip-source-port 68 -j DROP
				ebtables -A FORWARD --in-if  bat0 --protocol IPv4 --ip-protocol udp --ip-source-port 67 -j DROP
			}
		}

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
