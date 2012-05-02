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

START=96
STOP=9

CONF_DIR="/etc/config/"

pidFile="/var/run/gw4check.pid"

plainIfName()
{
	interface=$1
	[ "$(uci -q -P/var/state get network.${interface})" == "interface" ] && [ "$(uci -q -P/var/state get network.${interface}.type)" == "bridge" ] && echo br-${interface} && return 0
	[ "$(uci -q -P/var/state get network.${interface})" == "interface" ] && echo $(uci -q -P/var/state get network.${interface}.ifname) && return 0
	[ -e "/sys/class/net/${interface}" ] && echo ${interface} && return 0
	echo lo
	return 1
}

start()
{
	[ -f ${pidFile} ] ||
	{
		config_load eigennet
		config_get_bool  gw4Enabled      gw4check "enabled"  0
		config_get       bootmode        general  "bootmode" 1

		[ $gw4Enabled -eq 1 ] && [ $bootmode -ge 2 ] &&
		{
			config_get       interface       gw4check "interface"      "clients"
			config_get       ipaddr          gw4check "ipaddr"         "192.168.1.2/24"
			config_get       gateway         gw4check "gateway"        "192.168.1.1"
			config_get_bool  strictCheck     gw4check "strictCheck"    0
			config_get       checkInterval   gw4check "checkInterval"  "10s"
			config_get       checkHosts      gw4check "checkHosts"     "8.8.8.8 8.8.4.4"
			config_get       bandwidth       gw4check "bandwidth"      "5000/512"

			ifname=$(plainIfName ${interface})
			ip address add ${ipaddr} dev ${ifname} || true
			ip route add default via ${gateway}    || true

			while sleep $checkInterval
			do
				i=0
				failure=0
				for host in $checkHosts
				do
					ping -4 -c 5 -q $host &> /dev/null
					failure=$((failure+$?))
					i=$((i+1))
				done
				
				[ $strictCheck -eq 1 ] && [ $failure -gt 0  ] && batctl gw_mode client && continue
				[ $failure -ge $i ]    &&                        batctl gw_mode client && continue

				batctl gw_mode server $bandwidth
			done &

			echo $! > ${pidFile}
		}
	}
}

stop()
{
	[ -f ${pidFile} ] && 
	{
		kill $(cat ${pidFile})
		rm ${pidFile}
		batctl gw_mode client
		config_load eigennet
		config_get       interface       gw4check "interface"      "clients"
		config_get       ipaddr          gw4check "ipaddr"         "192.168.1.2/24"
		config_get       gateway         gw4check "gateway"        "192.168.1.1"
		ifname=$(plainIfName ${interface})
		ip route del default via ${gateway}    || true
		ip address del ${ipaddr} dev ${ifname} || true
	}
}