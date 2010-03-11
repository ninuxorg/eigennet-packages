#!/bin/bash /etc/rc.common

<<COPYRIGHT

Copyright (C) 2010  Gioacchino Mazzurco <gmazzurco89@gmail.com>

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

CONF_DIR="/etc/config/"
ipV6Subnet="fd7d:d7bb:2c97:dec3"

supportedHardwareCount=2

wiredDevice[0]="eth0"
wirelessDevice[0]="ath0"
wirelessDeviceTxPower[0]="" # Radio Trasmit Power in dBi # not used at moment
# 0 (Default) auto # 15 54Mb/s # 16 48Mb/2 # 18 36Mb/s #  20 24Mb/s ( for bullet )

function getIp6HWAddress()
{
  #Get device name as param

  iMAC=`ifconfig $1 | grep -m 1 HWaddr | awk -F 'HWaddr ' '{ print $2 }'`
  if [ ${#iMAC} -gt "17" ]
  then
    iMAC=${iMAC:0:17}
  fi
  echo "$ipV6Subnet:0000:${iMAC:0:2}${iMAC:3:2}:${iMAC:6:2}${iMAC:9:2}:${iMAC:12:2}${iMAC:15:2}"
}

function configureNetwork()
{
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding

  NETWORK_CONF="
config 'interface' 'loopback'
	option 'ifname' 'lo'
	option 'proto' 'static'
	option 'ipaddr' '127.0.0.1'
	option 'netmask' '255.0.0.0'

config 'interface' 'lan'
	option 'ifname' '${wiredDevice[0]}'
	option 'proto' 'static'
	option 'netmask' '255.255.255.0'
	option 'dns' ''
	option 'gateway' ''
	option 'ipaddr' '192.168.1.30'
	option 'ip6addr' '`getIp6HWAddress ${wiredDevice[0]}`'


config 'interface' 'wifi0'
	option 'ifname' '${wirelessDevice[0]}'
	option 'ipaddr' '192.168.10.19'
	option 'netmask' '255.255.255.0'  
	option 'proto' 'static'
	option 'ip6addr' '`getIp6HWAddress ${wirelessDevice[0]}`'

"
  echo "$NETWORK_CONF" > "$CONF_DIR/network"
}

function configureWireless()
{
  WIRELESS_CONF="
config 'wifi-device' 'wifi0'
	option 'type' 'atheros'
	option 'channel' 'auto'
	option 'disabled' '0'
#	option 'txpower' '${wirelessDeviceTxPower[0]}'

config 'wifi-iface'
	option 'device' 'wifi0'
	option 'network' 'wifi0'
	option 'sw_merge' '1'
	option 'mode' 'adhoc'
	option 'ssid' 'eigennet'
	option 'encryption' 'none'

"

  echo "$WIRELESS_CONF" > "$CONF_DIR/wireless"
}

function configureFirewall()
{
  FIREWALL_CONF="

"
  echo "$FIREWALL_CONF" > "$CONF_DIR/firewall"
}

function configureOlsrd()
{
  OLSRD_CONF="
config olsrd
  option config_file '/etc/olsrd.conf'

"
  OLSRD_ETC="

DebugLevel	1

IpVersion	6

Hna4
{
# Internet gateway
#    0.0.0.0   0.0.0.0

# specific small networks reachable through this node
#    15.15.0.0 255.255.255.0
#    15.16.0.0 255.255.255.0
}

# HNA IPv6 routes
# syntax: netaddr prefix
# Example Internet gateway:
#Hna6
#{
# Internet gateway
#     ::              0

# specific small networks reachable through this node
#    fec0:2200:106:0:0:0:0:0 48
#}


#fore some cause ( i like to understand this) olsrd want real device fro wireless but virtual interface for lan...
Interface \"${wirelessDevice[0]}\"
{
#    Mode \"mesh\"
#    IPv6Multicast	FF0E::1
}

Interface \"br-lan\"
{
#    Mode \"ether\"
#    IPv6Multicast	FF0E::1
}

"
  echo "$OLSRD_CONF" > "$CONF_DIR/olsrd"
  echo "$OLSRD_ETC" > "/etc/olsrd.conf"
}


function start()
{
  $0 disable

  if[ -e "/etc/isNotFirstRun"] && [ `cat "/etc/isNotFirstRun"` = "1" ]
  then
      exit 0
  fi

  configureNetwork
  configureWireless
  configureFirewall
  configureOlsrd
  echo "1" > "/etc/isNotFirstRun"

  reboot
}

function stop()
{
  exit 0
}

