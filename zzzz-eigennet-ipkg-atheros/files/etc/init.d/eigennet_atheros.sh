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

typicalWirelessDeviceName="wifiX" #where X is a number
typicalWirelessDeviceNameCharN=4 #Number of char before X number
typicalWiredDeviceName="ethX" #where X is a number
typicalWiredDeviceNameCharN=3 #Number of char before X number

CONF_DIR="/etc/config/"
meshIpV6Subnet="fd7d:d7bb:2c97:dec3"
meshDns="$meshIpV6Subnet:0000:0023:7d29:13fa"
OLSRHnaIpV6Prefix="fd7d:d7bb:2c97" #this should be combined with macaddress to have only xxxx:xxxx 32bit 2^32 addres range, should appear like this: fd7d:d7bb:2c97:xxxx:xxxx:xxxx:yyyy:yyyy where xxxx:xxxx:xxxx is device mac address and yyyy:yyyy is the ip given by dhcp to the client
OLSRMulticast="FF0E::1" #this should be moved to FF02:1 when all node will have olsrd 0.5.6-r8 or later ( for example nokia n810 )


networkWirelessDevice[0]=""
networkWirelessDevHWAddr[0]=""
networkWirelessDevHWAddr6[0]=""
networkWiredDevice[0]=""
networkWiredDevHWAddr[0]=""
networkWiredDevHWAddr6[0]=""

WIRELESS_CONF="
#Automatically generated for Eigennet
"
  OLSRD_CONF="
#Automatically generated for Eigennet
config olsrd
  option config_file '/etc/olsrd.conf'

"
  OLSRD_ETC="
#Automatically generated for Eigennet

DebugLevel	1

IpVersion	6

"

  OLSRHna6="
Hna6
{

"
  OLSRInterfaces=""

  NETWORK_CONF="
#Automatically generated for Eigennet

config interface loopback
        option ifname lo
        option proto static

"
DIBBLER_SERVER_CONF="
#Automatically generated for Eigennet

log-level 8
log-mode short
preference 0

"

function loadDevicesInfo()
{
  for device in `ifconfig -a | grep ^[a-z] | grep -v "lo        Link encap:Local Loopback" | awk '{ print $1 }'`
  do
    if [ ${device:0:$typicalWirelessDeviceNameCharN} == ${typicalWirelessDeviceName:0:$typicalWirelessDeviceNameCharN} ]
    then
      networkWirelessDevice[${#networkWirelessDevice[@]}]="$device"
      mac="`ifconfig $device | grep HWaddr | awk -F 'HWaddr ' '{ print $2 }'`"
      networkWirelessDevHWAddr[${#networkWirelessDevHWAddr[@]}]="$mac"
      networkWirelessDevHWAddr6[${#networkWirelessDevHWAddr6[@]}]="${mac:0:2}${mac:3:2}:${mac:6:2}${mac:9:2}:${mac:12:2}${mac:15:2}"
    else
      if [ ${device:0:$typicalWiredDeviceNameCharN} == ${typicalWiredDeviceName:0:$typicalWiredDeviceNameCharN} ]
      then
	networkWiredDevice[${#networkWiredDevice[@]}]=$device
	mac=`ifconfig $device | grep HWaddr | awk -F 'HWaddr ' '{ print $2 }'`
	networkWiredDevHWAddr[${#networkWiredDevHWAddr[@]}]=$mac
	networkWiredDevHWAddr6[${#networkWiredDevHWAddr6[@]}]="${mac:0:2}${mac:3:2}:${mac:6:2}${mac:9:2}:${mac:12:2}${mac:15:2}"
      fi
    fi
  done
}

function configureNetwork()
{
  echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
  echo 0 > /proc/sys/net/ipv6/conf/all/autoconf
 
  local indx=1
  local indi=0
#Generate configuration for wireless interface
  while [ "${networkWirelessDevice[$indx]}" != "" ]
  do
    NETWORK_CONF="$NETWORK_CONF

config interface wifimesh$indi
        option ifname     ath$(($indi*2 + 1))
        option proto      static
        option ip6addr    '$meshIpV6Subnet:0000:${networkWirelessDevHWAddr6[$indx]}'
        option dns        '$meshDns'

config interface wifiap$indi
        option ifname     ath$(($indi*2))
        option proto      static
        option ip6addr    '$OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0001/96'
        option gateway    '$meshIpV6Subnet:0000:${networkWirelessDevHWAddr6[$indx]}'

"

    OLSRHna6="$OLSRHna6

  $OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0000 96
"

	  WIRELESS_CONF="
config 'wifi-device'         '${networkWirelessDevice[$indx]}'
        option 'type'        'atheros'
        option 'channel'     '5'
        option 'disabled'    '0'

config 'wifi-iface'
        option 'device'      '${networkWirelessDevice[$indx]}'
        option 'network'     'wifimesh$indi'
        option 'sw_merge'    '1'
        option 'mode'        'adhoc'
        option 'ssid'        'eigennet'
        option 'encryption'  'none'

config 'wifi-iface'
        option 'device'      '${networkWirelessDevice[$indx]}'
        option 'network'     'wifiap$indi'
        option 'sw_merge'    '1'
        option 'mode'        'ap'
        option 'ssid'        'eigennetAP'
        option 'encryption'  'none'
"

	  OLSRInterfaces="$OLSRInterfaces
Interface \"ath$(($indi*2 + 1))\"
{
    Mode \"mesh\"
    IPv6Multicast	$OLSRMulticast
}
"

 DIBBLER_SERVER_CONF="$DIBBLER_SERVER_CONF
iface \"ath$(($indi*2))\"
{
        prefered-lifetime 3600
        valid-lifetime 7200
        class
        {
                pool $OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0002/96
        }
        option dns-server $OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0001
}

"

    ((indx++))
    ((indi++))
  done

#Generate configuration for wired interface
  indx=1
  indi=0
  while [ "${networkWiredDevice[$indx]}" != "" ]
  do
    NETWORK_CONF="$NETWORK_CONF
config interface lan$indi
        option ifname     ${networkWiredDevice[$indx]}
        option proto      static
        option ip6addr    '$OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0001/96'
	option gateway    '$meshIpV6Subnet:0000:${networkWiredDevHWAddr6[$indx]}'

config alias                                                           
        option interface lan$indi                                          
        option proto      static                                         
        option ip6addr    '$meshIpV6Subnet:0000:${networkWiredDevHWAddr6[$indx]}'
	option dns        '$meshDns'

"
	
    OLSRInterfaces="$OLSRInterfaces

Interface \"${networkWiredDevice[$indx]}\"
{
    Mode \"ether\"
    IPv6Multicast	$OLSRMulticast
}
"

    OLSRHna6="$OLSRHna6

  $OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0000 96
"

  DIBBLER_SERVER_CONF="$DIBBLER_SERVER_CONF
iface \"eth$indi\"
{
        prefered-lifetime 3600
        valid-lifetime 7200
        class
        {
                pool $OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0002/96
        }
        option dns-server $OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0001
}

"
  

    ((indx++))
    ((indi++))
  done

  OLSRHna6="$OLSRHna6
}
"

  OLSRD_ETC="$OLSRD_ETC$OLSRHna6$OLSRInterfaces"

  #cp "$CONF_DIR/network" "$CONF_DIR/network.back"
  #cp "$CONF_DIR/wireless" "$CONF_DIR/wireless.back"
  #cp "$CONF_DIR/olsrd" "$CONF_DIR/olsrd.back"
  #cp "/etc/olsrd.conf" "/etc/olsrd.conf.back"

  #echo "$NETWORK_CONF" > "$CONF_DIR/network.test"
  #echo "$WIRELESS_CONF" > "$CONF_DIR/wireless.test"
  #echo "$OLSRD_CONF" > "$CONF_DIR/olsrd.test"
  #echo "$OLSRD_ETC" > "/etc/olsrd.conf.test"

  echo "$NETWORK_CONF" > "$CONF_DIR/network"
  echo "$WIRELESS_CONF" > "$CONF_DIR/wireless"
  echo "$OLSRD_CONF" > "$CONF_DIR/olsrd"
  echo "$OLSRD_ETC" > "/etc/olsrd.conf"
  echo "$DIBBLER_SERVER_CONF" > "/etc/dibbler/server.conf"
}

function start()
{

  if [ -e "/etc/isNotFirstRun" ] && [ `cat "/etc/isNotFirstRun"` == "1" ]
  then
      mkdir /var/lib
      mkdir /var/lib/dibbler
      dibbler-server start
      exit 0
  fi

  sleep 10

  echo "1" > "/etc/isNotFirstRun"

  loadDevicesInfo
  configureNetwork

  sleep 2

  reboot
}

function stop()
{
  killall dibbler-server
  exit 0
}
