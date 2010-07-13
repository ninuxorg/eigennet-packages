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
STOP=10

eigenDebugEnabled=false

typicalWirelessDeviceName="wifiX" #Where X is a number
typicalWirelessDeviceNameCharN=4 #Number of char before X number
typicalWiredDeviceName="ethX" #Where X is a number
typicalWiredDeviceNameCharN=3 #Number of char before X number

CONF_DIR="/etc/config/"
meshIpV6Subnet="fd7d:d7bb:2c97:dec3"
meshDns="$meshIpV6Subnet:0000:0023:7d29:13fa"
OLSRHnaIpV6Prefix="fec0" #This should be one of: fec0, fed0, fee0 or fef0, that are site-local ipv6 prefix
OLSRMulticast="FF0E::1" #Newer version of olsrd use FF02:1 as default but we use this because is more "aggressive"(then our olsrd packets are also broadcasted inside SERRA)

ipv4Dns="10.0.0.1"
usedSubnetsFile="/tmp/usedSubnets"
olsrdDynConfFile="/tmp/olsr.conf"
olsrdStaticConfFile="/etc/olsrd.conf"
dynHna6=""

networkWirelessDevice[0]=""
networkWirelessDevHWAddr[0]=""
networkWirelessDevHWAddr6[0]=""
networkWirelessCidr="27"
networkWirelessIpv4BigSubnet="10.174.0.0/16"
networkWiredDevice[0]=""
networkWiredDevHWAddr[0]=""
networkWiredDevHWAddr6[0]=""
networkWiredCidr="29"
networkWiredIpv4BigSubnet="10.174.0.0/16"

function eigenDebug()
{
  if $eigenDebugEnabled
  then
    echo "Debug: $1"
  fi
}

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

function configureDynOlsrd()
{
  Hna6BeginLine=`grep -ni "Hna6" "$olsrdStaticConfFile" | awk -F: '{print $1}'`
  ((Hna6BeginLine++))
  echo "`head -$Hna6BeginLine "$olsrdStaticConfFile"`" > "$olsrdDynConfFile"
  echo "$dynHna6" >> "$olsrdDynConfFile"
  ((Hna6BeginLine++))
  reverseHna6BeginLine=$((`wc -l "$olsrdStaticConfFile" | awk '{print $1}'`-$Hna6BeginLine))
  echo "`tail -$reverseHna6BeginLine "$olsrdStaticConfFile"`" >> "$olsrdDynConfFile"

  killall -SIGUSR1 olsrd
  sleep 10s #We need that olsrd load the dynamic hna entry in his topology before look for another free subnet ( this can be increased if necessary)
}

function configureNetwork()
{
  WIRELESS_CONF="
#Automatically generated for Eigennet
"

  OLSRD_ETC="
#Automatically generated for Eigennet

DebugLevel	1

IpVersion	6

LoadPlugin \"olsrd_txtinfo.so.0.1\"
{
  PlParam     \"Accept\"   \"0::0\"
}

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

  DHCP_CONF="
#Automatically generated for Eigennet

"

  RESOLV_CONF_AUTO="
nameserver $meshDns
nameserver $ipv4Dns
"

  DIBBLER_SERVER_CONF="
#Automatically generated for Eigennet

log-level 8
log-mode short
preference 5
stateless

"
  RADVD_CONF="
#Automatically generated for Eigennet

"
  SYSCTL_CONF="
#Automatically generated for Eigennet

`cat /etc/sysctl.conf | grep -v net.ipv4.ip_forward | grep -v net.ipv6.conf.all.forwarding | grep -v net.ipv6.conf.all.autoconf`

net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.autoconf=0
"

  local indx=1
  local indi=0
#Generate configuration for wireless interface
  while [ "${networkWirelessDevice[$indx]}" != "" ]
  do
    NETWORK_CONF="$NETWORK_CONF

config interface wifimesh$indi
        option ifname     ath$(($indi*2 + 1))
        option proto      static
        option ip6addr    '$meshIpV6Subnet:0000:${networkWirelessDevHWAddr6[$indx]}/64'

config interface wifiap$indi
        option ifname     ath$(($indi*2))
        option proto      static
        option ip6addr    '$OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0000:0000:0001/64'

#Mobile#config interface wifiMobile$indi
#Mobile#	option ifname	ath$(($indi*2)) # check this index
#Mobile#	option proto	static
#Mobile#	option ipaddr	'192.168.174.1'
#Mobile#	option netmask	'255.255.255.0'

"

    OLSRHna6="$OLSRHna6

  $OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0000:0000:0000 64
"

    WIRELESS_CONF="$WIRELESS_CONF
config 'wifi-device'         '${networkWirelessDevice[$indx]}'
        option 'type'        'atheros'
        option 'channel'     '5'
        option 'disabled'    '0'

config 'wifi-iface'
        option 'device'      '${networkWirelessDevice[$indx]}'
        option 'network'     'wifimesh$indi'
        option 'sw_merge'    '1'
        option 'mode'        'adhoc'
        option 'ssid'        'Ninux.org'
        option 'encryption'  'none'

config 'wifi-iface'
        option 'device'      '${networkWirelessDevice[$indx]}'
        option 'network'     'wifiap$indi'
        option 'sw_merge'    '1'
        option 'mode'        'ap'
        option 'ssid'        'EigenNet'
        option 'encryption'  'none'

#Mobile#config 'wifi-iface'
#Mobile#        option 'device'      '${networkWirelessDevice[$indx]}'
#Mobile#        option 'network'     'wifiMobile$indi'
#Mobile#        option 'sw_merge'    '1'
#Mobile#        option 'mode'        'ap'
#Mobile#        option 'ssid'        'EigenNet_Mobile'
#Mobile#        option 'encryption'  'none'
"

    OLSRInterfaces="$OLSRInterfaces
Interface \"ath$(($indi*2 + 1))\"
{
    Mode \"mesh\"
    IPv6Multicast	$OLSRMulticast
    IPv6Src		$meshIpV6Subnet:0000:${networkWirelessDevHWAddr6[$indx]}
}
"

    DIBBLER_SERVER_CONF="$DIBBLER_SERVER_CONF
iface \"ath$(($indi*2))\"
{
        option dns-server $OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0000:0000:0001
}

"

    RADVD_CONF="$RADVD_CONF
interface ath$(($indi*2))
{
  AdvSendAdvert on;
  prefix $OLSRHnaIpV6Prefix:${networkWirelessDevHWAddr6[$indx]}:0000:0000:0000:0001/64
  {
    AdvOnLink on;
    AdvAutonomous on;
  };
};

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
	option ip6addr    '$OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0000:0000:0001/64'

config alias                                                           
	option interface lan$indi
	option proto      static
	option ip6addr    '$meshIpV6Subnet:0000:${networkWiredDevHWAddr6[$indx]}/64'

"

    OLSRInterfaces="$OLSRInterfaces

Interface \"${networkWiredDevice[$indx]}\"
{
    Mode \"ether\"
    IPv6Multicast	$OLSRMulticast
    IPv6Src		$meshIpV6Subnet:0000:${networkWiredDevHWAddr6[$indx]}
}
"


    OLSRHna6="$OLSRHna6

  $OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0000:0000:0000 64
"

    DIBBLER_SERVER_CONF="$DIBBLER_SERVER_CONF
iface \"eth$indi\"
{
        option dns-server $OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0000:0000:0001
}

"

    RADVD_CONF="$RADVD_CONF
interface ${networkWiredDevice[$indx]}
{
  AdvSendAdvert on;
  prefix $OLSRHnaIpV6Prefix:${networkWiredDevHWAddr6[$indx]}:0000:0000:0000:0001/64	 
  {
    AdvOnLink on;
    AdvAutonomous on;
  };
};

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
  #cp "$CONF_DIR/dhcp" "$CONF_DIR/dhcp.back"
  #cp "$olsrdStaticConfFile" "$olsrdStaticConfFile.back"

  #echo "$NETWORK_CONF" > "$CONF_DIR/network.test"
  #echo "$WIRELESS_CONF" > "$CONF_DIR/wireless.test"
  #echo "$DHCP_CONF" > "$CONF_DIR/dhcp.test"
  #echo "$OLSRD_ETC" > "$olsrdStaticConfFile.test"

  echo "$SYSCTL_CONF" > "/etc/sysctl.conf"
  echo "$NETWORK_CONF" > "$CONF_DIR/network"
  echo "$WIRELESS_CONF" > "$CONF_DIR/wireless"
  echo "$DHCP_CONF" > "$CONF_DIR/dhcp"
  echo "$OLSRD_ETC" > "$olsrdStaticConfFile"
  mkdir -p /etc/dibbler
  echo "$DIBBLER_SERVER_CONF" > "/etc/dibbler/server.conf"
  echo "$RADVD_CONF" > "/etc/radvd.conf"
  echo "$RESOLV_CONF_AUTO" > "/etc/resolv.conf.auto"
  echo "nameserver 127.0.0.1" > "/etc/resolv.conf"
}

function ipDotted2Int() # $1 = dotted ip
{  
  echo "`echo "$1" | awk -F\. '{print ($4)+($3*256)+($2*256*256)+($1*256*256*256)}'`"
}

function ipDotted2Colon() # $1 = dotted ip
{
  printf "%02X%02X:%02X%02X\n", `echo "$1" | awk -F\. '{print ($1)}'` `echo "$1" | awk -F\. '{print ($2)}'` `echo "$1" | awk -F\. '{print ($3)}'` `echo "$1" | awk -F\. '{print ($4)}'`
}

function ipInt2Dotted() # $1 = int 32 ip
{
  local intIp="$1"
  local dottedIp=""
  local dottedIp="$[($intIp&255<<(0*8))>>(0*8)]"
  local dottedIp="$[($intIp&255<<(1*8))>>(1*8)].$dottedIp"
  local dottedIp="$[($intIp&255<<(2*8))>>(2*8)].$dottedIp"
  local dottedIp="$[($intIp&255<<(3*8))>>(3*8)].$dottedIp"

  echo "$dottedIp"
}

function cidr2Int() # $1 = cidr  looking to a subnet you see for example 192.168.0.1/$1
{
  echo "$((2**(32-$1)))"
}

function int2cidrU() # $1 = number of needed ip (this function round up to an integer for example `int2cidr 250`=24)
{
  echo $((32 - `echo "$1" | awk '{printf "%d",(log($1)/log(2) == int(log($1)/log(2))) ? log($1)/log(2) : int(log($1)/log(2))+1}'`))
}

function int2cidrD() # $1 = number of needed ip (this function round down to an integer for example `int2cidr 250`=23)
{
  echo $((32 - `echo "$1" | awk '{printf "%d", int(log($1)/log(2))}'`))
}

function loadUsedSubnets()
{
  wget -q http://[0::1]:2006 -O - | grep ::ffff: | awk -F ::ffff: '{ print $2 }' | awk '{print $1}'| grep -v : | grep -v '^$' | sort -u -n -t . -k 1,1 -k 2,2 -k 3,3 -k 4,4 > "$usedSubnetsFile"

  #echo "`cat /home/gioacchino/Desktop/sortedsubnet.txt`" > "$usedSubnetsFile"
  #fd7d:d7bb:2c97:dec3:0:15:6dd5:f7d1
}

function unLoadUsedSubnets()
{
    rm -f "$usedSubnetsFile"
}

function getFreeSubnet() # $1 = big subnet where to look for free ip space $2 = Mask bit for example if you need x.y.z.0/24 $1 will be $1 = 24
{
  local ipv4BigSubnet=$1
  local intBigSubnetStartIp=`ipDotted2Int "${ipv4BigSubnet%/*}"`
  local intBigSubnetEndIp=$(($intBigSubnetStartIp+`cidr2Int "${ipv4BigSubnet#*/}"`))

  local intTestIfFreeStartIp=$intBigSubnetStartIp
  local intTestIfFreeEndIp=$intBigSubnetEndIp

  local row=1
  loadUsedSubnets
  local len="`wc -l "$usedSubnetsFile" | awk '{print $1}'`"

  while [ $row -le $len ];
  do
    local dotUsedIp="`head -$row "$usedSubnetsFile" | tail -1`" #Get one used subnet
    local usedCidr=$((${dotUsedIp#*/}-96))	# get cidr -96 is because in the file we have the subnets as ipv4 mapped -> ipv6
    local dotUsedIp=${dotUsedIp%/*}	# get dotted ip

    eigenDebug "reading $dotUsedIp/$usedCidr"

    local intStartUsedIp=`ipDotted2Int "$dotUsedIp"`
    local intEndUsedIp=$((`ipDotted2Int "$dotUsedIp"`+`cidr2Int $usedCidr`))

    if [ $intStartUsedIp -ge $intBigSubnetStartIp ] && [ $intEndUsedIp -le $intBigSubnetEndIp ]
    then
      eigenDebug "Used subnet $dotUsedIp/$usedCidr found inside BigSubnet"

      if [ $intTestIfFreeStartIp -ge $intStartUsedIp ] && [ $intTestIfFreeStartIp -le $intEndUsedIp ]
      then
	eigenDebug "Testing free ip start is inside used range!"
	local intTestIfFreeStartIp=$(($intEndUsedIp+1))
      fi

      if [ $intTestIfFreeEndIp -ge $intEndUsedIp ] && [ $intTestIfFreeEndIp -le $intEndUsedIp ]
      then
	eigenDebug "Testing free ip end is inside used range!"
	local intTestIfFreeIp=$(($intStartUsedIp-1))
      fi
    fi
    ((row++))
  done

  unLoadUsedSubnets

  if [ $intTestIfFreeStartIp -lt $intTestIfFreeEndIp ]
  then
    if [ $(($intTestIfFreeEndIp-$intTestIfFreeStartIp)) -ge `cidr2Int $2` ]
    then
      eigenDebug "Testing ip is Free!"
      echo "`ipInt2Dotted "$intTestIfFreeStartIp"`/$2"	#output
      return
    fi
    eigenDebug "Testing ip is Free! But with shorter range then requested"
    echo "`ipInt2Dotted "$intTestIfFreeStartIp"`/`int2cidrD "$(($intTestIfFreeEndIp-$intTestIfFreeStartIp))"`"
    
    return
  fi

  eigenDebug "Big Subnet Exausted"
  echo "0"
}

function start()
{
  echo "starting" >> /tmp/eigenlog

  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv6.conf.all.forwarding=1
  sysctl -w net.ipv6.conf.all.autoconf=0

  loadDevicesInfo

  if [ -e "/etc/isNotFirstRun" ] && [ "`cat "/etc/isNotFirstRun"`" == "1" ]
  then

      ip link set dev niit4to6 up
      ip link set dev niit6to4 up

      sleep 60s #in this way we are sure that olsrd see all other nodes before to look in topology ( this can be increased if necessary)

      local indx=1
      local indi=0
      local dhcp_ranges=""
#Mobile#      local dhcp_mobile_ranges=""

      while [ "${networkWirelessDevice[$indx]}" != "" ]
      do
	local mySubnet=`getFreeSubnet "$networkWirelessIpv4BigSubnet" $networkWirelessCidr`
	if [ "$mySubnet" == "0" ]; then break; fi

	local mySubnetCidr=${mySubnet#*/}
	local dotMySubnetStartIp="${mySubnet%/*}"
	local intMySubnetStartIp="`ipDotted2Int $dotMySubnetStartIp`"
	local intMySubnetEndIp="$(($intMySubnetStartIp+`cidr2Int "$mySubnetCidr"`))"
	local dotMySubnetEndIp=`ipInt2Dotted "$(($intMySubnetEndIp-1))"`

	ip -4 addr add `ipInt2Dotted $(($intMySubnetStartIp+1))`/$mySubnetCidr dev ath$(($indi*2))
	ip -6 route add 0::ffff:$dotMySubnetStartIp/$((96+$mySubnetCidr)) dev niit6to4
	$dynHna6="$dynHna6
0::ffff:`ipDotted2Colon $dotMySubnetStartIp` $((96+$mySubnetCidr))"

	if [ $mySubnetCidr -lt 29 ]; then
	  #$(($intMySubnetStartIp+3)) ( +3 instead of +1 then first 2 ip usable are reserved for statical configuration )
	  dhcp_ranges="$dhcp_ranges --dhcp-range=ath$(($indi*2)),`ipInt2Dotted $(($intMySubnetStartIp+2))`,$dotMySubnetEndIp,`ipInt2Dotted $((2**($mySubnetCidr)))`,1h"
	fi

	configureDynOlsrd

	((indx++))
	((indi++))
      done

      indx=1
      while [ "${networkWiredDevice[$indx]}" != "" ]
      do
	local mySubnet=`getFreeSubnet "$networkWiredIpv4BigSubnet" $networkWiredCidr`
	if [ "$mySubnet" == "0" ]; then break; fi

	local mySubnetCidr=${mySubnet#*/}
	local dotMySubnetStartIp="${mySubnet%/*}"
	local intMySubnetStartIp="`ipDotted2Int $dotMySubnetStartIp`"
	local intMySubnetEndIp="$(($intMySubnetStartIp+`cidr2Int "$mySubnetCidr"`))"
	local dotMySubnetEndIp=`ipInt2Dotted "$(($intMySubnetEndIp-1))"`

	ip -4 addr add `ipInt2Dotted $(($intMySubnetStartIp+1))`/$mySubnetCidr dev ${networkWiredDevice[$indx]}
	ip -6 route add 0::ffff:$dotMySubnetStartIp/$((96+$mySubnetCidr)) dev niit6to4
	$dynHna6="$dynHna6
0::ffff:`ipDotted2Colon $dotMySubnetStartIp` $((96+$mySubnetCidr))"

	if [ $mySubnetCidr -lt 29 ]; then
	  #$(($intMySubnetStartIp+4)) ( +4 instead of +2 then first 2 ip usable are reserved for statical configuration )
	  dhcp_ranges="$dhcp_ranges --dhcp-range=${networkWiredDevice[$indx]},`ipInt2Dotted $(($intMySubnetStartIp+4))`,$dotMySubnetEndIp,`ipInt2Dotted $((2**($mySubnetCidr)))`,2h"
	fi

	configureDynOlsrd

	((indx++))
      done
      

      echo $dhcp_ranges >> /tmp/eigenlog
      dnsmasq -K -D -y -Z -b -E -l /tmp/dhcp.leases -r /etc/resolv.conf.auto $dhcp_ranges
      return 0
  fi

  sleep 10s

  echo "1" > "/etc/isNotFirstRun"

  /etc/init.d/firewall disable
  /etc/init.d/dnsmasq disable

  configureNetwork

  sleep 2s

  reboot
}

function stop()
{
  killall dnsmasq
}

function restart()
{
  stop
  sleep 2s
  start
}
