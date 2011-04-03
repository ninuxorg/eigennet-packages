#!/bin/sh /etc/rc.common

<<COPYRIGHT

Copyright (C) 2010-2011  Gioacchino Mazzurco <gmazzurco89@gmail.com>

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

config_get debugLevel	general	debugLevel
config_get bootmode	general	bootmode

# Convert number from a base to another
#
# usage:
# baseconvert inputBase outputBase numberToConvert
# inputBase and outputBase must be expressed in base 10, numberToConvert is expressed in inputBase NOTE: it cannot be a big number
#
# example:
# baseconvert 2 10 1010101
#
baseconvert()
{
  echo $1 $2 $3 | awk '{
	  #our general alphabet
	  alphabet="0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	  # input base
	  ibase=$1; 

	  # output base
	  obase=$2;

	  # input number
	  inumber=toupper($3);

	  #convert third parameter to decimal base
	  for (i=1;i<=length(inumber);i++) {
		  number += (index(alphabet,substr(inumber,i,1))-1)*(ibase^(length(inumber)-i));
	  }
	  tmp=number;

	  #convert "number" to the output base
	  while (tmp>=obase) {
		  nut=substr(alphabet,tmp%obase+1,1);
		  final = nut final;
		  tmp=int(tmp/obase);
	  }
	  final = substr(alphabet,tmp%obase+1,1) final;

	  #printf("%s (b %s) -> %s (b 10) -> %s (b %s)\n",$3,ibase,number,final,obase);
	  printf("%s\n",final)
  }'
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

eigenDebug()
{
  [ $1 -ge $debugLevel ] &&
  {
    echo "Debug: $@" >> /tmp/eigenlog
  }
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

      if [ $ifbase == "wifi" ]; then
          mac=$(ifconfig $ifname | sed -n 1p | awk '{print $5}' | cut -c-17 | sed -e 's/-/:/g')
      elif [ $ifbase == "radio" ]; then
          mac=$(cat /sys/class/ieee80211/$(echo ${ifname} | sed 's/radio/phy/g')/addresses)
      elif [ $ifbase == "phy" ]; then
          mac=$(cat /sys/class/ieee80211/${ifname}/addresses)
      else
          mac=$(ifconfig $ifname | sed -n 1p | awk '{print $5}')
      fi

      echo $mac | tr '[a-z]' ['A-Z']
}

#[Doc]
#[Doc] Return part of given mac in ipv4 like format
#[Doc]
#[Doc] usage:
#[Doc] mac4ize mac_address
#[Doc]
#[Doc] example:
#[Doc] mac4ize ff:ff:ff:ff:ff:ff
#[Doc]
mac4ize()
{
  returnValue="$(baseconvert 16 10 $(echo $1 | awk -F: '{print $6}'))"
  returnValue="$(baseconvert 16 10 $(echo $1 | awk -F: '{print $5}')).$returnValue"
  returnValue="$(baseconvert 16 10 $(echo $1 | awk -F: '{print $4}')).$returnValue"
  
  echo $returnValue
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
#[Doc] scan_interfacer
#[Doc]
scan_devices()
{
      eth=""
      radio=""
      wifi=""

      # Getting wired interfaces
      eth=$(cat /proc/net/dev | sed -n -e 's/:.*//' -e 's/[ /t]*//' -e '/^eth[0-9]$/p')

      # Getting ath9k interfaces
      if [ -e /lib/wifi/mac80211.sh ] && [ -e /sys/class/ieee80211/ ]; then
          radio=$(ls /sys/class/ieee80211/ | sed -n -e '/^phy[0-9]$/p' | sed -e 's/^phy/radio/')
      fi

      # Getting madwifi interfaces
      if [ -e /lib/wifi/madwifi.sh ]; then
          cd /proc/sys/dev/
          wifi=$(ls | grep wifi)
      fi

      echo "${eth} ${radio} ${wifi}" | sed 's/ /\n/g' | sed '/^$/d'
}

configureNetwork()
{
  local accept_clients		; config_get accept_clients	network		accept_clients 
  local firewallEnabled		; config_get firewallEnabled	network		firewallEnabled
  local ipv6prefix		; config_get ipv4prefix		network		client4Prefix
  local ipv4prefix		; config_get ipv6prefix		network		client6Prefix
  local mesh6Prefix		; config_get mesh6Prefix	network		mesh6Prefix
  local mesh4Prefix		; config_get mesh4Prefix	network		mesh4Prefix
  local resolvers		; config_get resolvers		network		resolvers
  local sshEigenserverKey	; config_get sshEigenserverKey	network		sshEigenserverKey

  local ath9k_clients		; config_get ath9k_clients	wireless	ath9k_clients
  local ath9k_mesh		; config_get ath9k_mesh		wireless	ath9k_mesh
  local madwifi_clients		; config_get madwifi_clients	wireless	madwifi_clients
  local madwifi_mesh		; config_get madwifi_mesh	wireless	madwifi_mesh
  local mesh2channel		; config_get mesh2channel	wireless	mesh2channel
  local mesh5channel		; config_get mesh5channel	wireless	mesh5channel
  
  [ $firewallEnabled -eq 0 ] &&
  {
    /etc/init.d/firewall disable
  }
  
  echo "$sshEigenserverKey" >> "/etc/dropbear/authorized_keys"

  echo "
#Automatically generated for EigenNet

$(cat /etc/sysctl.conf | grep -v net.ipv4.ip_forward | grep -v net.ipv6.conf.all.forwarding | grep -v net.ipv6.conf.all.autoconf)

net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.autoconf=0
" > /etc/sysctl.conf

  echo "#Automatically generated for EigenNet" > $CONF_DIR/wireless
  
  for dns in $resolvers
  do
    echo nameserver $dns >> /etc/resolv.conf.auto
  done

  config_load network
  config_foreach del_interface interface

  uci set network.loopback=interface
  uci set network.loopback.ifname=lo
  uci set network.loopback.proto=static
  uci set network.loopback.ipaddr="127.0.0.1"
  uci set network.loopback.netmask="255.0.0.0"
  uci set network.loopback.ip6addr="0::1/128"

  for device in $(scan_devices)
  do
    devtype=$(echo $device | sed -e 's/[0-9]*$//')
    devindex=$(echo $device | sed -e 's/.*\([0-9]\)/\1/')

    case $devtype in
    "eth")
      uci set network.n$device=interface
      uci set network.n$device.ifname=$device
      uci set network.n$device.proto=static
      uci set network.n$device.ip6addr=$mesh6Prefix$(mac6ize $(get_mac $device))/64
      uci set network.n$device.ipaddr=$mesh4Prefix$(mac4ize $(get_mac $device))
      uci set network.n$device.netmask=255.255.255.255
      
      uci set babeld.n$device=interface
      
      [ $accept_clients -eq 1 ] &&
      {	
	uci set network.n$device.ipaddr=$ipv4prefix$devindex.1
	uci set network.n$device.netmask=255.255.255.224

	uci set network.nalias$device=alias
	uci set network.nalias$device.interface=n$device
	uci set network.nalias$device.proto=static
	uci set network.nalias$device.ip6addr=$ipv6prefix$devindex::1/64

	uci set radvd.ralias$device=interface
	uci set radvd.ralias$device.interface=nalias$device
	uci set radvd.ralias$device.AdvSendAdvert=1
	uci set radvd.ralias$device.ignore=0

	uci set radvd.rprefix$device=prefix
	uci set radvd.rprefix$device.interface=ralias$device
	uci set radvd.rprefix$device.AdvOnLink=1
	uci set radvd.rprefix$device.AdvAutonomous=1
	uci set radvd.rprefix$device.ignore=0

	uci set dhcp.d$device=dhcp
	uci set dhcp.d$device.interface=n$device
	uci set dhcp.d$device.start=2
	uci set dhcp.d$device.limit=28
	uci set dhcp.d$device.leasetime=1h
      }
    ;;

    "wifi")
      uci set wireless.$device=wifi-device
      uci set wireless.$device.type=atheros
      uci set wireless.$device.channel=$mesh2channel
      uci set wireless.$device.disabled=0

      [ $madwifi_mesh -eq 1 ] &&
      {
	uci set wireless.mesh$device=wifi-iface
	uci set wireless.mesh$device.device=$device
	uci set wireless.mesh$device.network=nmesh$device
	uci set wireless.mesh$device.sw_merge=1
	uci set wireless.mesh$device.mode=adhoc
	uci set wireless.mesh$device.ssid=Ninux.org
	uci set wireless.mesh$device.encryption=none

	uci set network.nmesh$device=interface
	uci set network.nmesh$device.proto=static
	uci set network.nmesh$device.ip6addr=$mesh6Prefix$(mac6ize $(get_mac $device))/64
	uci set network.nmesh$device.ipaddr=$mesh4Prefix$(mac4ize $(get_mac $device))
	uci set network.nmesh$device.netmask=255.255.255.255

	uci set babeld.nmesh$device=interface
      }

      [ $accept_clients -eq 1 ] && [ $madwifi_clients -eq 1 ] &&
      {
	uci set wireless.ap$device=wifi-iface
	uci set wireless.ap$device.device=$device
	uci set wireless.ap$device.network=nap$device
	uci set wireless.ap$device.sw_merge=1
	uci set wireless.ap$device.mode=ap
	uci set wireless.ap$device.ssid=EigenNet_$(get_mac $device | tr -d [=:=])
	uci set wireless.ap$device.encryption=none

	uci set network.nap$device=interface
	uci set network.nap$device.proto=static
	uci set network.nap$device.ip6addr=$ipv6prefix$devindex::1/64
	uci set network.nap$device.ipaddr=$ipv4prefix$devindex.1
	uci set network.nap$device.netmask=255.255.255.224

	uci set radvd.rap$device=interface
	uci set radvd.rap$device.interface=nap$device
	uci set radvd.rap$device.AdvSendAdvert=1
	uci set radvd.rap$device.ignore=0

	uci set radvd.rprefix$device=prefix
	uci set radvd.rprefix$device.interface=rap$device
	uci set radvd.rprefix$device.AdvOnLink=1
	uci set radvd.rprefix$device.AdvAutonomous=1
	uci set radvd.rprefix$device.ignore=0

	uci set dhcp.dap$device=dhcp
	uci set dhcp.dap$device.interface=nap$device
	uci set dhcp.dap$device.start=2
	uci set dhcp.dap$device.limit=28
	uci set dhcp.dap$device.leasetime=1h
      }
    ;;

    "radio")
      uci set wireless.$device=wifi-device
      uci set wireless.$device.type=mac80211
      uci set wireless.$device.macaddr=$(get_mac $device)
      uci set wireless.$device.channel=$mesh2channel
      uci set wireless.$device.disabled=0

      [ $ath9k_mesh -eq 1 ] &&
      {
	uci set wireless.mesh$device=wifi-iface
	uci set wireless.mesh$device.device=$device
	uci set wireless.mesh$device.network=nmesh$device
	uci set wireless.mesh$device.sw_merge=1
	uci set wireless.mesh$device.mode=adhoc
	uci set wireless.mesh$device.ssid=Ninux.org
	uci set wireless.mesh$device.encryption=none

	uci set network.nmesh$device=interface
	uci set network.nmesh$device.proto=static
	uci set network.nmesh$device.ip6addr=$mesh6Prefix$(mac6ize $(get_mac $device))/64
	uci set network.nmesh$device.ipaddr=$mesh4Prefix$(mac4ize $(get_mac $device))
	uci set network.nmesh$device.netmask=255.255.255.255

	uci set babeld.nmesh$device=interface
      }

      [ $accept_clients -eq 1 ] && [ $ath9k_clients -eq 1 ] && 
      {
	uci set wireless.ap$device=wifi-iface
	uci set wireless.ap$device.device=$device
	uci set wireless.ap$device.network=nap$device
	uci set wireless.ap$device.sw_merge=1
	uci set wireless.ap$device.mode=ap
	uci set wireless.ap$device.ssid=EigenNet_$(get_mac $device | tr -d [=:=])
	uci set wireless.ap$device.encryption=none

	uci set network.nap$device=interface
	uci set network.nap$device.proto=static
	uci set network.nap$device.ip6addr=$ipv6prefix$devindex::1/64
	uci set network.nap$device.ipaddr=$ipv4prefix$devindex.1
	uci set network.nap$device.netmask=255.255.255.224

	uci set radvd.rap$device=interface
	uci set radvd.rap$device.interface=nap$device
	uci set radvd.rap$device.AdvSendAdvert=1
	uci set radvd.rap$device.ignore=0

	uci set radvd.rprefix$device=prefix
	uci set radvd.rprefix$device.interface=rap$device
	uci set radvd.rprefix$device.AdvOnLink=1
	uci set radvd.rprefix$device.AdvAutonomous=1
	uci set radvd.rprefix$device.ignore=0

	uci set dhcp.dap$device=dhcp
	uci set dhcp.dap$device.interface=nap$device
	uci set dhcp.dap$device.start=2
	uci set dhcp.dap$device.limit=28
	uci set dhcp.dap$device.leasetime=1h
      }
    ;;
    esac
  done

  [ $accept_clients -eq 1 ] &&
  {
    uci set babeld.fallback64=filter
    uci set babeld.fallback64.type=redistribute
    uci set babeld.fallback64.ip="$mesh6Prefix:/64"
    uci set babeld.fallback64.action=deny
    
    uci set babeld.clients6=filter
    uci set babeld.clients6.type=redistribute
    uci set babeld.clients6.ip="::0/0"
    uci set babeld.clients6.action="metric 386"
    
    uci set babeld.clients4=filter
    uci set babeld.clients4.type=redistribute
    uci set babeld.clients4.ip="0.0.0.0/0"
    uci set babeld.clients4.action="metric 384"
    
    uci set dhcp.eigennet.ignore=0
  }

  uci set eigennet.general.bootmode=2

  uci commit
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
    
	configureNetwork

	sleep 2s
	reboot
  }

  [ $bootmode -ge 2 ] &&
  {
	sysctl -w net.ipv4.ip_forward=1
	sysctl -w net.ipv6.conf.all.forwarding=1
	sysctl -w net.ipv6.conf.all.autoconf=0

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

