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
  local meshIfnames=""
  local clientIfnames="bat0"
  
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

  for device in $(scan_devices)
  do
    devtype=$(echo $device | sed -e 's/[0-9]*$//')
    devindex=$(echo $device | sed -e 's/.*\([0-9]\)/\1/')

    case $devtype in
    "eth")
      uci set network.$device=interface
      uci set network.$device.ifname=$device
      uci set network.$device.mtu=1524
      uci set network.$device.proto=static
      uci set network.$device.ip6addr=$mesh6Prefix$(mac6ize $(get_mac $device))/64
      
      meshIfnames="$meshIfnames $device"

      [ $accept_clients -eq 1 ] &&
      {
	clientIfnames="$clientIfnames $device"
      }

    ;;

    "wifi")
      uci set wireless.$device=wifi-device
      uci set wireless.$device.type=atheros
      uci set wireless.$device.channel=$mesh2channel
      uci set wireless.$device.disabled=0

      mif=""

      [ $madwifi_mesh -eq 1 ] &&
      {
	uci set wireless.mesh$device=wifi-iface
	uci set wireless.mesh$device.device=$device
	uci set wireless.mesh$device.network=mesh$device
	uci set wireless.mesh$device.sw_merge=1
	uci set wireless.mesh$device.mode=adhoc
	uci set wireless.mesh$device.ssid=Ninux.org
	uci set wireless.mesh$device.encryption=none

	uci set network.mesh$device=interface
	uci set network.mesh$device.proto=static
	uci set network.mesh$device.mtu=1524
	uci set network.mesh$device.ip6addr=$mesh6Prefix$(mac6ize $(get_mac $device))/64

	mif="ath$devindex"
      }

      [ $accept_clients -eq 1 ] && [ $madwifi_clients -eq 1 ] &&
      {
	cif="ath$devindex"

	[ $madwifi_mesh -eq 1 ]
	{
	  mif="ath$(($devindex+1))"
	  cif="ath$(($devindex*2))"
	}

	uci set wireless.ap$device=wifi-iface
	uci set wireless.ap$device.device=$device
	uci set wireless.ap$device.network=ap$device
	uci set wireless.ap$device.sw_merge=1
	uci set wireless.ap$device.mode=ap
	uci set wireless.ap$device.ssid=EigenNet_$(get_mac $device | tr -d [=:=])
	uci set wireless.ap$device.encryption=none

	clientIfnames="$clientIfnames $cif"

      }

      meshIfnames="$meshIfnames $mif"

    ;;

    "radio")
      uci set wireless.$device=wifi-device
      uci set wireless.$device.type=mac80211
      uci set wireless.$device.macaddr=$(get_mac $device)
      uci set wireless.$device.channel=$mesh2channel
      uci set wireless.$device.disabled=0

      mif=""

      [ $ath9k_mesh -eq 1 ] &&
      {
	uci set wireless.mesh$device=wifi-iface
	uci set wireless.mesh$device.device=$device
	uci set wireless.mesh$device.network=mesh$device
	uci set wireless.mesh$device.sw_merge=1
	uci set wireless.mesh$device.mode=adhoc
	uci set wireless.mesh$device.ssid=Ninux.org
	uci set wireless.mesh$device.encryption=none

	uci set network.mesh$device=interface
	uci set network.mesh$device.proto=static
	uci set network.mesh$device.mtu=1524
	uci set network.mesh$device.ip6addr=$mesh6Prefix$(mac6ize $(get_mac $device))/64

	mif="wlan$devindex"
      }

      [ $accept_clients -eq 1 ] && [ $ath9k_clients -eq 1 ] && 
      {
	cif="wlan$devindex"
	[ $ath9k_mesh -eq 1 ]
	{
	  mif="wlan$(($devindex+1))"
	  cif="wlan$(($devindex*2))"
	}

	uci set wireless.ap$device=wifi-iface
	uci set wireless.ap$device.device=$device
	uci set wireless.ap$device.network=ap$device
	uci set wireless.ap$device.sw_merge=1
	uci set wireless.ap$device.mode=ap
	uci set wireless.ap$device.ssid=EigenNet_$(get_mac $device | tr -d [=:=])
	uci set wireless.ap$device.encryption=none

	clientIfnames="$clientIfnames $cif"

      }

      meshIfnames="$meshIfnames $mif"
    ;;
    esac
  done

  uci set batman-adv.bat0.interfaces="$meshInterfaces"

  [ $accept_clients -eq 1 ] &&
  {
    uci set network.clients=interface
    uci set network.clients.proto=static
    uci set network.clients.type=bridge
    uci set network.clients.ifname="$clientIfnames"
  }

  uci set eigennet.general.bootmode=2

  uci commit
}


start()
{
  config_load	eigennet

  config_get debugLevel	general	debugLevel
  config_get bootmode	general	bootmode
  
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
	return 0
	sleep 10s
    
	configureNetwork

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

