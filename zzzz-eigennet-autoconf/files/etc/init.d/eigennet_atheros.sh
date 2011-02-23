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

eigenDebugEnabled=false

CONF_DIR="/etc/config/"
meshPrefix="2001:470:1f13:67f:0:"
mesh2channel=8
mesh5channel=60
ipv6prefix="2001:470:ca42:"   #at least a /48 prefix
ipv4prefix="10.174."          #at least a /16 prefix

resolvers="2001:470:1f12:325:0:23:7d29:13fa 10.175.0.101"

SSH_EIGENSERVER_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAyLK+91TbZOFGC4Psdmoe/vImeTXFDekcaDuKJbAILoVitTZUeXToSCrtihwmcTmoyL/8QtwoBTMa+6fRlWYWmba8I2erwxT+WqHgrh4mwVCDmyVRnoOMgjiWjmzs+cgqV/ECJgx8D3qlACO0ZlJWkYCqc8tBWMM7sBTBwSCGsL1lxwn449myHj9w3iNfy0a11+7d/eVsSGRmNHJ9Tz1+88OJA2FI3riI7cUiKHbHt0Mlr8ggUS74jP+XbyeKq7pPbCgmNzL7uDeqJgzDW28ALRznOSqSYP8Q2IJfPaTn2Re+F8VsljMHcUD0YoT3q9WMHBYNA8cOuB9lmM/1i+0YKQ== www-data@eigenserver"

eigenDebug()
{
  if $eigenDebugEnabled
  then
    echo "Debug: $@" >> /tmp/eigenlog
  fi
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

configureNetwork()
{
  echo "$SSH_EIGENSERVER_KEY" >> "/etc/dropbear/authorized_keys"

  echo "
#Automatically generated for Eigennet

$(cat /etc/sysctl.conf | grep -v net.ipv4.ip_forward | grep -v net.ipv6.conf.all.forwarding | grep -v net.ipv6.conf.all.autoconf)

net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
net.ipv6.conf.all.autoconf=0
" > /etc/sysctl.conf

  for dns in $resolvers
  do
    echo nameserver $dns >> /etc/resolv.conf.auto
  done

  . /etc/functions.sh
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
      uci set network.$device.proto=static
      uci set network.$device.ip6addr=$meshPrefix$(mac6ize $(get_mac $device))/64
      uci set network.$device.ipaddr=$ipv4prefix$devindex.1
      uci set network.$device.netmask=255.255.255.224

      uci set network.alias$device=alias
      uci set network.alias$device.interface=$device
      uci set network.alias$device.proto=static
      uci set network.alias$device.ip6addr=$ipv6prefix$devindex::1/64
      uci set network.alias$device.ignore=1

      uci set babel.$device=interface

      uci set radvd.alias$device=interface
      uci set radvd.alias$device.interface=alias$device
      uci set radvd.alias$device.AdvSendAdvert=1
      uci set radvd.alias$device.ignore=1

      uci set radvd.prefix$device=prefix
      uci set radvd.prefix$device.interface=alias$device
      uci set radvd.prefix$device.AdvOnLink=1
      uci set radvd.prefix$device.AdvAutonomous=1
      uci set radvd.prefix$device.ignore=1
    ;;

    "wifi")
      uci set wireless.$device=wifi-device
      uci set wireless.$device.type=atheros
      uci set wireless.$device.channel=$mesh2channel
      uci set wireless.$device.disabled=0

      uci set wireless.mesh$device=wifi-iface
      uci set wireless.mesh$device.device=$device
      uci set wireless.mesh$device.network=mesh$device
      uci set wireless.mesh$device.sw_merge=1
      uci set wireless.mesh$device.mode=adhoc
      uci set wireless.mesh$device.ssid=Ninux.org
      uci set wireless.mesh$device.encryption=none

      uci set wireless.ap$device=wifi-iface
      uci set wireless.ap$device.device=$device
      uci set wireless.ap$device.network=ap$device
      uci set wireless.ap$device.sw_merge=1
      uci set wireless.ap$device.mode=ap
      uci set wireless.ap$device.ssid=EigenNet
      uci set wireless.ap$device.encryption=none
      uci set wireless.ap$device.ignore=1

      uci set network.mesh$device=interface
      uci set network.mesh$device.proto=static
      uci set network.mesh$device.ip6addr=$meshPrefix$(mac6ize $(get_mac $device))/64

      uci set babel.mesh$device=interface

      uci set network.ap$device=interface
      uci set network.ap$device.proto=static
      uci set network.ap$device.ip6addr=$ipv6prefix$devindex::1/64
      uci set network.ap$device.ipaddr=$ipv4prefix$devindex.1
      uci set network.ap$device.netmask=255.255.255.224
      uci set network.ap$device.ignore=1

      uci set radvd.ap$device=interface
      uci set radvd.ap$device.interface=ap$device
      uci set radvd.ap$device.AdvSendAdvert=1
      uci set radvd.ap$device.ignore=1

      uci set radvd.prefix$device=prefix
      uci set radvd.prefix$device.interface=alias$device
      uci set radvd.prefix$device.AdvOnLink=1
      uci set radvd.prefix$device.AdvAutonomous=1
      uci set radvd.prefix$device.ignore=1
    ;;

    "radio")
      uci set wireless.$device=wifi-device
      uci set wireless.$device.type=mac80211
      uci set wireless.$device.macaddr=$(get_mac $device)
      uci set wireless.$device.channel=$mesh2channel
      uci set wireless.$device.disabled=0

      uci set wireless.mesh$device=wifi-iface
      uci set wireless.mesh$device.device=$device
      uci set wireless.mesh$device.network=mesh$device
      uci set wireless.mesh$device.sw_merge=1
      uci set wireless.mesh$device.mode=adhoc
      uci set wireless.mesh$device.ssid=Ninux.org
      uci set wireless.mesh$device.encryption=none

      uci set babel.mesh$device=interface

      uci set wireless.ap$device=wifi-iface
      uci set wireless.ap$device.device=$device
      uci set wireless.ap$device.network=ap$device
      uci set wireless.ap$device.sw_merge=1
      uci set wireless.ap$device.mode=ap
      uci set wireless.ap$device.ssid=EigenNet
      uci set wireless.ap$device.encryption=none
      uci set wireless.ap$device.ignore=1

      uci set network.mesh$device=interface
      uci set network.mesh$device.proto=static
      uci set network.mesh$device.ip6addr=$meshPrefix$(mac6ize $(get_mac $device))/64

      uci set network.ap$device=interface
      uci set network.ap$device.proto=static
      uci set network.ap$device.ip6addr=$ipv6prefix$devindex::1/64
      uci set network.ap$device.ipaddr=$ipv4prefix$devindex.1
      uci set network.ap$device.netmask=255.255.255.224
      uci set network.ap$device.ignore=1

      uci set radvd.ap$device=interface
      uci set radvd.ap$device.interface=ap$device
      uci set radvd.ap$device.AdvSendAdvert=1
      uci set radvd.ap$device.ignore=1

      uci set radvd.prefix$device=prefix
      uci set radvd.prefix$device.interface=alias$device
      uci set radvd.prefix$device.AdvOnLink=1
      uci set radvd.prefix$device.AdvAutonomous=1
      uci set radvd.prefix$device.ignore=1
    ;;
    esac
  done

  uci commit
}


start()
{
  eigenDebug "starting"
  
  [ ! -e "/etc/isNotFirstRun" ] &&
  {
	sleep 61s
	echo "1" > "/etc/isNotFirstRun"
	reboot
	return 0
  }  

  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv6.conf.all.forwarding=1
  sysctl -w net.ipv6.conf.all.autoconf=0

  [ -e "/etc/isNotFirstRun" ] && [ "`cat "/etc/isNotFirstRun"`" == "2" ] &&
  {
    return 0
  }

  sleep 10s

  echo "2" > "/etc/isNotFirstRun"

  /etc/init.d/firewall disable

  configureNetwork

  sleep 2s

  reboot
}

stop()
{
  eigenDebug "stopping"
}

restart()
{
  stop
  sleep 2s
  start
}

