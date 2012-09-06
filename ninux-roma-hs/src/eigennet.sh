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

config_load eigennet

config_get debugLevel general "debugLevel" 0

#[Doc]
#[Doc] Statement of common variables
#[Doc]
#[Doc] for to work on config file usage:
#[Doc]
#[Doc] var=$var ; config_* var module "var"
#[Doc]

accept_clients=$accept_clients	; config_get_bool	accept_clients	network	"accept_clients"	1
ip6addr_mesh=$ip6addr_mesh	; config_get		ip6addr_mesh	network	"ip6addr_mesh"		"2001:4c00:893b:1:cab::/128"
ip4addr_mesh=$ip4addr_mesh	; config_get		ip4addr_mesh	network	"ip4addr_mesh"		"172.16.0.1"
netmask_mesh=$netmask_mesh	; config_get		netmask_mesh	network	"netmask_mesh"		"255.255.0.0"

ip6addr_lan=$ip6addr_lan	; config_get		ip6addr_lan	network	"ip6addr_lan"		"2001:4c00:893b:cab::123/64"
ip4addr_lan=$ip4addr_lan	; config_get		ip4addr_lan	network	"ip4addr_lan"		"192.168.1.21"
netmask_lan=$netmask_lan	; config_get		netmask_lan	network	"netmask_lan"		"255.255.255.0"

hs_enable=$hs_enable		; config_get_bool	hs_enable	hotspot "hs_enable"		0
ip4addr_hs=$ip4addr_hs		; config_get            ip4addr_hs      hotspot "ip4addr_hs"            "192.168.10.1"
netmask_hs=$netmask_hs  	; config_get            netmask_hs      hotspot "netmask_hs"            "255.255.255.0"
hsSSID=$hsSSID			; config_get		hsSSID		hotspot "hsSSID"		"www.ninux.org"
hsMaxClients=$hsMaxClients	; config_get		hsMaxClients	hotspot "hsMaxClients"		"50"

wan_set=$wan_set		; config_get		wan_set		network	"wan_set"		0
ip4_wan=$ip4_wan		; config_get		ip4_wan		network	"ip4_wan"		"0.0.0.0"
wan_mask=$wan_mask		; config_get		wan_mask	network	"wan_mask"		"0.0.0.0"

hostName=$hostName		; config_get		hostName	network	"hostName"		"node_device"
resolvers=$resolvers		; config_get		resolvers	network	"resolvers"		"160.80.221.11 8.8.8.8"

wifi_clients=$wifi_clients	; config_get_bool	wifi_clients	wireless "wifi_clients"		1
wifi_mesh=$wifi_mesh		; config_get_bool	wifi_mesh	wireless "wifi_mesh"		1
ath9k_clients=$wifi_clients	; config_get_bool	ath9k_clients	wireless "wifi_clients"		1
ath9k_mesh=$wifi_mesh		; config_get_bool	ath9k_mesh	wireless "wifi_mesh"		1
madwifi_clients=$wifi_clients	; config_get_bool	madwifi_clients	wireless "wifi_clients"		1
madwifi_mesh=$wifi_mesh		; config_get_bool	madwifi_mesh	wireless "wifi_mesh"		1

tx_power=$tx_power		; config_get		tx_power	wireless "tx_power"
countrycode=$countrycode	; config_get		countrycode	wireless "countrycode"
mesh2channel=$wifi_channel	; config_get		mesh2channel	wireless "wifi_channel"
meshSSID=$meshSSID		; config_get		meshSSID	wireless "meshSSID"		"mesh.ninux.org"
meshBSSID=$meshBSSID		; config_get		meshBSSID	wireless "meshBSSID"		"02:aa:bb:cc:dd:00"
meshMcastRate=$meshMcastRate	; config_get		meshMcastRate	wireless "meshMcastRate"
apSSID=$apSSID			; config_get		apSSID		wireless "apSSID"		"ninux.org"
apKEY=$apKEY			; config_get		apKEY		wireless "apKEY"
apMaxClients=$apMaxClients	; config_get		apMaxClients	wireless "apMaxClients"

gw_announce=$gw_announce	; config_get_bool	gw_announce	olsrd "gw_announce"		0

lan6prefix=$lan6prefix		; config_get		lan6prefix	olsrd "lan6prefix"		"64"

hna6=$hna6			; config_get		hna6		olsrd "hna6"			"2001:4c00:893b:abcd::"
hna4=$hna4			; config_get		hna4		olsrd "hna4"			"192.168.1.0"
supernode=$supernode            ; config_get_bool       supernode       olsrd "supernode"               0

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
	model=""
	eth=""
	radio=""
	wifi=""
	
	# Getting router model
	model=$(cat /proc/cpuinfo |grep machine|awk '{print $4}')
	
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
	else
		wifi=$(ls /sys/class/net/ | sed -n -e '/^wlan[0-9]/p')
	fi

	echo "${eth} ${radio} ${wifi}" | sed 's/ /\n/g' | sed '/^$/d'
}
  
configureNetwork()
{
local TimeZone="CET-1CEST,M3.5.0,M10.5.0/3"
	uci set system.@system[0].hostname=$hostName
	uci set system.@system[0].timezone=$TimeZone
	uci del system.ntp
	uci set system.ntp=timeserver
	uci set system.ntp.enable_server=1
	uci set system.ntp.server=timeserver.ninux.org

	/etc/init.d/firewall disable
	/etc/init.d/olsrd disable

	echo -e "$(cat /etc/sysctl.conf | grep -v net.ipv6.conf.all.autoconf) \n net.ipv6.conf.all.autoconf=0" > /etc/sysctl.conf

	rm -rf /etc/resolv.conf
	for dns in $resolvers
	do
		echo nameserver $dns >> /etc/resolv.conf
	done
	
	/etc/init.d/dnsmasq enable

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

	uci set network.lan=interface
	uci set network.lan.proto=static
	uci set network.lan.type=bridge
	uci set network.lan.ip6addr=$ip6addr_lan
	uci set network.lan.ipaddr=$ip4addr_lan
	uci set network.lan.netmask=$netmask_lan
	
	if [ $model == TL-WR741ND ]
		then
		uci add_list network.lan.ifname=eth0
		uci set network.@switch[0]=switch
		uci set network.@switch[0].name=eth0
		uci set network.@switch[0].reset=1
		uci set network.@switch[0].enable_vlan=1
		uci set network.@switch_vlan[0]=switch_vlan
		uci set network.@switch_vlan[0].device=eth0
		uci set network.@switch_vlan[0].vlan=1
		uci set network.@switch_vlan[0].ports=0 1 2 3 4
		if [ $wan_set -eq 1 ]
			then
			uci set network.wan=interface
			uci set network.wan.ifname=eth1
			uci set network.wan.proto=static
			uci set network.wan.ipaddr=$ip4_wan
			uci set network.wan.netmask=$wan_mask
			uci set network.wan.dns=$resolvers
			else
			uci set network.wan=interface
			uci set network.wan.ifname=eth1
			uci set network.wan.proto=dhcp
		fi
	elif [ $model == TL-WR1043ND ]
		then
		uci add_list network.lan.ifname=eth0.2
		uci set network.@switch[0]=switch
		uci set network.@switch[0].name=rtl8366rb
		uci set network.@switch[0].reset=1
		uci set network.@switch[0].enable_vlan=1
		uci set network.@switch[0].enable_vlan4k=1
		uci set network.@switch_vlan[0]=switch_vlan
		uci set network.@switch_vlan[0].device=rtl8366rb
		uci set network.@switch_vlan[0].vlan=1
		uci set network.@switch_vlan[0].ports=0 5t
		uci set network.@switch_vlan[1]=switch_vlan
		uci set network.@switch_vlan[1].device=rtl8366rb
		uci set network.@switch_vlan[1].vlan=2
		uci set network.@switch_vlan[1].ports=1 2 3 4 5t
		if [ $wan_set -eq 1 ]
			then
			uci set network.wan=interface
			uci set network.wan.ifname=eth0.1
			uci set network.wan.proto=static
			uci set network.wan.ipaddr=$ip4_wan
			uci set network.wan.netmask=$wan_mask
			uci set network.wan.dns=$resolvers
			else	
			uci set network.wan=interface
			uci set network.wan.ifname=eth0.1
			uci set network.wan.proto=dhcp
		fi				
	else
		uci add_list network.lan.ifname=eth0
	fi

	for device in $(scan_devices)
	do
		devtype=$(echo $device | sed -e 's/[0-9]*$//')
		devindex=$(echo $device | sed -e 's/.*\([0-9]\)/\1/')

		case $devtype in
			"wifi")
				uci set wireless.$device.channel=$mesh2channel
				uci set wireless.$device.disabled=0
				uci set wireless.$device.txpower=$tx_power
				uci set wireless.$device.country=$countrycode

				[ $madwifi_mesh -eq 1 ] &&
				{
					uci set wireless.mesh$device=wifi-iface
					uci set wireless.mesh$device.device=$device
					uci set wireless.mesh$device.network=nmesh$device
					uci set wireless.mesh$device.mode=adhoc
					uci set wireless.mesh$device.bssid=$meshBSSID
					uci set wireless.mesh$device.ssid=$meshSSID
					uci set wireless.mesh$device.encryption=none
					uci set wireless.mesh$device.mcast_rate=$meshMcastRate
										
					uci set network.nmesh$device=interface
					uci set network.nmesh$device.proto=static
					uci set network.nmesh$device.mtu=1528
					uci set network.nmesh$device.ip6addr=$ip6addr_mesh
					uci set network.nmesh$device.ipaddr=$ip4addr_mesh
					uci set network.nmesh$device.netmask=$netmask_mesh
					ifname_mesh=nmesh$device
				}

				[ $accept_clients -eq 1 ] && [ $madwifi_clients -eq 1 ] &&
				{
					uci set wireless.ap$device=wifi-iface
					uci set wireless.ap$device.device=$device
					uci set wireless.ap$device.network=lan
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

                                [ $accept_clients -eq 1 ] && [ $hs_enable -eq 1 ] &&
                                {
                                        uci set wireless.hs$device=wifi-iface
                                        uci set wireless.hs$device.device=$device
                                        uci set wireless.hs$device.network=hot$device
                                        uci set wireless.hs$device.mode=ap
                                        uci set wireless.hs$device.ssid=$hsSSID
                                        uci set wireless.hs$device.encryption=none
                                        uci set wireless.hs$device.maxassoc=$hsMaxClients
					
					uci set network.hot$device=interface
					uci set network.hot$device.proto=static
					uci set network.hot$device.ipaddr=$ip4addr_hs
					uci set network.hot$device.netmask=$netmask_hs
					ifname_hs=hot$device
                                }
			;;

			"radio")
				uci set wireless.$device.channel=$mesh2channel
				uci set wireless.$device.disabled=0
				uci set wireless.$device.txpower=$tx_power
				uci set wireless.$device.country=$countrycode ## Seems newer hardware doest permit change country

				[ $ath9k_mesh -eq 1 ] &&
				{
					uci set wireless.mesh$device=wifi-iface
					uci set wireless.mesh$device.device=$device
					uci set wireless.mesh$device.network=nmesh$device
					uci set wireless.mesh$device.mode=adhoc
					uci set wireless.mesh$device.bssid=$meshBSSID
					uci set wireless.mesh$device.ssid=$meshSSID
					uci set wireless.mesh$device.encryption=none
					uci set wireless.mesh$device.mcast_rate=$meshMcastRate
					
					uci set network.nmesh$device=interface
					uci set network.nmesh$device.proto=static
					uci set network.nmesh$device.mtu=1528
					uci set network.nmesh$device.ip6addr=$ip6addr_mesh
					uci set network.nmesh$device.ipaddr=$ip4addr_mesh
					uci set network.nmesh$device.netmask=$netmask_mesh
					ifname_mesh=nmesh$device
				}

				[ $accept_clients -eq 1 ] && [ $ath9k_clients -eq 1 ] && 
				{
					uci set wireless.ap$device=wifi-iface
					uci set wireless.ap$device.device=$device
					uci set wireless.ap$device.network=lan
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

				[ $accept_clients -eq 1 ] && [ $hs_enable -eq 1 ] &&
                                {
                                        uci set wireless.hs$device=wifi-iface
                                        uci set wireless.hs$device.device=$device
                                        uci set wireless.hs$device.network=hot$device
                                        uci set wireless.hs$device.mode=ap
                                        uci set wireless.hs$device.ssid=$hsSSID
                                        uci set wireless.hs$device.encryption=none
                                        uci set wireless.hs$device.maxassoc=$hsMaxClients
					
					uci set network.hot$device=interface
					uci set network.hot$device.proto=static
					uci set network.hot$device.ipaddr=$ip4addr_hs
					uci set network.hot$device.netmask=$netmask_hs
					ifname_hs=hot$device
                                }
			;;
		esac
	done

uci commit network

/etc/init.d/network restart

iface_mesh=$(ip -6 a s | grep -B 2 $ip6addr_mesh | sed -n 2p | awk '{print $2}' | sed 's/://')
iface_hs=$(ip -4 a s | grep -B 2 $ip4addr_hs | sed -n 2p | awk '{print $2}' | sed 's/://')
iface_olsrd=""

if [ $supernode -eq 1 ]
	then
		iface_olsrd=$(echo '"'${iface_mesh}'"' '"br-lan"')
	else
		iface_olsrd=$(echo '"'${iface_mesh}'"')
fi
}

configureOlsrd4()
{
local gw=""
local hna4_full="${hna4} ${netmask_lan}"
local OLSRD4="/etc/config/olsrd4"

if [ $gw_announce -eq 1 ]
	then
		gw="0.0.0.0 0.0.0.0"
	else	
		gw="#"
fi

cat > $OLSRD4 << EOF
#Automatically generated for Eigennet
DebugLevel  0
IpVersion 4

Pollrate  0.025
FIBMetric "flat"

# RtTable 111
# RtTableDefault 112

UseNiit no
SmartGateway no

Hna4
{
${hna4_full}
${gw}
}

#Hna6
#{
#}

UseHysteresis no
TcRedundancy  2
MprCoverage 7

LinkQualityLevel 2
LinkQualityAlgorithm    "etx_ff"
LinkQualityAging 0.05
LinkQualityFishEye  1

# Don't remove olsrd_txtinfo from this file
# as this plugin is used by the Webinterface
# to display the OLSR Info
LoadPlugin "olsrd_txtinfo.so.0.1"
{
   PlParam     "port"   "2006"
   PlParam     "Accept"   "127.0.0.1"
}

InterfaceDefaults {
   HelloInterval 3.0
   HelloValidityTime 125.0
   TcInterval 2.0
   TcValidityTime 500.0
   MidInterval 25.0
   MidValidityTime 500.0
   HnaInterval 10.0
   HnaValidityTime 125.0
}

Interface ${iface_olsrd}
{
    Mode "mesh"
}

EOF

chmod a+x $OLSRD4
echo "olsrd -f /etc/config/olsrd4 -d 0" > /etc/init.d/olsrd4
chmod a+x /etc/init.d/olsrd4
ln -s /etc/init.d/olsrd4 /etc/rc.d/S65olsrd4
}

configureOlsrd6()
{
local OLSRD6="/etc/config/olsrd6"
local hna6_full="${hna6} ${lan6prefix}"

cat > $OLSRD6 << EOF
#Automatically generated for Eigennet
DebugLevel  0

IpVersion 6

Pollrate  0.025
FIBMetric "flat"
UseNiit no
SmartGateway no


Hna6
{
${hna6_full}
}

UseHysteresis no
TcRedundancy  2

MprCoverage 7

LinkQualityLevel 2
LinkQualityAlgorithm    "etx_ff"
LinkQualityAging 0.05
LinkQualityFishEye  1

LoadPlugin "olsrd_txtinfo.so.0.1"
{
   PlParam     "port"   "2007"
   PlParam     "Accept"   "::"
}

InterfaceDefaults {
   HelloInterval 3.0
   HelloValidityTime 125.0
   TcInterval 2.0
   TcValidityTime 500.0
   MidInterval 25.0
   MidValidityTime 500.0
   HnaInterval 10.0
   HnaValidityTime 125.0
}

Interface ${iface_olsrd}
{
    Mode "mesh"
    IPv6Multicast FF02::6D

}

EOF

chmod a+x $OLSRD6
echo "olsrd -f /etc/config/olsrd6 -d 0" > /etc/init.d/olsrd6
chmod a+x /etc/init.d/olsrd6
ln -s /etc/init.d/olsrd6 /etc/rc.d/S65olsrd6
}

configureRadvd()
{
local RADVD="/etc/config/radvd"
local radvd_prefix ; config_get		radvd_prefix	network	"radvd_prefix"		"2001:4c00:893b:cab::/64"

cat > $RADVD << EOF
#Automatically generated for Eigennet
config interface
	option interface	'lan'
	option AdvSendAdvert	1
	option AdvManagedFlag	1
	option AdvOtherConfigFlag 1
	option AdvLinkMTU	1280
	option ignore		0

config prefix
	option interface	'lan'
	list prefix		'${radvd_prefix}'
	option AdvOnLink	1
	option AdvAutonomous	1
	option AdvRouterAddr	1
	option ignore		0
	
EOF

chmod a+x $RADVD
/etc/init.d/radvd enable
}

configureDhcp()
{
local maxclient=""
local DHCP="/etc/config/dhcp"

if [ -n $apMaxClients ]
	then
	maxclient=$(($apMaxClients+20))
	else
	maxclient=20
fi

cat > $DHCP << EOF
#Automatically generated for Eigennet
config dnsmasq
	option domainneeded '1'
	option boguspriv '1'
	option filterwin2k '0'
	option localise_queries '1'
	option rebind_protection '0'
	option rebind_localhost '1'
	option local '/lan/'
	option domain 'lan'
	option expandhosts '1'
	option nonegcache '0'
	option authoritative '1'
	option readethers '1'
	option leasefile '/tmp/dhcp.leases'
	option resolvfile '/etc/resolv.conf'

config dhcp 'lan'
	option interface 'lan'
	option leasetime '12h'
	option start '50'
	option limit '${maxclient}'

config dhcp '${ifname_mesh}'
	option interface '${ifname_mesh}'
	option ignore '1'

EOF

chmod a+x $DHCP

if [ $hs_enable -eq 1 ]
	then
		uci set dhcp.$ifname_hs=dhcp
		uci set dhcp.$ifname_hs.interface=$ifname_hs
		uci set dhcp.$ifname_hs.leasetime=12h
		uci set dhcp.$ifname_hs.start=10
		uci set dhcp.$ifname_hs.limit=$hsMaxClients
		uci commit dhcp
	else
		uci commit dhcp
fi
/etc/init.d/dnsmasq enable
}

configureSnmp()
{
local SNMP="/etc/config/mini_snmpd"
	local snmpEnable	; config_get_bool	snmpEnable	snmp	"Enable" 1
	local snmpContact	; config_get		snmpContact	snmp	"Contact"	"contatti@ninux.org"
	local snmpLocation	; config_get		snmpLocation	snmp	"Location"

	if [ $snmpEnable -eq 1 ]
		then
			snmpEnable="1"
		else	
			snmpEnable="0"
	fi

cat > $SNMP << EOF
#Automatically generated for Eigennet
config mini_snmpd
	option enabled ${snmpEnable}
	option ipv6 ${snmpEnable}
	option community 'public'
	option contact '${snmpContact}'
	option location '${snmpLocation}'

	# enable basic disk usage statistics on specified mountpoint
	list disks '/overlay'
	list disks '/tmp'

	# enable basic network statistics on specified interface
	# 4 interfaces maximum, as named in /etc/config/network
	list interfaces 'loopback'
	list interfaces 'br-lan'
	list interfaces '${ifname_mesh}'

EOF

if [ $hs_enable -eq 1 ]
        then
                uci del mini_snmpd.@mini_snmpd[0].interfaces
                uci set mini_snmpd.@mini_snmpd[0].interfaces=loopback
                uci set mini_snmpd.@mini_snmpd[0].interfaces=br-lan
                uci set mini_snmpd.@mini_snmpd[0].interfaces=${ifname_mesh}
                uci set mini_snmpd.@mini_snmpd[0].interfaces=${ifname_hs}
                uci commit mini_snmpd
        else
                uci commit mini_snmpd
fi

chmod a+x $SNMP
/etc/init.d/mini_snmpd enable
}

configureSplash()
{
#local splah_enable	; config_get_bool	splah_enable	hotspot	"enabled"	0
local SPLASH=/etc/nodogsplash/nodogsplash.conf
if [ $hs_enable -eq 1 ]
	then
		/etc/init.d/nodogsplash enable
		cat > $SPLASH << EOF
#Automatically generated for Eigennet
GatewayInterface ${iface_hs}
FirewallRuleSet authenticated-users {
    FirewallRule allow all
}
FirewallRuleSet preauthenticated-users {
    FirewallRule allow tcp port 53	
    FirewallRule allow udp port 53
    FirewallRule allow udp port 67
}
FirewallRuleSet users-to-router {
    FirewallRule allow udp port 53	
    FirewallRule allow tcp port 53	
    FirewallRule allow udp port 67
    FirewallRule allow tcp port 22
    FirewallRule allow tcp port 23
    FirewallRule allow tcp port 80
    FirewallRule allow tcp port 443
}

EOF
chmod a+x $SPLASH
	else
		/etc/init.d/nodogsplash disable
fi
}

configureUhttpd()
{
	local pointingEnabled           ; config_get_bool pointingEnabled       pointing         "enabled"                0
	local bwClientEnabled           ; config_get_bool bwClientEnabled       bwtestclient     "enabled"                0
	local httpInfoEnabled           ; config_get_bool httpInfoEnabled       httpinfo         "enabled"                0

	if [ $pointingEnabled -eq 0 ] && [ $bwClientEnabled -eq 0 ] && [ $httpInfoEnabled -eq 0 ]
		then
			/etc/init.d/uhttpd disable
		else
			/etc/init.d/uhttpd enable
			uci set      uhttpd.main.listen_http="0.0.0.0:80"
			uci add_list uhttpd.main.listen_http="[::]:80"
	fi
}

configureHttpInfo()
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

configurePointing()
{
	local pointingEnabled           ; config_get_bool pointingEnabled       pointing         "enabled"                0

	[ $pointingEnabled -eq 1 ] && chmod 777 /www/cgi-bin/pointing.cgi
	[ $pointingEnabled -eq 0 ] && chmod 750 /www/cgi-bin/pointing.cgi
}

configureBWTestClient()
{
	local bwClientEnabled           ; config_get_bool bwClientEnabled       bwtestclient     "enabled"                0

	[ $bwClientEnabled -eq 1 ] && chmod 777 /www/cgi-bin/bwtclient.cgi && chmod 777 /www/cgi-bin/startbwt.cgi
	[ $bwClientEnabled -eq 0 ] && chmod 750 /www/cgi-bin/bwtclient.cgi && chmod 750 /www/cgi-bin/startbwt.cgi
}

configureDropbear()
{
	local sshEnabled                ; config_get_bool sshEnabled            sshserver         "enabled"               1
	local passwdAuth                ; config_get_bool passwdAuth            sshserver         "passwdAuth"            1
	local sshAuthorizedKeys         ; config_get      sshAuthorizedKeys     sshserver         "sshAuthorizedKeys"

	if [ $sshEnabled -eq 1 ]
		then
			/etc/init.d/dropbear enable
			echo "$sshAuthorizedKeys" > "/etc/dropbear/authorized_keys" 
			uci set dropbear.@dropbear[0].PasswordAuth=$passwdAuth
		else
			/etc/init.d/dropbear enable
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
		configureOlsrd4
		configureOlsrd6
		configureRadvd
		configureDhcp
		configureSnmp
		configureSplash

		uci set eigennet.general.bootmode=2

		uci commit

		sleep 2s
		reboot

		return 0
	}

	[ $bootmode -ge 2 ] &&
	{
		sysctl -w net.ipv6.conf.all.autoconf=0

		local accept_clients config_get_bool accept_clients network "accept_clients"  1
		[ $accept_clients -eq 1 ] && ip link set dev br-lan up

		local accept_clients  ; config_get_bool accept_clients    network      "accept_clients"   1
		local wifi_clients    ; config_get_bool wifi_clients      wireless     "wifi_clients"     1

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

