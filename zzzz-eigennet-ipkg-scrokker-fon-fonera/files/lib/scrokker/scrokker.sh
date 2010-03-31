#!/bin/sh

<<COPYRIGHT

Copyright (C) 2010  Gioacchino Mazzurco <gmazzurco89@gmail.com>
Copyright (C) 2010  art-insite.org

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

. /etc/functions.sh                                                                           

# This method log message in directory set in general.log_dir section of
# /etc/config/scrokker file
log() {
    if [ ! -d $log_dir ]; then                                                          
        mkdir -p $log_dir
    fi
    echo "[$(date +"%d/%m/%y %k:%M:%S")] : $1"
    echo "[$(date +"%d/%m/%y %k:%M:%S")] : ${1}" >> ${log_dir}/scrokker-$(date +"%d%m%y").log
}                                                                   

# Check if wireless is connected
is_connected (){
    if [ "void`route -n | /lib/scrokker/gateway.awk`" != "void" ];
      then
	rm -f $log_dir/test
        wget -O $log_dir/test $test_file > /dev/null 2>&1 &
	sleep 5
        if [ "void`cat $log_dir/test`" == "void$test_key" ];
	  then
	    echo "true"
	    return 0
        fi
	echo "false"
	return 2
    fi
    echo "false"
    return 1
}

# Check if $2 ESSID is friend
is_friend (){
  if [ "`uci get trusted.$2`" == "friend" ]; then
    echo "true"
    return 0
  fi
  echo "false"
  return 1
}

# Check if $2 ESSID is enemy
is_enemy (){
  if [ "`uci get trusted.$2`" == "enemy" ]; then
    echo "true"
    return 0
  fi
  echo "false"
  return 1
}

# Try to connect to selected network
try (){

    if [ "`uci get wireless.@wifi-iface[1]`" != "wifi-iface" ]; then
	log "Creating missing interface"
    	uci add wireless wifi-iface
    fi

    uci set wireless.@wifi-iface[1].device=$device
    uci set wireless.@wifi-iface[1].network=wan
    uci set wireless.@wifi-iface[1].mode=sta
    uci set wireless.@wifi-iface[1].ssid=$2
    uci set wireless.$device.channel=$4

    echo "casing: $LINE -> $6"
    case "$6" in
  	"WEP")
		echo "encription cased as 'WEP'"
  	  	uci set wireless.@wifi-iface[1].encryption='wep'
  	  	uci set wireless.@wifi-iface[1].key=$7
  	;;
  	"WPA-PSK")
		echo "encription cased as 'WPA-PSK'"
  		uci set wireless.@wifi-iface[1].encryption='psk'
		uci set wireless.@wifi-iface[1].key=$7
  	;;
  	"WPA2-PSK")
		echo "encription cased as 'WPA2-PSK'"
  		uci set wireless.@wifi-iface[1].encryption='psk2'
		uci set wireless.@wifi-iface[1].key=$7
  	;;
  	## Missing encription we need to see the output of iwlist to know how to handle this
	# wpa2i (WPA2-EAP)
	# wpa (WPA-EAP)	
	#"")
	#	echo "encription cased as ''"
  	#	uci set wireless.@wifi-iface[1].encryption='none'
	#	uci set wireless.@wifi-iface[1].key=''
	#;;
  	*)
		echo "encription cased as '*'"
		echo "unknown encription '$6' for '$2'"
		uci set wireless.@wifi-iface[1].encryption='none'
		uci set wireless.@wifi-iface[1].key=''
  	;;
    esac
    
    echo "Applying configuration:"
    echo "device:       `uci get wireless.@wifi-iface[1].device`"
    echo "netowrk:      `uci get wireless.@wifi-iface[1].network`"
    echo "mode:         `uci get wireless.@wifi-iface[1].mode`"
    echo "ssid:         `uci get wireless.@wifi-iface[1].ssid`"
    echo "channel:      `uci get wireless.$device.channel`"
    echo "ecryption:    `uci get wireless.@wifi-iface[1].encryption`"
    echo "key:          `uci get wireless.@wifi-iface[1].key`"

    
    /sbin/wifi down
    sleep 2s
    /sbin/wifi up
    sleep 5s
  
    echo "configuration applied `iwconfig`"
}

# Scan all wireless                                                 
scan (){
    echo "scanning"
    echo "before while"
    echo "is_connected == `is_connected`"

    iwlist $scan_ifname scan | /lib/scrokker/scan.awk | grep "Master" | while read LINE && [ "`is_connected`" != "true" ] ; do

	echo "inside while"
	echo "is_connected == `is_connected`"

    	if [ "`is_enemy $LINE`" == "false" ]; then

	  echo "$LINE isn' t enemy"

	  if [ "`echo $LINE | awk -F " " '{print $5}'`" == "0" ];
	    then
	      try $LINE
	    else if [ "`is_friend $LINE`" == "true" ];
	      then

		echo "$LINE is friend"

		essid="`echo $LINE | awk -F " " '{print $2}'`"
		LINE="$LINE `uci get trusted.$essid.key`"

		echo "LINE= $LINE"

		try $LINE
	    fi
	  fi
        fi
    done
}

# The main method
main (){

    config_clear
    config_load scrokker

    # Set initial configuration
    #config_get <variable> <section> [<option> [<default>]]
    config_get scan_interval general scan_interval
    config_get log_dir general log_dir
    config_get device general device
    config_get scan_ifname general scan_ifname
    config_get test_file general test_file
    config_get test_key general test_key

    trap exit 2
    
    while true;
    do
        if [ "`is_connected`" != "true" ]; then
            echo "You are currently not connected..."
            scan
        fi
        sleep $scan_interval
    done
}

log "Starting"

main
