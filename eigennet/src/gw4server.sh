#!/bin/sh /etc/rc.common

START=96
STOP=9

CONF_DIR="/etc/config/"

pidFile="/var/run/gw4check.pid"

start()
{
	[ -f ${pidFile} ] ||
	{
		config_load eigennet
		config_get_bool  gw4Enabled      gw4server "enabled"  0
		config_get       bootmode        general  "bootmode" 1

		[ $gw4Enabled -eq 1 ] && [ $bootmode -ge 2 ] &&
		{
			config_get_bool  strictCheck     gw4server "strictCheck"    0
			config_get       checkInterval   gw4server "checkInterval"  "10s"
			config_get       checkHosts      gw4server "checkHosts"     "8.8.8.8 8.8.4.4"
			config_get       bandwidth       gw4server "bandwidth"      "5000/512"

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
	}
}

restart()
{
	stop
	sleep 2s
	start
}
