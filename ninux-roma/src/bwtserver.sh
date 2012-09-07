#!/bin/sh /etc/rc.common

START=96
STOP=9

CONF_DIR="/etc/config/"

pidFile="/var/run/gw4check.pid"

config_load eigennet

start()
{
	[ -f ${pidFile} ] ||
	{
		config_load      eigennet
		config_get_bool  bwtservernabled      bwtestserver "enabled"  0
		config_get       bootmode             general      "bootmode" 1

		[ $bwtservernabled -eq 1 ] && [ $bootmode -ge 2 ] &&
		{
			while true
			do
				# Simmetric test: Server<->Client
				yes $(seq -s , 1 260) | nc -l -p 5000 &> /dev/null
				# Asimmetric test: Server->Client
				yes $(seq -s , 1 260) | nc -l -p 5001 &> /dev/null
				# Asimmetric test: Server<-Client
				yes $(seq -s , 1 260) | pv -q -L 10 | nc -l -p 5002 &> /dev/null
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
