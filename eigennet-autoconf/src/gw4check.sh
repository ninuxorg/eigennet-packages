#!/bin/sh

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

CONF_DIR="/etc/config/"

. /lib/functions.sh

config_load eigennet

config_get_bool  gw4Enabled      gateway4 "enabled"        0
config_get_bool  strictCheck     gateway4 "strictCheck"    0
config_get       checkInterval   gateway4 "checkInterval"  "10s"
config_get       checkHosts      gateway4 "checkHosts"     "8.8.8.8 8.8.4.4"
config_get       bandwidth       gateway4 "bandwidth"      "5000/512"

while [ $gw4Enabled -eq 1 ]
do
	sleep $checkInterval
	i=0
	failure=0
	for host in $checkHosts
	do
		ping -4 -c 5 -q $host &> /dev/null
		failure=$((failure+$?))
		i=$((i+1))
	done
	
	[ $failure -gt 0  ] &&  [ $strictCheck -eq 1 ] && batctl gw_mode client && continue
	[ $failure -ge $i ] &&                            batctl gw_mode client && continue

	batctl gw_mode server $bandwidth
done
