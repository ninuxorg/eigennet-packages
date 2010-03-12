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

function start()
{

  wlanconfig ath0 create wlandev wifi0 wlanmode sta nosbeacon
  wpa_supplicant -Dwext -iath0 -c/etc/wpa_supplicant.conf >/dev/null 2>/dev/null &
  dhcpcd ath0
  iptables -t nat -A POSTROUTING -o ath0 -j MASQUERADE
  
  exit 0
}

function stop()
{
  echo "$0 stop does nothing"
  exit 0
}
