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

. /usr/lib/eigennet/links.sh

cat <<EOF
Content-type: text/javascript



function pointingPaint()
{
	myContent='<tr><td style="text-align:center;">Device</td><td style="text-align:center;">dBm</td><td style="text-align:center;">Istogram</td></tr>'
EOF
get_links 20 | awk '{
signal=$1;
deviceMAC=$2;
maxGreen=255;
maxRed=255;
maxBlue=25;
maxSignal=-10;
noiseFloor=-95;
maxWidth=150
actQ=(signal-noiseFloor)/(maxSignal-noiseFloor)
actWidth=10+((maxWidth-10)*actQ)
actGreen=maxGreen*actQ
actRed=maxRed-actGreen
printf "myContent+='"'"'<tr><td>%s</td><td style=\"text-align:right;\">%d</td><td width=\"%d\"><div style=\"width:%d; background-color: rgb(%d, %d, %d);\">#</div></td></tr>'"'"'\n", deviceMAC, signal, maxWidth, actWidth, actRed, actGreen, maxBlue }'
cat <<EOF

document.getElementById("pointingTable").innerHTML=myContent
}

EOF