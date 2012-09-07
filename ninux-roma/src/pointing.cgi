#!/bin/sh

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