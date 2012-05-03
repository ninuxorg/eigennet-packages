#!/bin/sh

. /usr/lib/eigennet/links.sh

cat <<EOF
<html>
<head>
<script type="text/JavaScript"><!--
function delaiedRefresh()
{
	setTimeout("location.reload(true);",1000);
}
//   -->
</script>
</head>
<body onload="JavaScript:delaiedRefresh()">
<table>
<tr><td>Device</td><td>dBm</td><td>Istogram</td></tr>
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
printf "<tr><td>%s</td><td>%d</td><td width=\"%d\"><div witdh=\"%d\" bgcolor=\"rgb(%d, %d, %d)\">#</div></td></tr>\n", deviceMAC, signal, maxWidth, actWidth, actRed, actGreen, maxBlue }'
cat <<EOF
</table>
</body>
</html>
EOF
