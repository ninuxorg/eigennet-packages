#!/bin/sh 

echo "Content-type: text/javascript

function bwtPaint()
{
	document.getElementById('BWTsimmetric').innerHTML='$(awk -F[ '{print $2}' /tmp/bwtsimc | awk -F] '{print $1}')&#8593; &#8595;$(awk -F[ '{print $2}' /tmp/bwtsims | awk -F] '{print $1}')'
	document.getElementById('BWTasimSC').innerHTML='$(awk -F[ '{print $2}' /tmp/bwtasims | awk -F] '{print $1}')&#8595;'
	document.getElementById('BWTasimCS').innerHTML='$(awk -F[ '{print $2}' /tmp/bwtasimc | awk -F] '{print $1}')&#8593;'
}
"
