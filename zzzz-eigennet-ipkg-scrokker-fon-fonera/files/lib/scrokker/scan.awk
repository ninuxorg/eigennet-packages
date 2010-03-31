#!/usr/bin/awk -f

#
#Copyright (C) 2010  Gioacchino Mazzurco <gmazzurco89@gmail.com>
#Copyright (C) 2010  art-insite.org
#
#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.
#
#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.
#
#You should have received a copy of the GNU General Public License
#along with this file.  If not, see <http://www.gnu.org/licenses/>.

BEGIN {
	FS="[ :=]+"
	OFS=" "
}

{
	if(match($5, /Address/)){
		BSSID=$6 ":" $7 ":" $8 ":" $9 ":" $10 ":" $11
	}
	if(match($2, /ESSID/)){
		gsub("\"", "", $3)
		ESSID=$3
	}
	if(match($2, /Mode/)){
		MODE=$3
	}
	if(match($2, /Frequency/)){
		CHANNEL=substr($6, 1, length($6)-1)
	}
	if(match($2, /Encryption/)){
		if(match($4, /on/)){
			ENC=1
			ENCTYPE="WEP"
		}else{
			ENC=0
		}
	}
	if(ENC==1 && match($3, /WPA/)){
		if($5==1){
			ENCTYPE=$3
		}else{
			ENCTYPE=$3 $5
		}
	}
	if(ENC==1 && match($2, /Authentication/)){
		ENCTYPE=ENCTYPE "-" $5
	}
	if((match($2, /Cell/) && !match($3, /01/)) || length()==0){
		LIST[i++]=BSSID " " ESSID " " MODE " " CHANNEL " " ENC " " ENCTYPE
	}
}

END {
	for ( e in LIST ){
		print LIST[e]
	}
}
