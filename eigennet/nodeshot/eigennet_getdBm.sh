#!/bin/bash

HOST="$1"
USER="$2"
KEYFILE="$3"

HOST="2001:1418:1a9:eeab:0:15:6d7b:9708"
USER="root"
KEYFILE="/home/gioacchino/.ssh/nodi_rsa"

ISTANCEPATH="/tmp/ssh_nodeshot_${USER}_at_$( echo ${HOST} | tr -d : )"
CONFILE=${ISTANCEPATH}.conf

echo "
ControlMaster auto
ControlPath ${ISTANCEPATH}
ControlPersist 60
ServerAliveInterval 10
ConnectTimeout 20
CheckHostIP no
VerifyHostKeyDNS no
StrictHostKeyChecking no
#BatchMode yes
IdentityFile ${KEYFILE}
User ${USER}
" > ${CONFILE}

SSH_SHOT="ssh -F ${CONFILE} ${HOST}"

#${SSH_SHOT} "echo pippo"

${SSH_SHOT} ". /usr/lib/eigennet/links.sh && get_links"
