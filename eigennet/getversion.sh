#!/bin/sh

TOPDIR="$1"

echo Built $(date) by $(whoami) at $(hostname)
echo
echo "OpenWrt"
echo "`cd $TOPDIR; svn info`"
echo
echo "Feeds"

grep -v '^#' $TOPDIR/feeds.conf | grep src | while read line
do
	echo ""
	srcsvc="$(echo $line | awk '{print $1}' | awk -F- '{print $2}')"
	srcdir="$(echo $line | awk '{print $2}')"
	case "$srcsvc" in
		"svn")
			echo $srcdir
			echo "`cd $TOPDIR/feeds/$srcdir; svn info`"
		;;
		"git")
			echo $srcdir
			echo "URL: $(echo $line | awk '{print $3}')"
			echo "`cd $TOPDIR/feeds/$srcdir; git log -n 1`"
		;;
	esac
done
