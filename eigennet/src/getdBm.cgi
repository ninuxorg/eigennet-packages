#!/bin/sh

. /usr/lib/eigennet/links.sh

cat <<EOF
Content-type: text/plain

EOF
echo -e "dBm\tStation"
get_links

echo
