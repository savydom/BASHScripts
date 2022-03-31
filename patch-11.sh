export PATH=/usr/sbin:/usr/bin
PDATE=`date +%Y%m%d`
pkg update --be-name patch-$PDATE --accept
