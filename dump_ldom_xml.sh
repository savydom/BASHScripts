#####################################################
#
# dump_ldom_xml.sh
#
# This script is run via cron on the ldom controllers
#
#####################################################

/usr/sbin/ldm ls |grep -v NAME |grep -v primary|grep -v secondary |while read ldom rest
do
	/usr/sbin/ldm ls-constraints -x $ldom > /home/%userprofile%/LDOMS/COOP/"$ldom".xml
done
