PATH=/usr/sbin:/usr/bin
export PATH
rm /var/tmp/patchlist
echo "Analyzing..."
smpatch set patchpro.report.motd.messages=false
smpatch set patchpro.patch.source=http://192.168.119.5:3816
smpatch analyze > /var/tmp/patchlist

###
### Check if no patches are required.
###
OK=`egrep -c "No patches required." /var/tmp/patchlist`
if [ "$OK" -eq 1 ]
then
  echo "No patches required."
  exit 0
fi

# Production servers only apply patches that have been downloaded already
rm /var/tmp/patch-apply
for i in `cat /var/tmp/patchlist |cut -d " " -f1`
do
	if [ -f /net/192.168.104.149/jumpstart/patch/sparc/$i".zip" ]
#        if [ -f /net/sscmgt1/jumpstart/patch/sparc/$i".zip" ]
#        if [ -f /net/192.168.14.150/export/home/patch/$i".zip" ]
#        if [ -f /net/sdmgt1/export/home/patch/$i".zip" ]
	then
        	echo $i >> /var/tmp/patch-apply
	fi
done
rm /var/tmp/patchorder
smpatch order -d /net/192.168.104.149/jumpstart/patch/sparc -xidlist=/var/tmp/patch-apply > /var/tmp/patchorder
#smpatch order -d /net/sscmgt1/jumpstart/patch/sparc -xidlist=/var/tmp/patch-apply > /var/tmp/patchorder
#smpatch order -d /net/192.168.14.150/export/home/patch/ -xidlist=/var/tmp/patch-apply > /var/tmp/patchorder
#smpatch order -d /net/sdmgt1/export/home/patch/ -xidlist=/var/tmp/patch-apply > /var/tmp/patchorder

if [ -f /var/tmp/patch-apply ]
then
     cat /var/tmp/patchorder
else
     echo "Patches found are not already installed in Test."
fi
