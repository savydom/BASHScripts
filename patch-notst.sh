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

for i in `cat /var/tmp/patchlist |cut -d" " -f1`
do
        echo downloading $i
        if [ ! -f /net/192.168.104.149/jumpstart/patch/sparc/$i".zip" ]
	then
        smpatch download -d /net/192.168.104.149/jumpstart/patch/sparc -i $i
	fi

#        if [ ! -f /net/sscmgt1/jumpstart/patch/sparc/$i".zip" ]
#	 then
#        smpatch download -d /net/sscmgt1/jumpstart/patch/sparc -i $i
#	 fi

#        if [ ! -f /net/192.168.14.150/export/home/patch/$i".zip" ]
#	 then
#        smpatch download -d /net/192.168.14.150/export/home/patch/ -i $i
#        fi

#        if [ ! -f /net/sdmgt1/export/home/patch/$i".zip" ]
#	 then
#        smpatch download -d /net/sdmgt1/export/home/patch/ -i $i
#        fi
done
# let verify we have all the patches
for i in `cat /var/tmp/patchlist|cut -d" " -f1`
do
        if [ ! -f /net/192.168.104.149/jumpstart/patch/sparc/$i".zip" ]
#        if [ ! -f /net/sscmgt1/jumpstart/patch/sparc/$i".zip" ]
#        if [ ! -f /net/192.168.14.150/export/home/patch/$i".zip" ]
#        if [ ! -f /net/sdmgt1/export/home/patch/$i".zip" ]
        then
                echo "Missing patch $i"
                exit
        fi
done
smpatch order -d /net/192.168.104.149/jumpstart/patch/sparc -xidlist=/var/tmp/patchlist > /var/tmp/patchorder
#smpatch order -d /net/sscmgt1/jumpstart/patch/sparc -xidlist=/var/tmp/patchlist > /var/tmp/patchorder
#smpatch order -d /net/192.168.14.150/export/home/patch/ -xidlist=/var/tmp/patchlist > /var/tmp/patchorder
#smpatch order -d /net/sdmgt1/export/home/patch/ -xidlist=/var/tmp/patchlist > /var/tmp/patchorder

cat /var/tmp/patchorder

# create new liveupgrade boot environment
PDATE=`date +%Y%m%d`
lucreate -n patch-$PDATE

smpatch add -d /net/192.168.104.149/jumpstart/patch/sparc -b patch-$PDATE -xidlist=/var/tmp/patchorder
#smpatch add -d /net/sscmgt1/jumpstart/patch/sparc -b patch-$PDATE -xidlist=/var/tmp/patchorder
#smpatch add -d /net/192.168.14.150/export/home/patch -b patch-$PDATE -xidlist=/var/tmp/patchorder
#smpatch add -d /net/sdmgt1/export/home/patch -b patch-$PDATE -xidlist=/var/tmp/patchorder
