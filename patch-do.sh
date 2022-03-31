#!/usr/bin/bash
PATH=/usr/sbin:/usr/bin:$PATH
export PATH
WDT=$(which date); WHT=$(which hostname)
OSH=$($WHT); OST=$(uname -s); #OSR=$(uname -r)
OSR=`uname -r | awk -F. '{print$NF}'`
if [[ $OSR != "el5" ]]; then
  OSH=$(echo ${OSH^^})
fi
OSD=$($WDT -u '+%y%m%d_%H%M%S')
OSN=$OSH"_"$OSD"_"$OST"_"$OSR
ii=0
echo '[[         Patch Log          ]]' > /home/scriptid/Logs/Patching/$OSN
echo '[[ '$OSH' ]]'
echo '[[ '$OSH' ]]' >> /home/scriptid/Logs/Patching/$OSN
find /home/scriptid/Logs/Patching/ -name $OSH"*" ! \( -mtime -30 \) | \
xargs -i -t rm -f {$1} >> /home/scriptid/Logs/Patching/$OSN 2>&1
if [[ $OST == "SunOS" ]]; then
  if [[ $OSR == "11" ]]; then
    echo '[[        Pruning BEs         ]]' >> /home/scriptid/Logs/Patching/$OSN
    beadm list >> /home/scriptid/Logs/Patching/$OSN 2>&1
    BEL=($(beadm list -H | awk -F\; '($3==""&&$4==""){print$7":"$1}' | sort -n | awk -F: '{print$2}'))
    for ((ii=0; ii<${#BEL[@]}-1; ++ii)); do
      beadm destroy -F ${BEL[$ii]} >> /home/scriptid/Logs/Patching/$OSN 2>&1
    done
    beadm list >> /home/scriptid/Logs/Patching/$OSN 2>&1
    echo '[[                            ]]' >> /home/scriptid/Logs/Patching/$OSN
    echo '[[Resetting AutoFS & Publisher]]' >> /home/scriptid/Logs/Patching/$OSN
    svcadm restart autofs >> /home/scriptid/Logs/Patching/$OSN 2>&1
    pkg unset-publisher solaris >> /home/scriptid/Logs/Patching/$OSN 2>&1
#    pkg set-publisher -g file:///net/sscmgt5/export/home/repo solaris >> /home/scriptid/Logs/Patching/$OSN 2>&1
    pkg set-publisher -G '*' -M '*' -g http://sscmgt5:10000/ solaris >> /home/scriptid/Logs/Patching/$OSN 2>&1
    echo '[[                            ]]' >> /home/scriptid/Logs/Patching/$OSN
    echo '[[    Checking - Patching     ]]' >> /home/scriptid/Logs/Patching/$OSN
#    pkg update -nv >> /home/scriptid/Logs/Patching/$OSN 2>&1
    pkg update -v --accept >> /home/scriptid/Logs/Patching/$OSN 2>&1
  elif [[ $OSR == "10" ]]; then
    echo '[[        Listing BEs         ]]' >> /home/scriptid/Logs/Patching/$OSN
    lustatus >> /home/scriptid/Logs/Patching/$OSN 2>&1
    rm /var/tmp/patchlist
    echo '[[                            ]]' >> /home/scriptid/Logs/Patching/$OSN
    echo '[[  Setting SMPatch settings  ]]' >> /home/scriptid/Logs/Patching/$OSN
    #smpatch set patchpro.report.motd.messages=false >> /home/scriptid/Logs/Patching/$OSN 2>&1
    #smpatch set patchpro.patch.source=http://192.168.119.5:3816 >> /home/scriptid/Logs/Patching/$OSN 2>&1
    echo '[[                            ]]' >> /home/scriptid/Logs/Patching/$OSN
    echo '[[    Checking - Patching     ]]' >> /home/scriptid/Logs/Patching/$OSN
    smpatch analyze > /var/tmp/patchlist
    cat /var/tmp/patchlist >> /home/scriptid/Logs/Patching/$OSN
  fi
elif [[ $OST == "Linux" ]]; then
    echo '[[   Checking subscriptions   ]]' >> /home/scriptid/Logs/Patching/$OSN
    echo '[[    Checking - Patching     ]]' >> /home/scriptid/Logs/Patching/$OSN
    package-cleanup -y --oldkernels --count=2 >> /home/scriptid/Logs/Patching/$OSN 2>&1
    yum clean all >> /home/scriptid/Logs/Patching/$OSN 2>&1
    yum -y update >> /home/scriptid/Logs/Patching/$OSN 2>&1
else
    echo '[[ Some kind of error message ]]' >> /home/scriptid/Logs/Patching/$OSN
fi
if [ -f /home/scriptid/Logs/Patching/$OSN ]; then
  chmod 644 /home/scriptid/Logs/Patching/$OSN
  ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa 192.168.104.39 mailx -s $OSN mark.d.johnson5.ctr@navy.mil,authur.groteguth.ctr@navy.mil < /home/scriptid/Logs/Patching/$OSN
#  ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa sscmail mailx -s $OSN mark.d.johnson5.ctr@navy.mil,authur.groteguth.ctr@navy.mil < /home/scriptid/Logs/Patching/$OSN
fi
