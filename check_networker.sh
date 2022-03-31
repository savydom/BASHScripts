#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Networker Check' > /home/%userprofile%/bin/check_networker_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_networker_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i pkginfo -l LGTOclnt | egrep -i '(pkginst|version)' >> /home/%userprofile%/bin/check_networker_log.txt
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_networker_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo yum -q list installed lgtoclnt" >> /home/%userprofile%/bin/check_networker_log.txt
  else
    echo "$i $OST issues" >> /home/%userprofile%/bin/check_networker_log.txt
  fi
done
