#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'Networker Check' > /home/mjohnson/bin/check_networker_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/mjohnson/bin/check_networker_log.txt
    ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i pkginfo -l LGTOclnt | egrep -i '(pkginst|version)' >> /home/mjohnson/bin/check_networker_log.txt
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/mjohnson/bin/check_networker_log.txt
    ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i "/usr/bin/sudo yum -q list installed lgtoclnt" >> /home/mjohnson/bin/check_networker_log.txt
  else
    echo "$i $OST issues" >> /home/mjohnson/bin/check_networker_log.txt
  fi
done
