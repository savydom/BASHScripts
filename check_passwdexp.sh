#!/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'Passwd Expiration Log' > /home/mjohnson/bin/check_passwdexp_log.txt
for i in `/usr/bin/cat $HL`
do
    echo "$i" >> /home/mjohnson/bin/check_passwdexp_log.txt
    ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i "/usr/bin/sudo /home/mjohnson/bin/expdate.sh | \
       egrep -vi '(root|emerg|oracle|sybase|cognos|mpteci|trancms|sas|tmmca|tfmms|user|sps|webxsys)'" >> /home/mjohnson/bin/check_passwdexp_log.txt 2>&1
#       egrep -i '(account|root|emerg|oracle|sybase|cognos|mpteci|trancms|sas|tmmca|tfmms|user|sps|webxsys)'" >> /home/mjohnson/bin/check_passwdexp_log.txt 2>&1
#       egrep -i '(account|billiotb|brandtg|reedp|rodriguezj|spraginsb|zimmermannl|crawfordc)'" >> /home/mjohnson/bin/check_passwdexp_log.txt 2>&1
    echo >> /home/mjohnson/bin/check_passwdexp_log.txt
done
