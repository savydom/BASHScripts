#!/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'Passwd Expiration Log' > /home/%userprofile%/bin/check_passwdexp_log.txt
for i in `/usr/bin/cat $HL`
do
    echo "$i" >> /home/%userprofile%/bin/check_passwdexp_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo /home/%userprofile%/bin/expdate.sh | \
       egrep -vi '(root|emerg|oracle|sybase|cognos|mpteci|trancms|sas|tmmca|tfmms|user|sps|webxsys)'" >> /home/%userprofile%/bin/check_passwdexp_log.txt 2>&1
#       egrep -i '(account|root|emerg|oracle|sybase|cognos|mpteci|trancms|sas|tmmca|tfmms|user|sps|webxsys)'" >> /home/%userprofile%/bin/check_passwdexp_log.txt 2>&1
#       egrep -i '(account|billiot|brandt|reed|rodriguez|spragins|zimmermann|crawford)'" >> /home/%userprofile%/bin/check_passwdexp_log.txt 2>&1
    echo >> /home/%userprofile%/bin/check_passwdexp_log.txt
done
