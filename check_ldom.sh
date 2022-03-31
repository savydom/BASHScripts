#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'LDOM Log' > /home/mjohnson/bin/check_ldom_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/mjohnson/bin/check_ldom_log.txt
         ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i '/usr/local/bin/sudo /usr/sbin/lustatus' >> /home/mjohnson/bin/check_ldom_log.txt
    done
