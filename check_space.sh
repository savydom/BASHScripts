#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'Space Log' > /home/mjohnson/bin/check_space_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/mjohnson/bin/check_space_log.txt
         ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i df -ah >> /home/mjohnson/bin/check_space_log.txt
    done
