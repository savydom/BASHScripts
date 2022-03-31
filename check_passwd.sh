#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'Passwd Log' > /home/mjohnson/bin/check_passwd_log.txt
for i in `/usr/bin/cat $HL`
do
    echo "$i" >> /home/mjohnson/bin/check_passwd_log.txt
    ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i "egrep '(emerg|holden)' /etc/passwd"
done
