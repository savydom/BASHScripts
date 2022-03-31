#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'Crypt Log' > /home/mjohnson/bin/check_crypt_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/mjohnson/bin/check_crypt_log.txt
         ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i grep ALLOW=1 /etc/security/policy.conf >> /home/mjohnson/bin/check_crypt_log.txt
    done
