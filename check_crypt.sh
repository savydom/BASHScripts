#!/usr/bin/bash
HL=/home/*/bin/hostlist.txt
echo 'Crypt Log' > /home/*/bin/check_crypt_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/*/bin/check_crypt_log.txt
         ssh -l mjohnson -i /home/*/.ssh/id_rsa $i grep ALLOW=1 /etc/security/policy.conf >> /home/*/bin/check_crypt_log.txt
    done
