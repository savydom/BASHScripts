#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Crypt Log' > /home/%userprofile%/bin/check_crypt_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/%userprofile%/bin/check_crypt_log.txt
         ssh -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i grep ALLOW=1 /etc/security/policy.conf >> /home/%userprofile%/bin/check_crypt_log.txt
    done
