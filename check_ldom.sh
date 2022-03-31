#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'LDOM Log' > /home/%userprofile%/bin/check_ldom_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/%userprofile%/bin/check_ldom_log.txt
         ssh -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i '/usr/local/bin/sudo /usr/sbin/lustatus' >> /home/%userprofile%/bin/check_ldom_log.txt
    done
