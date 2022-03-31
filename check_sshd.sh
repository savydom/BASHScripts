#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'SSHD Log' > /home/mjohnson/bin/upcheck_sshd_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i"
         echo "$i" >> /home/mjohnson/bin/check_sshd_log.txt
         ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i '/usr/bin/sudo /usr/bin/egrep "(oracle|young|williams|walga|bari|kocha)" /etc/ssh/sshd_config' >> /home/mjohnson/bin/check_sshd_log.txt
    done
