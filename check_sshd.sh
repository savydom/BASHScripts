#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'SSHD Log' > /home/%userprofile%/bin/upcheck_sshd_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i"
         echo "$i" >> /home/%userprofile%/bin/check_sshd_log.txt
         ssh -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i '/usr/bin/sudo /usr/bin/egrep "(oracle|young|williams|walga|bari|kocha)" /etc/ssh/sshd_config' >> /home/%userprofile%/bin/check_sshd_log.txt
    done
