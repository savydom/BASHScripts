#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Passwd Log' > /home/%userprofile%/bin/check_passwd_log.txt
for i in `/usr/bin/cat $HL`
do
    echo "$i" >> /home/%userprofile%/bin/check_passwd_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "egrep '(emerg|holden)' /etc/passwd"
done
