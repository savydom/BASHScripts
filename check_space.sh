#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Space Log' > /home/%userprofile%/bin/check_space_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i" >> /home/%userprofile%/bin/check_space_log.txt
         ssh -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i df -ah >> /home/%userprofile%/bin/check_space_log.txt
    done
