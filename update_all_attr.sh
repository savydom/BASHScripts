#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'USER_ATTR Log' > /home/mjohnson/bin/update_all_attr_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i"
         echo "$i" >> /home/mjohnson/bin/update_all_attr_log.txt
         ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i '/usr/local/bin/sudo /usr/bin/bash - "/home/mjohnson/bin/update_attr"' >> /home/mjohnson/bin/update_all_attr_log.txt
    done
