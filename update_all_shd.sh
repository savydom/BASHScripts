#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'SHD Log' > /home/mjohnson/bin/update_all_shd_log.txt
for i in `/usr/bin/cat $HL`
    do
         echo "$i"
         echo "$i" >> /home/mjohnson/bin/update_all_shd_log.txt
         ssh -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i '/usr/local/bin/sudo /usr/bin/bash - "/home/mjohnson/bin/update_shd"' >> /home/mjohnson/bin/update_all_shd_log.txt
    done
