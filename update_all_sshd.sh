#!/usr/bin/bash
HL=/home/mjohnson/bin/hostlist.txt
echo 'SSHD Log' > /home/mjohnson/bin/update_all_sshd_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/mjohnson/bin/update_all_sshd_log.txt
    ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i '/usr/local/bin/sudo /usr/bin/bash - /home/mjohnson/bin/update_sshd' >> /home/mjohnson/bin/update_all_sshd_log.txt
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/mjohnson/bin/update_all_sshd_log.txt
    ssh -q -l mjohnson -i /home/mjohnson/.ssh/id_rsa $i '/usr/bin/sudo /bin/bash - /home/mjohnson/bin/RHupdate_sshd' >> /home/mjohnson/bin/update_all_sshd_log.txt
  fi
done
