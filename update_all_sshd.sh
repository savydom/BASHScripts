#!/usr/bin/bash
HL=/home/%currentuser%/bin/hostlist.txt
echo 'SSHD Log' > /home/%currentuser%/bin/update_all_sshd_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l %currentuser% -i /home/%currentuser%/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/%currentuser%/bin/update_all_sshd_log.txt
    ssh -q -l %currentuser% -i /home/%currentuser%/.ssh/id_rsa $i '/usr/local/bin/sudo /usr/bin/bash - /home/%currentuser%/bin/update_sshd' >> /home/%currentuser%/bin/update_all_sshd_log.txt
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/%currentuser%/bin/update_all_sshd_log.txt
    ssh -q -l %currentuser% -i /home/%currentuser%/.ssh/id_rsa $i '/usr/bin/sudo /bin/bash - /home/%currentuser%/bin/RHupdate_sshd' >> /home/%currentuser%/bin/update_all_sshd_log.txt
  fi
done
