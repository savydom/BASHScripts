#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Samba Check' > /home/%userprofile%/bin/check_samba_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_samba_log.txt
    OSR=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -r")
    if [ $OSR == "5.10" ]; then
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i showrev -p | grep '^Patch: 119757-4' | egrep '(757-42|757-43)' | /usr/bin/awk '{print$1$2}' >> /home/%userprofile%/bin/check_samba_log.txt
    elif [ $OSR == "5.11" ]; then
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i 'pkg list -H --no-refresh | grep -i samba' >> /home/%userprofile%/bin/check_samba_log.txt
    fi
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_samba_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo yum -q list installed samba" >> /home/%userprofile%/bin/check_samba_log.txt
  else
    echo "$i $OST issues" >> /home/%userprofile%/bin/check_samba_log.txt
  fi
done
