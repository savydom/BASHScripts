#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Package Check' > /home/%userprofile%/bin/check_install_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_install_log.txt
    OSR=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -r")
    if [ $OSR == "5.10" ]; then
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i pkginfo | egrep -i '(splunk|lgto|moz|samba|j6|j7|j8)' >> /home/%userprofile%/bin/check_install_log.txt
    elif [ $OSR == "5.11" ]; then
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i pkg list -H --no-refresh | egrep -i '(splunk|lgto|fox|samba|jre|jdk)' >> /home/%userprofile%/bin/check_install_log.txt
    fi
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_install_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo yum -q list installed | egrep -i '(splunk|networker|fox|samba|jdk|jre)'" >> /home/%userprofile%/bin/check_install_log.txt
  else
    echo "$i $OST issues" >> /home/%userprofile%/bin/check_install_log.txt
  fi
done
