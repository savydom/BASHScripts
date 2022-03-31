#!/usr/bin/bash
HL=/home/%userprofile%/bin/hostlist.txt
echo 'Splunk Check' > /home/%userprofile%/bin/check_splunk_log.txt
for i in `/usr/bin/cat $HL`
do
  OST=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -s")
  if [ $OST == "SunOS" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_splunk_log.txt
    OSR=$(ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "uname -r")
    if [ $OSR == "5.10" ]; then
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i pkginfo splunkforwarder >> /home/%userprofile%/bin/check_splunk_log.txt
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "sudo cat /opt/splunkforwarder/etc/system/local/inputs.conf /opt/splunkforwarder/etc/apps/nola_all_deploymentclient/local/deploymentclient.conf | grep -v '^#'" >> /home/%userprofile%/bin/ check_splunk_log.txt
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i ps -ef | grep splunk | grep -v grep >> /home/%userprofile%/bin/check_splunk_log.txt
    elif [ $OSR == "5.11" ]; then
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i pkg list -H --no-refresh splunkforwarder >> /home/%userprofile%/bin/check_splunk_log.txt
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo cat /opt/splunkforwarder/etc/system/local/inputs.conf /opt/splunkforwarder/etc/apps/nola_all_deploymentclient/local/deploymentclient.conf | grep -v '^#'" >> /home/%userprofile%/bin/check_splunk_log.txt
      ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i ps -ef | grep splunk | grep -v grep >> /home/%userprofile%/bin/check_splunk_log.txt
    fi
  elif [ $OST == "Linux" ]; then
    echo "$i" >> /home/%userprofile%/bin/check_splunk_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo yum -q list installed splunkforwarder" >> /home/%userprofile%/bin/check_splunk_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i "/usr/bin/sudo cat /opt/splunkforwarder/etc/system/local/inputs.conf /opt/splunkforwarder/etc/apps/nola_all_deploymentclient/local/deploymentclient.conf | grep -v '^#'" >> /home/%userprofile%/bin/check_splunk_log.txt
    ssh -q -l %userprofile% -i /home/%userprofile%/.ssh/id_rsa $i '/usr/bin/sudo ps -ef | grep splunk | grep -v grep' >> /home/%userprofile%/bin/check_splunk_log.txt
  else
    echo "$i $OST issues" >> /home/%userprofile%/bin/check_splunk_log.txt
  fi
done
