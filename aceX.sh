xhost -
xhost +aceprddb
xhost +acetstdb
xhost +local:
xauth list | nawk '{"hostname" | getline gHost };{if ($0 ~ gHost) print $0}' | xargs -i -t sh -c "sudo su - oracle -c \"/usr/openwin/bin/xauth -vf /export/home/oracle/.Xauthority add {$1}\""
echo "#!/usr/bin/ksh" > /export/home/oracle/acedisplay
echo "export DISPLAY=$DISPLAY" >> /export/home/oracle/acedisplay
echo "xhost -" >> /export/home/oracle/acedisplay
echo "xhost +aceprddb" >> /export/home/oracle/acedisplay
echo "xhost +acetstdb" >> /export/home/oracle/acedisplay
echo "xhost +local:" >> /export/home/oracle/acedisplay
