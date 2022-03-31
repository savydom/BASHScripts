xhost -
xhost +jalisdbprd
xhost +jalisdbtst
xhost +jalisdbdev
xhost +local:
xauth list | gawk '{"hostname" | getline gHost };{if ($0 ~ gHost) print $0}' | xargs -i -t sh -c "sudo su - oracle -c \"/usr/bin/xauth -vf /export/home/oracle/.Xauthority add {$1}\""
echo "#!/usr/bin/csh" > /export/home/oracle/jalisdisplay
echo "setenv DISPLAY $DISPLAY" >> /export/home/oracle/jalisdisplay
echo "xhost -" >> /export/home/oracle/jalisdisplay
echo "xhost +jalisdbprd" >> /export/home/oracle/jalisdisplay
echo "xhost +jalisdbtst" >> /export/home/oracle/jalisdisplay
echo "xhost +jalisdb" >> /export/home/oracle/jalisdisplay
echo "xhost +local:" >> /export/home/oracle/jalisdisplay
