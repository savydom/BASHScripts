echo "Drives"
zpool list
echo "Drives Quota"
zpool list -H | awk '{print$1}' | xargs -i zfs list -o quota {$1}
echo "CPU"
psrinfo -pv
echo "Mem"
prtconf -pv|grep Mem|awk ' { print $3,$4 }'
