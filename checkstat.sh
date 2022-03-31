echo "Processors:"
psrinfo -pv
echo "Memory:"
prtconf -pv | grep Mem | awk '{print$3,$4}'
