cd /etc/rc3.d
/etc/init.d/accm stop
mv S11accm xS11accm
mv K11accm xK11accm
rm S??accm K??accm
mv xK11accm K11accm
mv xS11accm S11accm
/etc/init.d/accm start
