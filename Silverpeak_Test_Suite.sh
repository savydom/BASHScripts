#!/bin/sh
tunnel=50
cd /home/scriptid/scripts/BACKUPS
#/usr/bin/script -a Output_from_test.txt
# create encrypted file
#	pktool genkey keystore=file keytype=aes keylen=128 outkey=key
#	encrypt -a aes -k key -i myfile.txt -o secretstuff:

echo "Random text test"
/home/scriptid/scripts/BACKUPS/generate_random_text_traffic.pl $tunnel
echo "Random binary test"
/home/scriptid/scripts/BACKUPS/generate_random_binary_traffic.pl $tunnel
echo "Oracle Redo Log test"
/home/scriptid/scripts/BACKUPS/generate_redolog_traffic.pl $tunnel
echo "Oracle Dump File test"
/home/scriptid/scripts/generate_dmp_traffic.pl $tunnel
echo "Oracle Compressed Dump File test"
/home/scriptid/scripts/BACKUPS/generate_compressed_traffic.pl $tunnel
echo "AFTD Test Data"
/usr/local/bin/sudo /home/scriptid/scripts/BACKUPS/generate_AFTD_traffic.pl $tunnel
