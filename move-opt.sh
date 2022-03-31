## create new app mountpoint
#zfs create -o mountpoint=/mnt nmpbsdbdev1_data/opt_app
#cd /opt/app
## copy files from /opt/app to new mountpoint
#find . -print | cpio -pdmuv /mnt
#cd /var/tmp
## unmount old /opt/app as mountpoint
#zfs set mountpoint=legacy nmpbsdbdev1_rpoolx/opt_app
## mount new mountpoint as /opt/app
#zfs set mountpoint=/opt/app nmpbsdbdev1_data/opt_app
##

## create new export mountpoint
#zfs create -o mountpoint=/mnt nmpbsdbdev1_data/export_home
#cd /export/home
## copy files from /export/home to new mountpoint
#find . -print | cpio -pdmuv /mnt
#cd /var/tmp
## rename old /export/home dir
#mv /export/home /export/home.old
## mount new mountpoint as /export/home
#zfs set mountpoint=/export/home nmpbsdbdev1_data/export_home
##

## after you verify /opt/app files remove old /opt/app mountpoint
#zfs destroy nmpbsdbdev1_rpoolx/opt_app
## after you verify /export/home files remove old /export/home.old dir
#rm -r /export/home.old
##
