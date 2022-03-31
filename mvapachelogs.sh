MDATE=`date +%Y%m%d`
cd /usr/local/apache2/logs
mv access_log access_log.$MDATE
mv ssl_request_log ssl_request_log.$MDATE
mv ocsp_request_log ocsp_request_log.$MDATE
mv error_log error_log.$MDATE
touch access_log
touch ssl_request_log
touch ocsp_request_log
touch error_log
chown webadm:staff access_log ssl_request_log ocsp_request_log error_log
chmod 644 access_log ssl_request_log ocsp_request_log error_log
gzip access_log.$MDATE
gzip ssl_request_log.$MDATE
gzip ocsp_request_log.$MDATE
gzip error_log.$MDATE
