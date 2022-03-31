ls /usr/local/apache2/logs/*_log | xargs -i -t cp {$1} {$1}.`date '+%Y%m%d%H%M%S'`
ls /usr/local/apache2/logs/*_log | xargs -i -t sh -c "echo '' > {$1}"
ls /usr/local/apache2/logs/*_log.* | grep -v .gz | xargs -i -t gzip {$1}
ls /usr/local/apache2/logs/mod_jk.log.* | grep -v .gz | xargs -i -t gzip {$1}
chown webadm:staff /usr/local/apache2/logs/*
