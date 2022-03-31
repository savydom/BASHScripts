find /opt/jboss/standalone/log/ -name 'server.log.2*' -a ! \( -mtime -31 \) -print | xargs -i rm {$1}
ls /opt/jboss/standalone/log/server.log.2* | xargs -i gzip {$1}
