cd /var/sadm/pkg/
find -H ./ | grep obsolete.Z | xargs -i -t rm {$1}
