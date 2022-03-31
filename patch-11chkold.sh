export PATH=/usr/sbin:/usr/bin
pkg list -u
printf "%50s %30s %30s\n" "Package" "Current Version" "Available Version"
pkg list -u | xargs -i echo {$1} | xargs -i nawk '{u="";("pkg list -Hn "$1 | getline u);close("pkg list -Hn "$1); \
n=split(u,o," ");printf("%50s %30s %30s\n", $1, $2, o[2]);}'
