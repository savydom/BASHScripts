#!/bin/bash
OST=$(uname -s)
if [ $OST == "SunOS" ]; then
  echo "[Account][St][LastChanged][MinPW][MaxPW][Warn][DaysSincePWChange]"
  cut -d: -f1 /etc/passwd | xargs -i passwd -s {$1} | egrep -v '(LK|NL)' | \
   nawk '{yr=0;mo=0;dy=0;pd=$3;\
   split("0_31_59_90_120_151_181_212_243_273_304_334",mary,"_");("date +%m/%d/%y"|getline td);\
   yr=substr(pd,7,2);yr=yr+2000;mo=substr(pd,1,2)+0;\
   dy=substr(pd,4,2)+0;lp=0;for(cy=1970;cy<=yr;cy++){if(((cy%4==0)&&!(cy%100==0))||(cy%400==0))lp++;};\
   yday=(yr-1970)*365;mday=mary[mo];pday=yday+mday+dy+lp-1;\
   yr=substr(td,7,2);yr=yr+2000;mo=substr(td,1,2)+0;\
   dy=substr(td,4,2)+0;lp=0;for(cy=1970;cy<=yr;cy++){if(((cy%4==0)&&!(cy%100==0))||(cy%400==0))lp++;};\
   yday=(yr-1970)*365;mday=mary[mo];tday=yday+mday+dy+lp-1;\
   dif=(tday-pday);print $0,"     ",dif;}'
elif [ $OST == "Linux" ]; then
  echo "[DaysSince][Exp][Date][PasswordUsed or Locked][Account]"
  cut -d: -f1 /etc/passwd | xargs -i passwd -S {$1} | grep -v 99999 | \
   awk '{print "   "$5,$3,$8,$9,$10,$11,$12,$1}' | awk '{yr=0;mo=0;dy=0;lp=0;pd=$2;\
   split("0_31_59_90_120_151_181_212_243_273_304_334",mary,"_");("date +%s"|getline td);\
   yr=strtonum(substr(pd,1,4));mo=strtonum(substr(pd,6,2));\
   dy=strtonum(substr(pd,9,2));for(cy=1970;cy<=yr;cy++){if(((cy%4==0)&&!(cy%100==0))||(cy%400==0))lp++;};\
   yday=(yr-1970)*365;mday=mary[mo];dsec=(yday+mday+dy+lp-1)*86400;\
   dif=(td-dsec)/86400;print dif,$0;}'
else
  echo "Issues"
fi
