#!/bin/bash
## This creates a consolodated BASH history file /var/log/history2

ORIGINAL_USER=`who am i |awk {'print $1'}`
if [ "$USER" = "$ORIGINAL_USER" ];then
  MYUSER=""
else
  MYUSER="(as $USER)"
fi

if [ ! -z "!!" ];then
  export PROMPT_COMMAND="${PROMPT_COMMAND:+$PROMPT_COMMAND ; }"'echo [bash-history] $MYUSER "$(history 1 | cut -c8-)" |logger -p user.debug'
else
  PROMPT_COMMAND=""
fi
