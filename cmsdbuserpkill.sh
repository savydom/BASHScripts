ps -ef | grep -i cmsdbuser | grep -vi grep | awk '{print$2}' | xargs -i kill -9 {$1}
