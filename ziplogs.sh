#!/bin/bash
find *.log -type f -size +1G |xargs -L1 -I file zip file.zip file
