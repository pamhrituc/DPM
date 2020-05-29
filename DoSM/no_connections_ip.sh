#!/bin/sh

src_ip=$1
results=`netstat -ntu -4 -6 | awk '/^tcp/{print $5}' | sed -r 's/[0-9]+$//' | sort | uniq -c | sort -n | grep $src_ip`
echo $results
