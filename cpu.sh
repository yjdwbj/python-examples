#!/bin/bash
# memory.sh - Memory usage stats
#
# Copyright 2010 Frode Petterson. All rights reserved.
# See README.rdoc for license.
rrdtool=/usr/bin/rrdtool
db=/home/rrdtool/cpu.rrd
img=/var/www/html
if [ ! -e $db ]
then
$rrdtool create $db \
DS:us:GAUGE:10:0:50000000000 \
DS:sy:GAUGE:10:0:50000000000 \
DS:id:GAUGE:10:0:50000000000 \
DS:wa:GAUGE:10:0:50000000000 \
DS:si:GAUGE:10:0:50000000000 \
RRA:AVERAGE:0.5:1:576 \
RRA:AVERAGE:0.5:6:672 \
RRA:AVERAGE:0.5:24:732 \
RRA:AVERAGE:0.5:144:1460
fi
$rrdtool update $db -t us:sy:id:wa:si `top -n1 | grep "%Cpu" | cut -d ":" -f2 | awk  -F' '  '{"date +%s" | getline d; print d":" $2 ":" $4  ":" $8 ":"  $10 ":" $12  }'`


for period in day week month year
do
$rrdtool graph $img/cpu-$period.png -s -1$period \
-t "CPU Top usage the last $period" -z \
-c "BACK#FFFFFF" -c "SHADEA#FFFFFF" -c "SHADEB#FFFFFF" \
-c "MGRID#AAAAAA" -c "GRID#CCCCCC" -c "ARROW#333333" \
-c "FONT#333333" -c "AXIS#333333" -c "FRAME#333333" \
-h 134 -w 543 -l 0 -a PNG -v "%" \
DEF:us=$db:us:AVERAGE \
DEF:sy=$db:sy:AVERAGE \
DEF:id=$db:id:AVERAGE \
DEF:wa=$db:wa:AVERAGE \
DEF:si=$db:si:AVERAGE  \
VDEF:minus=us,MINIMUM \
VDEF:maxus=us,MAXIMUM \
VDEF:minsy=sy,MINIMUM \
VDEF:maxsy=sy,MAXIMUM \
VDEF:minid=id,MINIMUM \
VDEF:maxid=id,MAXIMUM \
VDEF:minsi=si,MINIMUM \
VDEF:maxsi=si,MAXIMUM \
VDEF:avgus=us,AVERAGE 
done


