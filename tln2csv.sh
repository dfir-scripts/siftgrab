#!/bin/bash
# http://windowsir.blogspot.com/2009/02/timeline-analysis-pt-iii.html
# Converts comma separated 5 columnar TLN files with timestamps back to standard TLN Format with epoch time"
# Timestamps must be formatted "YYYY-MM-DD HH:MM:SS" to convert to TLN
[ -f "$1" ] || echo "Usage: tln2csv.sh [TLN File]"
[ -f "$1" ] && cat $1  | while read d; 
  do
    echo "$d" |grep -E '^0\|'|awk -F'|' 'NF >= 5' |awk -F'|' '{print "1970-01-01 00:00:00,"$2","$3","$4","$5}'
    echo "$d" |grep -E '^[0-9]{10}'|awk -F'|' 'NF >= 5' |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'
  done
