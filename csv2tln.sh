#!/bin/bash
# Converts comma separated 5 columnar TLN files with timestamps back to standard TLN Format with epoch time"
# http://windowsir.blogspot.com/2009/02/timeline-analysis-pt-iii.html
# Timestamps must be formatted as "YYYY-MM-DD HH:MM:SS" to process
[ -f "$1" ] || echo "Usage: csv2tln.sh [TLN CSV File]"
[ -f "$1" ] && cat $1  | while read d; 
do
 timestamp=$(echo $d| awk -F',' '{print $1}'| grep -E '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
 [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
 tlninfo=$(echo $d| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')  
 [ "$timestamp" != "" ] && echo $tlntime$tlninfo
done
