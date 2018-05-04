#!/bin/bash
# Converts comma separated 5 columnar TLN files with timestamps back to standard TLN Format with epoch time"
# Timestamps must be formatted "YYYY-MM-DD HH:MM:SS" to convert to TLN
[ -f "$1" ] || echo "Usage: csv2tln.sh [TLN CSV File]"
[ -f "$1" ] && cat $1  | while read d; 
do
 timestamp=$(echo $d| awk -F',' '{print $1}'| cut -c -19)
 tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
 tlninfo=$(echo $d| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')  
 echo $tlntime $tlninfo
done
