#!/bin/bash
# Extracts MACB Timestamps from mounted NTFS volumes
# https://www.tuxera.com/community/ntfs-3g-advanced/extended-attributes
function extract_macb(){
  tempMACB=$(mktemp)
  cd $INPUT_PATH   
  getfattr -h -e hex -Rn system.ntfs_times_be . 2>/dev/null|grep -v ^$|sed 's|^.*system.ntfs_times_be\=|:|g'|sed 'N;s/\n//' > $tempMACB
  echo "BIRTH,MODIFIED,ACCESSED,CHANGED,PATH/FILE_NAME"
  cat $tempMACB |while read d; 
  do
    FILE_PATH=$(echo "$d"|awk -F':' '{print $2}')
    TIMESTAMPS=$(echo "$d"|awk -F':' '{print $3}'|sed 's/.\{18\}/&:0x/;s/.\{37\}/&:0x/;s/.\{56\}/&:0x/')
    BIRTH=$(echo "$TIMESTAMPS"| awk -F':' '{print $1}' |while read d; do echo $(($d/10000000-11644473600))| awk '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $0}';done)
    MODIFIED=$(echo "$TIMESTAMPS"| awk -F':' '{print $2}' |while read d; do echo $(($d/10000000-11644473600))| awk '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $0}';done)
    ACCESSED=$(echo "$TIMESTAMPS"| awk -F':' '{print $3}' |while read d; do echo $(($d/10000000-11644473600))| awk '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $0}';done)
    CHANGED=$(echo "$TIMESTAMPS"| awk -F':' '{print $4}' |while read d; do echo $(($d/10000000-11644473600))| awk '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $0}';done)
    echo $BIRTH","$MODIFIED","$ACCESSED","$CHANGED","$FILE_PATH
  done
}
INPUT_PATH=$1
[ "$1" == "" ] && echo "USAGE: grabmacb.sh [Path to NTFS Volume]" && exit
extract_macb
