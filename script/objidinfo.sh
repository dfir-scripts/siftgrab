#!/bin/bash
# Extracts Object ID and extended attribute information from mounted NTFS volumes
# https://www.tuxera.com/community/ntfs-3g-advanced/extended-attributes

function extract_objid(){
  cd $INPUT_PATH   
  getfattr -h -e hex -Rn system.ntfs_object_id . 2>/dev/null| sed 's|^.*system.ntfs\_object_id\=0x|:|g'|grep :|sed "s/.*# file: //"|sed 'N;s/\n//'  >/tmp/objid.tmp
  echo "OBJECT_ID,BIRTH_VOLUME_ID,BIRTH_OBJECT_ID,DOMAIN_ID,PATH/FILE_NAME,BIRTH,MODIFIED,ACCESSED,CHANGED,DOS_NAME"
  cat /tmp/objid.tmp |while read d; 
  do
    FILE_PATH=$(echo "$d"|awk -F':' '{print $1}')
    OBJID=$(echo "$d"|awk -F':' '{print $2}'|sed 's/.\{32\}/&,/;s/.\{65\}/&,/;s/.\{98\}/&,/')
    TIMESTAMPS=$(echo "$FILE_PATH"|while read d; do getfattr -h -e hex -n system.ntfs_times_be "$d" 2>/dev/null | grep "="|awk -F'=' '{print $2}'|sed 's/.\{18\}/&,0x/;s/.\{37\}/&,0x/;s/.\{56\}/&,0x/';done)
    BIRTH=$(echo "$TIMESTAMPS"|	while read d; do awk -F',' '{print $1}'|date -d @$(($d/10000000-11644473600));done)
    MODIFIED=$(echo "$TIMESTAMPS"| while read d; do awk -F',' '{print $2}'| date -d @$(($d/10000000-11644473600));done)
    ACCESSED=$(echo "$TIMESTAMPS"| while read d; do awk -F',' '{print $3}'| date -d @$(($d/10000000-11644473600));done)
    CHANGED=$(echo "$TIMESTAMPS"| while read d; do awk -F',' '{print $4}' | date -d @$(($d/10000000-11644473600));done)
    DOS_NAME=$(echo "$FILE_PATH"|while read d; do getfattr -h -n system.ntfs_dos_name "$d" 2>/dev/null| awk -F'=' '{print $2}'|xargs printf %s"\n";done)
    echo "$OBJID","$FILE_PATH","$BIRTH","$MODIFIED","$ACCESSED","$CHANGED","$DOS_NAME"
  done
}
INPUT_PATH=$1
[ "$1" == "" ] && echo "USAGE: objectidinf.sh [Path to NTFS Volume]" && exit
extract_objid
