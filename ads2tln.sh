#!/bin/bash
# https://tuxera.com/forum/viewtopic.php?f=2&t=10621
# Extract Alternate Data Streams from a mounted NTFS Volume 
clear
cd $1
tempADS=$(mktemp)
getfattr -Rn ntfs.streams.list . 2>/dev/null |grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'|while read d; do printf %s "$d"|sed 's/.*# file: /\"\n"/g'|sed 's/"//g'>>$tempADS;done
[ "$2" != "-e" ] && cat $tempADS |while read d; do a="$(stat --format "%z" "$1/$d" 2>/dev/null)" && echo "$a,ADS,,,[ADS]: /$d";done
[ "$2" == "-e" ] && cat $tempADS |while read d; do a="$(stat --format "%Z" "$1/$d" 2>/dev/null)" && echo "$a|ADS|||[ADS]: /$d";done
rm $tempADS
[ "$(sudo ls -A $1)" ] || echo "Usage: ads2tln.sh [path to Windows directory] [-e]"
