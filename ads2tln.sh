#!/bin/bash
# https://tuxera.com/forum/viewtopic.php?f=2&t=10621
# Extract Alternate Data Streams and Birth(crtime) timestamps from a mounted NTFS Volume 
[ "$(sudo ls -A "$1")" ] || echo "Usage: ads2tln.sh [path to mounted NTFS Volume] [-e]"
clear
tempADS=$(mktemp)
cd "$1"
# Traverse volume and extract Alternata Data Streams and store in a temp directory as /path/file_name:ADS_name
getfattr -Rn ntfs.streams.list . 2>/dev/null |grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'|while read d; 
do 
    printf %s "$d"|sed 's/.*# file: /\"\n"/g'|sed 's/"//g'|sed 's/^$//'>>$tempADS;
done

#Read through file created (tempADS)
cat $tempADS 2>/dev/null| while read d; 
do
    # set variable for file containing ADS
    filepath=$(echo "$d" |sed 's/\(.*\):.*/\1/')
    # Use the getfattr command to extract Birth time(crtime)
    crtime=$(getfattr -h -e hex -n system.ntfs_times_be "$filepath" 2>/dev/null| grep '=' | sed -e 's/^.*=\(0x................\).*$/\1/')
    # Convert timestamps from Windows epoch time to readable timestamp (e.g. 1970-01-01 00:00:00)
    [ "$2" != "-e" ] && [ "$crtime" != "" ] && timestamp=$(echo $(($crtime/10000000-11644473600))| awk '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $0}')
    # Convert timestamps from Windows epoch time to Unix epoch time
    [ "$2" == "-e" ] && [ "$crtime" != "" ] && timestamp=$(echo $(($crtime/10000000-11644473600)))
    # Provide a null value for timestamps calculation errors 
    [ "$2" != "-e" ] && [ "$timestamp" == "" ] && timestamp="1970-01-01 00:00:00"
    [ "$2" == "-e" ] && [ "$timestamp" == "" ] && timestamp="0000000000"
    # Print results to stdout based on command line 
    [ "$2" != "-e" ] && [ "$filepath" != "" ] && echo "$timestamp,ADS,,,[ADS]: /$d"
    [ "$2" == "-e" ] && [ "$filepath" != "" ] && echo "$timestamp|ADS|||[ADS]: /$d"
done
rm $tempADS