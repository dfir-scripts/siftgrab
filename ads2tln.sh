#!/bin/bash
# https://medium.com/@stdout_/accessing-ntfs-extended-attributes-from-linux-f79552947981
# https://tuxera.com/forum/viewtopic.php?f=2&t=10621
# Extracts Alternate Data Streams, MACB timestamps as a TLN from NTFS Volumes 
export TZ='Etc/UTC'
function ADS_extract(){
  
    #  scan mounted NTFS disk for Alternate Data Streams
	getfattr -n ntfs.streams.list $ntfs_dir  >/dev/null 2>/dev/null || (echo $usage; exit)
    getfattr -Rn ntfs.streams.list . 2>/dev/null | \
    grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'| \
    sed 's/.*# file: //'|sed 's/"$//g'|paste -d "" - -|grep -v :$ | while read ADS_file; 
    do 
      base_file=$(echo "$ADS_file"|sed 's/:.*//')
      crtime=$(getfattr -h -e hex -n system.ntfs_times_be "$base_file" 2>/dev/null|grep "="|awk -F'=' '{print $2}'|grep -o '0x................')
      epoch_time=$(echo $(($crtime/10000000-11644473600)))
	  hr_time=$(echo $(($crtime/10000000-11644473600))| awk '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $0}')
      [ $epoch_time ] || epoch_time="0000000000"
      #[ $hr_time !="" ] || hr_time="1970-01-01 00:00:00"
	  [ "$output" != "csv" ] && time_stamp=$epoch_time || time_stamp=$hr_time
	  MAC=$(stat --format=%y,%x,%z "$base_file" 2>/dev/null) 
      [ "$ADS_file" ] && echo "$time_stamp|ADS|$comp_name||[ADS Created]: $ADS_file [MAC]: $MAC"|grep -va "ntfs.streams.list\="|tee -a $tempfile
    done
}

usage="Usage: ads2tln.sh [path to mounted NTFS Volume] [-c]  (for CSV output)"
[ "$(ls -A "$1" 2>/dev/null)" ] || $usage
[ "$2" == "-c" ] && output="csv" 
ntfs_dir=$1
cd $ntfs_dir
ADS_extract
