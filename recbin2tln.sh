#!/bin/bash
# http://linuxsleuthing.blogspot.ae/2009/10/processing-vista-recyclebin.html
# https://github.com/keydet89/Tools/blob/master/source/recbin.pl
# Read "$I" entries from mounted NTFS volume's $Recycle.Bin and extracts to TLN with epoch "-e" or timestamp "default"
find $1/\$Recycle.Bin -type f 2>/dev/null|grep "\/\$I"|sed 's|^\./||'|while read d; 
  do  
    name=$(strings -el -f $d)
    name=${name#*$1/}
    hexsize=$(cat "$d"|xxd -s8 -l8 -ps|sed -e 's/[0]*$//g'|awk '{print "0x"$0}')
    size=$(echo $(($hexsize)))
    hexdate=$(cat "$d" |xxd -s16 -l8 -ps| awk '{gsub(/.{2}/,"& ")}1'|awk '{for(i=NF;i>0;i--)printf "%s",$i}'&& echo "")
    epoch=$(echo $(((0x$hexdate/10000000)-11644473600)))
    date=$(date -d @$epoch +"%Y-%m-%d %H:%M:%S")
    [ "$2" == "" ] && echo "$date,Recycle,,,[Deleted] "$name  "FILESIZE:$size"
    [ "$2" == "-e" ] && echo "$epoch|Recycle|||[Deleted] "$name  "FILESIZE:$size"
  done
 [ "$(sudo ls -A $1/\$Recycle.Bin 2>/dev/null)" ] || echo "Usage: recbin2tln.sh [path to Windows root directory] [-e]"