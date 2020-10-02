#!/bin/bash
# bash only windows $recycle bin parser
# http://linuxsleuthing.blogspot.ae/2009/10/processing-vista-recyclebin.html
# Reads "$I" entries from mounted NTFS volume's $Recycle.Bin and extracts to TLN with epoch "-e" or timestamp "default"
find $1/\$Recycle.Bin -type f 2>/dev/null|grep "\/\$I"|sed 's|^\./||'|while read d; 
  do  
    name=$(strings -el -f $d)
    name=${name#*$1/}
    hexsize=$(cat "$d"|xxd -s8 -l8 -ps|sed -e 's/[0]*$//g'|awk '{print "0x"$0}')
    size=$(echo $(($hexsize)))
    hexdate0=$(cat "$d" |xxd -s16 -l8 -ps| awk '{gsub(/.{2}/,"& ")}1'|awk '{for(i=NF;i>0;i--)printf "%s",$i}'&& echo "")
    hexdate1=$(echo $((0x$hexdate0/10000000)))
    epoch=$(echo $(($hexdate1-11644473600)))
    date=$(date -d @$epoch +"%Y-%m-%d %H:%M:%S")
    [ "$2" == "-c" ] && echo "$date,Recycle,,,[Deleted] "$name  "FILESIZE:$size"
    [ "$2" != "-c" ] && echo "$epoch|Recycle|||[Deleted] "$name  "FILESIZE:$size"
  done
 [ "$(ls -A $1/\$Recycle.Bin 2>/dev/null)" ] || echo "Usage: recbin2tln.sh [path to Windows root or Directory containing $Recycle.bin] [-c]"
