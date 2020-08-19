#!/bin/bash
#chrome2tln.sh usage:skype2tln.sh [path to Chrome Profile Folder]
#Default Chrome Profile Folder: "Users/[User Name]\/AppData\/Local\/Google\/Chrome\/User\ Data\/Default
#https://www.forensicswiki.org/wiki/Google_Chrome
#http://www.acquireforensics.com/blog/google-chrome-browser-forensics.html

function parse_chrome_history(){
#Extract Chrome Browsing info 
sqlite3 History "select (last_visit_time/1000000-11644473600),url, title, visit_count from urls ORDER BY last_visit_time" 2>/dev/null |awk -F'|' '{print $1"|chrome|||[URL]:"$2"|TITLE: "$3"| VISIT COUNT:"$4}'
#Extract Chrome Downloads 
sqlite3 History "select (start_time/1000000-11644473600), url, target_path, total_bytes FROM downloads INNER JOIN downloads_url_chains ON downloads_url_chains.id = downloads.id ORDER BY start_time" 2>/dev/null|awk -F'|' '{print $1"|chrome|||[DOWNLOAD]-"$2"|TARGET:-"$3"| BYTES TRANSFERRED:-"$4}'
#Extract Chrome Cookies
sqlite3 Cookies "select (cookies.creation_utc/1000000-11644473600), cookies.host_key,cookies.path, cookies.name, datetime(cookies.last_access_utc/1000000-11644473600,'unixepoch','utc'), cookies.value FROM cookies" 2>/dev/null|awk -F'|' '{print $1"|chrome|||[Cookie]:"$2" |LASTACCESS: "$5" |VALUE: "$4}' 
}

type sqlite3 &>/dev/null || echo "usage: chrome2tln.sh [path to Chrome Profile Folder] -e (epoch)"
input_path=$1
cd "$input_path"
epoch=$2
[ "$epoch" == "-e" ] && parse_chrome_history |sort -rn
[ "$epoch" != "-e" ] && parse_chrome_history |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|sort -rn
