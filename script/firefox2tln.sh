#!/bin/bash
#https://developer.mozilla.org/en-US/docs/Mozilla/Tech/Places/Database
#https://www.alekz.net/archives/740
# Default Firefox Profile Folder: "Users/[User Name]\/AppData\/Roaming\/Mozilla\/Firefox\/Profiles\/<random profile name.default>

function parse_ff_history(){
#Extract Firefox Browsing info
sqlite3 places.sqlite "select (moz_historyvisits.visit_date/1000000), moz_places.url, moz_places.title, moz_places.visit_count FROM moz_places,moz_historyvisits where moz_historyvisits.place_id=moz_places.id order by moz_historyvisits.visit_date" |awk -F'|' '{print $1"|FireFox|||[URL]: "$2"|TITLE:"$3"|VISIT-COUNT:" $4}'
#Extract Firefox Downloads info
sqlite3 places.sqlite "SELECT (dateAdded/1000000) AS dateAdded, url AS Location, moz_anno_attributes.name, content FROM moz_places, moz_annos, moz_anno_attributes WHERE (moz_places.id = moz_annos.place_id) AND (moz_annos.anno_attribute_id = moz_anno_attributes.id)"|awk -F"|" '{print $1"|firefox|||[Download]: "$2"|"$3"|"$4}'
#Extract Chrome Cookies
sqlite3 cookies.sqlite "select (creationTime/1000000), host,name,datetime((lastAccessed/1000000),'unixepoch','utc'),datetime(expiry,'unixepoch','utc') FROM moz_cookies"|awk -F'|' '{print $1"|FireFox|||[Cookie]: "$2" |NAME:"$3" |LAST ACCESS:"$4" |EXPIRY: "$5}'
}

type sqlite3 &>/dev/null || echo "usage: chrome2tln.sh [path to main.db] -e (epoch)"
input_path=$1
cd "$input_path"
epoch=$2
[ "$epoch" == "-e" ] && parse_ff_history |sort -rn
[ "$epoch" != "-e" ] && parse_ff_history |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'|sort -rn
