#!/bin/bash
# skype2tln.sh usage:skype2tln.sh [path to main.db]
# Extracts Skype information from main.db to five columnar CSV (Default) or TLN (-e) 
# https://gist.github.com/r3t/4466231

#parse_maindb 
function parse_maindb(){
  #contacts 
  sqlite3 file:$input_path 'select profile_timestamp,skypename, fullname,displayname from Contacts' 2>/dev/null|awk -F'|' '{print $1"|SKYPE|||NEW CONTACT: "$2", "$3", "$4}'|sed 's|^\||0\||'
  #messages
  sqlite3 file:$input_path 'select timestamp,body_xml,author,dialog_partner from Messages' 2>/dev/null|awk -F'|' '{print $1"|SKYPE|||MESSAGE: "$2", FROM:"$3","$4}'|sed 's|^\||0\||' 
  #Voicemail 
  sqlite3 file:$input_path 'select timestamp,partner_dispname,path from Voicemails' 2>/dev/null|awk -F'|' '{print $1"|SKYPE|||VOICEMAIL FROM: "$2" FILE: "$3}'|sed 's|^\||0\||'
  #Conversations
  sqlite3 file:$input_path 'select creation_timestamp,displayname from Conversations' 2>/dev/null|awk -F'|' '{print $1"|SKYPE|||CONVERSATION STARTED: "$2}'|sed 's|^\||0\||'
  sqlite3 file:$input_path 'select last_activity_timestamp, displayname from Conversations' 2>/dev/null|awk -F'|' '{print $1"|SKYPE|||CONVERSTATION END: " $2}'|sed 's|^\||0\||' 
  #File Transfer
  sqlite3 file:$input_path 'select starttime, filepath,bytestransferred,partner_dispname from Transfers' 2>/dev/null|awk -F'|' '{print $1"|SKYPE||FILE TRANSFER:" $2}'|sed 's|^\||0\||' 
}
type sqlite3 &>/dev/null && parse_maindb || echo "usage: skype2tln.sh [path to main.db] -e (epoch)"
input_path=$1
epoch=$2
[ "$2" == "-e" ] && parse_maindb|sort -rn
[ "$2" != "-e" ] && parse_maindb|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|sort -rn