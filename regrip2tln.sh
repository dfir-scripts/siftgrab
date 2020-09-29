#!/bin/bash
#"usage: riptlns.sh [source path] -e (epoch)
function get_computer_name(){
   COMPNAME=$(find $input_path -maxdepth 10 -type f |egrep -m1 -i /system$| while read d; do rip.pl -r "$d" -p compname 2>/dev/null |grep -i "computername   "|awk -F'= ' '{ print $2 }';done) 
   [ "$COMPNAME" == "" ] && COMPNAME="-s ---- "
   [ "$COMPNAME" != "" ] && COMPNAME="-s $COMPNAME "    
}
function regrip_tlns(){
	get_computer_name
    # Process Software registry Hive and add to TLN	 
    find $input_path  -type f | grep -i "\/software$" |while read d; 
      do 
         rip.pl $COMPNAME -r "$d" -p apppaths_tln 2>/dev/null
         rip.pl $COMPNAME -r "$d" -p at_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p cmd_shell_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p direct_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p landesk_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p tracing_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p uninstall_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p winlogon_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p gpohist_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p logmein_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p srun_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p silentprocessexit_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p networklist_tln 2>/dev/null 
      done
    # Process Security registry Hive and add to TLN	  
    find $input_path -type f | grep -i "\/security$"| while read d; 
	  do 
		rip.pl $COMPNAME -r "$d" -p secrets_tln 2>/dev/null 
      done  
	     # Process Sam registry Hive and add to TLN
    find $input_path -type f | grep -i "\/sam$"| while read d; 
      do 
        rip.pl $COMPNAME -r "$d" -p samparse_tln 2>/dev/null 
      done 
         # Process System registry Hive and add to TLN
    find $input_path -type f | grep -i "\/system$"| while read d; 
      do 
         rip.pl $COMPNAME -r "$d" -p appcompatcache_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p legacy_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p shimcache_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p bam_tln 2>/dev/null 
         rip.pl -r "$d" -p svc_tln 2>/dev/null 
         rip.pl $COMPNAME -r "$d" -p bthport_tln 2>/dev/null 
      done	  
}
input_path="$1"
cd "$input_path"
epoch=$2
[ "$input_path" == "" ] && echo "usage: riptlns.sh [source path] -e (epoch)"\  && exit

[ "$epoch" == "-e" ] && regrip_tlns | grep -a ^[0-9] |sort -rn
[ "$epoch" != "-e" ] && regrip_tlns | grep -a ^[0-9] |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'|sort -rn
