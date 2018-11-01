#!/bin/bash
#		ntuser2tln.sh
#       Automation script for processing NTUSER.DAT files using RegRipper:  https://github.com/keydet89/regripper2.8
usage="\n\n\t********** ntuser2tln.sh **********\n		USAGE: ntuser2tln.sh [input path] [OPTIONS]\n
\t		[input path]  file or directory path to NTUSER.DAT file(s)\n  
\n
\t	[OPTIONS]\n
\t		[computername] writes value entered in computer name field of timeline\n
\t		-e Outputs TLN using epoch timestamps (Default csv)\n
\t		-c Uses first level child folders of the input path as computer names\n		
\n\n
\t	EXAMPLES:\n
\t		Extract a TLN from a single ntuser.dat file \n
\t       ./ntuser2tln.sh /cases/Win10-lab12/Users/User42/NTUSER.DAT Win10-lab12 -e \n
\n		
\t		Extract a csv for all NTUSER.DAT files for a single PC named Win10-lab12\n
\t		./ntuser2tln.sh /cases/Win10-lab12/Users Win10-lab12 \n
\n
\t		Extract TLN for all NTUSER.DATs from multiple systems\n
\t		./ntuser2tln.sh /cases -e\n
\n
\t		Extract a TLN of multiple NTUSER.DAT files and Computers\n 
\t		./ntuser2tln.sh /cases -e -c\n
\n
\t	NOTE: In order to capture both computer names and user names in the timeline, \n
\t 		store NTUSER files in directories that identifiy both Computer and User name: \n\n
\t      EXAMPLE DIRECTORY:\n
\t		/cases/Windows10-lab12/Users/Administrator/NTUSER.DAT\n
\t		/cases/Win7-221/rsysdow/NTUSER.DAT\n
\t		/cases/DESKTOP-Q47R7/Artifact/LOCAL/Users/testuser/NTUSER.DAT\n
\n"
function regrip_ntusers_tln(){ 
    # Process NTUSER registry hives and add to TLN  
    sleep 1  
    find $input_path/$cname -type f 2>/dev/null | grep -i "\/ntuser.dat$" | while read d; 
    do
      USER_NAME=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      #  Format timeline as TLN
      rip.pl -r "$d" -p cmdproc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/CMD_PROC.TLN.TMP
      rip.pl -r "$d" -p cached_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/CACHED.TLN.TMP;
      rip.pl -r "$d" -p recentapps_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/RECENT_APPS.TLN.TMP;
      rip.pl -r "$d" -p typedpaths_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/TYPED_PATHS.TLN.TMP;
      rip.pl -r "$d" -p trustrecords_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/TRUST_RECORDS.TLN.TMP;
      rip.pl -r "$d" -p mmc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/MMC.TLN.TMP;
      rip.pl -r "$d" -p osversion_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/OS_VER.TLN.TMP;
      rip.pl -r "$d" -p winrar_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/WINRAR.TLN.TMP;
      rip.pl -r "$d" -p mixer_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/MIXER.TLN.TMP;
      rip.pl -r "$d" -p appkeys_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/" |tee -a $output_dir/APPKEYS.TLN.TMP;
      rip.pl -r "$d" -p officedocs2010_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/OFFICE_DOCS.TLN.TMP;
      rip.pl -r "$d" -p uninstall_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/UNINSTALL.TLN.TMP;
      rip.pl -r "$d" -p attachmgr_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/ATTACH_MGR.TLN.TMP;
      rip.pl -r "$d" -p muicache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/MUICACHE.TLN.TMP;
      rip.pl -r "$d" -p typedurlstime_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/TYPEDURLSTIME.TLN.TMP;
      rip.pl -r "$d" -p applets_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/APPLETS.TLN.TMP;
      rip.pl -r "$d" -p urun_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/URUN.TLN.TMP;
      rip.pl -r "$d" -p typedurls_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/TYPEDURLS.TLN.TMP;
      rip.pl -r "$d" -p userassist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/USERASSIST.TLN.TMP;
      rip.pl -r "$d" -p recentdocs_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/RECENTDOCS.TLN.TMP;
      rip.pl -r "$d" -p sysinternals_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/SYSINTERNALS.TLN.TMP;
      rip.pl -r "$d" -p tsclient_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/TSCLIENT.TLN.TMP;
      rip.pl -r "$d" -p mndmru_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/MNDMRU.TLN.TMP;
      rip.pl -r "$d" -p runmru_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/RUNMRU.TLN.TMP;
      rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $output_dir/DELETED-KEYS.TLN.TMP
    done
}
function sort_output(){
    echo "Sorting..."
    [ "$epoch" == "-e" ] && cat $output_dir/CMD_PROC.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/CMD_PROC.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/CMD_PROC.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/CMD_PROC.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|" | awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/CMD_PROC.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/CMD_PROC.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/CACHED.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/CACHED.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/CACHED.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/CACHED.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/CACHED.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/CACHED.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/RECENT_APPS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/RECENT_APPS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/RECENT_APPS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/RECENT_APPS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/RECENT_APPS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/RECENT_APPS.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/TYPED_PATHS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/TYPED_PATHS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TYPED_PATHS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/TYPED_PATHS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/TYPED_PATHS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TYPED_PATHS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/TRUST_RECORDS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/TRUST_RECORDS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TRUST_RECORDS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/TRUST_RECORDS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/TRUST_RECORDS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TRUST_RECORDS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/MMC.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/MMC.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MMC.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/MMC.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/MMC.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MMC.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/OS_VER.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/OS_VER.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/OS_VER.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/OS_VER.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/OS_VER.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/OS_VER.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/WINRAR.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/WINRAR.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/WINRAR.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/WINRAR.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/WINRAR.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/WINRAR.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/MIXER.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/MIXER.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MIXER.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/MIXER.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/MIXER.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MIXER.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/APPKEYS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/APPKEYS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/APPKEYS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/APPKEYS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/APPKEYS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/APPKEYS.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/OFFICE_DOCS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/OFFICE_DOCS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/OFFICE_DOCS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/OFFICE_DOCS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/OFFICE_DOCS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/OFFICE_DOCS.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/UNINSTALL.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/UNINSTALL.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/UNINSTALL.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/UNINSTALL.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/UNINSTALL.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/UNINSTALL.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/ATTACH_MGR.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/ATTACH_MGR.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/ATTACH_MGR.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/ATTACH_MGR.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/ATTACH_MGR.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/ATTACH_MGR.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/MUICACHE.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/MUICACHE.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MUICACHE.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/MUICACHE.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/MUICACHE.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MUICACHE.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/TYPEDURLSTIME.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/TYPEDURLSTIME.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TYPEDURLSTIME.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/TYPEDURLSTIME.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/TYPEDURLSTIME.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TYPEDURLSTIME.TLN.TMP;
    [ "$epoch" == "-e" ] && cat $output_dir/APPLETS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/APPLETS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/APPLETS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/APPLETS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/APPLETS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/APPLETS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/URUN.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/URUN.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/URUN.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/URUN.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/URUN.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/URUN.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/TYPEDURLS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/TYPEDURLS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TYPEDURLS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/TYPEDURLS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/TYPEDURLS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TYPEDURLS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/USERASSIST.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/USERASSIST.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/USERASSIST.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/USERASSIST.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/USERASSIST.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/USERASSIST.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/RECENTDOCS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/RECENTDOCS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/RECENTDOCS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/RECENTDOCS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/RECENTDOCS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/RECENTDOCS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/SYSINTERNALS.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/SYSINTERNALS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/SYSINTERNALS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/SYSINTERNALS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/SYSINTERNALS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/SYSINTERNALS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/TSCLIENT.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/TSCLIENT.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TSCLIENT.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/TSCLIENT.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/TSCLIENT.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/TSCLIENT.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/MNDMRU.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/MNDMRU.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MNDMRU.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/MNDMRU.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/MNDMRU.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/MNDMRU.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/RUNMRU.TLN.TMP  2>/dev/null| sort -rn| uniq |tee -a $output_dir/RUNMRU.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/RUNMRU.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/RUNMRU.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|" |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/RUNMRU.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/RUNMRU.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/DELETED-KEYS.TLN.TMP 2>/dev/null| sort -rn| uniq |tee -a $output_dir/DELETED-KEYS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/DELETED-KEYS.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/DELETED-KEYS.TLN.TMP  2>/dev/null| sort -rn| uniq | grep -Ea "^[0-9]{10}\|"  |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5", "$6", "$7}'| tee -a $output_dir/DELETED-KEYS.TLN.txt |tee -a $output_dir/Triage-Timeline.TLN.TMP && rm $output_dir/DELETED-KEYS.TLN.TMP;	
    [ "$epoch" == "-e" ] && cat $output_dir/Triage-Timeline.TLN.TMP | sort -rn |uniq | grep -Ea "^[0-9]{10}\|" | tee -a $output_dir/Triage-Timeline.TLN.txt && rm $output_dir/Triage-Timeline.TLN.TMP;
    [ "$epoch" != "-e" ] && cat $output_dir/Triage-Timeline.TLN.TMP | sort -rn |uniq |tee -a $output_dir/Triage-Timeline.TLN.txt && rm $output_dir/Triage-Timeline.TLN.TMP;
    find $output_dir/ -maxdepth 1 -empty -delete
}
output_dir=$PWD
input_path="$1"
[ ! -d "${input_path}" ] && [ ! -f "${input_path}" ] && echo -e $usage && sleep 1 &&  exit
[ -d $input_path ] && cd "$input_path"
COMPNAME=$(echo $2| grep -v ^-)
[ "$COMPNAME" == "" ] && COMPNAME=$(echo $3| grep -v ^-)
[ "$2" == "-e" ] || [ "$3" == "-e" ] && epoch="-e"
[ "$2" != "-c" ] && [ "$3" != "-c" ] && regrip_ntusers_tln && sort_output && echo "NTUSER.DAT TLN Complete!" && exit
[ "$2" == "-c" ] || [ "$3" == "-c" ] && COMP_NAMES=$(ls -1d */ |sed 's/\/$//'|sed '/^\/.*/d'|while read d; do echo $d;done) 
echo "$COMP_NAMES" |while read cname; 
do
  cd $input_path/$cname
  COMPNAME=$cname
  regrip_ntusers_tln
done
sort_output
echo "NTUSER.DAT TLN Complete!"
