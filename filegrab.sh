#!/bin/bash
#Function to produce Red Text Color 
function makered() {
    COLOR='\033[01;31m' # bold red
    RESET='\033[00;00m' # normal white
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
} 
#Function to produce Green Text Color
function makegreen() {
    COLOR='\033[0;32m' # Green
    RESET='\033[00;00m' # normal white
    MESSAGE=${@:-"${RESET}Error: No message passed"}
    echo -e "${COLOR}${MESSAGE}${RESET}"
}
######### PATH FUNCTIONS ###########
# Identify image file and set mount points 
function set_source_path(){
      # Set Data Source or mount point"
      echo ""
      df -h|grep "mnt\|media"|grep .
      echo ""
      makered "SET DATA SOURCE (Mounted Windows Volume)"
      echo "Enter Source Data Path:"
      read -e -p "" -i "" MOUNT_DIR  
      [ ! -d "${MOUNT_DIR}" ] && makered "Path does not exist.." && sleep 1 && show_menu            
}
#Locates directories to compensate for case mismatches in directory names 
function set_windir(){
      WINDIR=$(find $MOUNT_DIR -maxdepth 1 -type d |grep -io windows$) 
      WINSYSDIR=$(find $MOUNT_DIR -maxdepth 2 -type d |grep -io windows\/system32$)
      USERDIR=$(find $MOUNT_DIR -maxdepth 1 -type d |grep -io users$)
	  REGDIR=$( find $MOUNT_DIR/$WINSYSDIR -maxdepth 1 -type d |grep -io config$)
	  EVTXDIR=$(find $MOUNT_DIR/$WINSYSDIR -maxdepth 2 -type d |grep -io winevt\/logs$)
      [ "$WINDIR" == "" ] || [ "$WINSYSDIR" == "" ] && makered "No Windows Directory Path Found on Source..." && sleep 2 && show_menu
}
############## FILE ACQUISITION FUNCTIONS#################  
#Get Master File Table $MFT 
function get_mft(){
    makegreen "Searching for \$MFT "
    cd $MOUNT_DIR	
    tar -Prvf $output_dir/filegrab.tar \$MFT |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
    echo ""
}
# Get Windows Journal Files
function get_usnjrnl(){
    makegreen "Searching for $LogFile and  \$UsnJrnl:\$J"
	cd $MOUNT_DIR
    tar -Prvf $output_dir/filegrab.tar \$Extend/\$UsnJrnl:\$J |tee -a  $output_dir/filegrab.log.txt&& makegreen "Complete!"
	echo ""
    tar -Prvf $output_dir/filegrab.tar \$LogFile |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
     sleep .5
} 
#Get Windows Registry Files
function get_registry(){
    cd $MOUNT_DIR  
    makegreen "Searching for Windows Registry files"
    [ "$type" == "" ] && find $WINSYSDIR/$REGDIR -type f  2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
	[ "$type" != "" ] && find $WINSYSDIR/$REGDIR -maxdepth 1 -regextype posix-extended -regex '.*.(SYSTEM$|SOFTWARE$|SAM$|SECURITY$|system$|software$|sam$|security$)' 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
     echo ""
}
# Get User's registry hive (NTUSER.DAT) 
function get_ntuser(){
    makegreen "Searching for NTUSER.DAT files"
    cd $MOUNT_DIR
    find $USERDIR -maxdepth 2 -mindepth 2 -type f -iname "ntuser.dat" 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
	echo ""
}
# Get User's AppData Directory and contents
function get_appdata(){
    makegreen "Searching for files in the AppData Directory"
    cd $MOUNT_DIR
    find $USERDIR/*/AppData/ -type f 2>/dev/null -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
    echo ""
}
# Get Amcache.hve and or Recentfilecache.bcf
function get_Amcache.hve(){
    makegreen "Searching for AMCACHE.HVE and RECENTFILECACHE.BCF" 
    cd $MOUNT_DIR
    find $WINDIR/[Aa]pp[Cc]ompat/Programs -maxdepth 1 -mindepth 1 -type f -iname "Recentfilecache.bcf" 2>/dev/null -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt
    find $WINDIR/[Aa]pp[Cc]ompat/Programs -maxdepth 1 -mindepth 1 -type f -iname "Amcache.hve" 2>/dev/null -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt
	makegreen "Complete!" 
    echo ""
}
# Get SRUM.dat
function get_srumdb(){
    makegreen "Searching for SRUMDB.DAT" 
    cd $MOUNT_DIR
    find $WINSYSDIR/[Ss][Rr][Vv]/ -maxdepth 1 -mindepth 1 -type f -iname "srumdb.dat" 2>/dev/null -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt&& makegreen "Complete!" 
    echo ""
}
# Get usrclass.dat
function get_Usrclass(){
    makegreen "Searching for USRCLASS.DAT"
    cd $MOUNT_DIR
    find $USERDIR/*/AppData/Local/Microsoft/Windows/UsrClass.dat 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
    echo ""	
}
# Get Chrome History file
function get_chrome_history(){
    makegreen "Searching for Chrome History file"
    cd $MOUNT_DIR
    find $USERDIR/*/AppData/Local/Google/Chrome/User\ Data/Default/History -maxdepth 1 -type f 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
    echo ""	
}
# Get Internet Explorer WebcacheV...dat file
function get_webcache.dat(){
    makegreen "Searching for WEBCACHEV0x.DAT"
    cd $MOUNT_DIR/$USER_DIR
    find $USERDIR/*/AppData/Local/Microsoft/Windows/WebCache -maxdepth 1 -type f -iname "webcachev*.dat" 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
    echo ""
}
# Get Firefox Sqlite files
function get_firefox_history(){
    makegreen "Searching for Firefox sqlite files"
    cd $MOUNT_DIR/$USER_DIR
    find $USERDIR/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/ -maxdepth 1 -type f -iname "*.sqlite" 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
    echo ""
}
# Get Skype main.db file
function get_skype(){
     makegreen "Searching for Skype Main.db"
     cd $MOUNT_DIR
     find $USERDIR/*/AppData/Roaming/Skype/*/main.db -maxdepth 1 -type f 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
     echo ""
}
#Copies lnk files 
function get_lnk_files(){
    makegreen "Searching for LNK files"
    cd $MOUNT_DIR
    find $USERDIR/*/AppData/Roaming/Microsoft/Windows/Recent/ -type f \( -iname "*.lnk" -o -iname "*-ms" \) 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt 
    find $USERDIR/*/AppData/Roaming/Microsoft/Office/Recent/*.lnk -type f 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt
    makegreen "Complete!" 
    echo ""
}
# Get Setupapi logs 
function get_setupapi(){
     cd $MOUNT_DIR
     makegreen "Searching for SETUPAPIDEV.LOG"
     find $WINDIR/[Ii][Nn][Ff] -type f -iname "setupapi*log" 2>/dev/null -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
     echo ""
}
# Get Scheduled Tasks 
function get_scheduled_tasks(){
    makegreen "Searching for SCHEDULED TASKS"
    cd $MOUNT_DIR
    find $WINDIR/[Tt][Aa][Ss][Kk][Ss] -regextype posix-extended -regex  '.*.(\.[Jj][Oo][Bb]$|\.[Aa][Tt]$|[Ss][Cc][Hh][Ee][Dd][Ll][Gg][Uu]\.[Tt][Xx][Tt])' 2>/dev/null -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
    echo ""
}
# Get Windows Event Logs
function get_evtx(){
    makegreen "Searching for Windows Event Logs"
    cd $MOUNT_DIR
    [ "$type" != "minimal" ] && find $WINSYSDIR/$EVTXDIR -type f 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
    [ "$type" == "minimal" ] && find $WINSYSDIR/$EVTXDIR -type f \( -iname "security.evtx" -o -iname "system.evtx" -o -iname "application.evtx" \) 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
    echo ""
}
# Get Prefetch files
function get_prefetch(){
     makegreen "Searching for Prefetch files"
     cd $MOUNT_DIR
     find $WINDIR/Prefetch/*.pf 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt 
     find $WINDIR/Prefetch/*.db* 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt 
     makegreen "Complete!"
     echo ""
}
# Get metadata from Windows Recycle.bin
function get_Recycle.Bin(){
     makegreen "Searching for file metadata in \$Recycle.bin"
     cd $MOUNT_DIR
     find "\$Recycle.Bin" -type f -iname "*\$I*" 2>/dev/null -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
     echo ""
 }     
# Get Windows Log files 
function get_logfiles(){
     cd $MOUNT_DIR
     makegreen "Searching for Windows Log files"
     find [Ii][Nn][Ee][Tt][Pp][Uu][Bb] -type f -iname "\.log" -print0 | tar -rvf  $output_dir/filegrab.tar --null -T - && makegreen "Complete!" 
     find $WINSYSDIR -maxdepth 1 -type d -iname "LogFiles" -print0  | tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
     echo ""
}
# Get MS Office, Adobe and Open Office Documents  
function get_documents(){
     cd $MOUNT_DIR
     makegreen "Searching for MS-Office PDFs and Other Documents"
     find $MOUNT_DIR -regextype posix-extended -regex '.*.(\.[Pp][Dd][Ff]$|\.[Dd][Oo][Cc].$|\.[Xx][Ll][Ss].$|\.[Pp][Pp][Tt].$|\.[Rr][Tt][Ff]$|\.[Oo][Dd].$|\.[Dd][Oo][Cc]$|\.[Dd][Oo][Tt]$|\.[Dd][Oo][Tt].$|\.[Xx][Ll].$|\.[Xx][Ll][Aa][Mm]$|\.[Xx][Ll].$|\.[Xx][Ll][Tt].$|\.[Pp][Oo][Tt]$|\.[Pp][Oo][Tt].$|\.[Pp][Pp].$|\.[Pp][Pp][Aa][Mm]$|\.[Pp][Pp][Ss].$|\.xps$|\.fdf$|\.xfdf)' -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!"
     echo ""
}
# Get Outlook mail files 
function get_outlook(){
    makegreen "Searching for OUTLOOK OST/PST files"
    cd $MOUNT_DIR
	find $MOUNT_DIR -regextype posix-extended -regex '.*.(\.[Pp][Ss][Tt]$|\.[Oo][Ss][Tt]$)' -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
}
# Collect Volatilile data files
function get_volatile(){
    cd $MOUNT_DIR
    makegreen "Searching for Volatile Data Files"
    find $MOUNT_DIR -regextype posix-extended -regex '.*.(*.[Dd][Mm][Pp]$|[Hh][Ii][Bb][Ee][Rr][Ff][Ii][Ll]\.[Ss][Yy][Ss]$|[Pp][Aa][Gg][Ee][Ff][Ii][Ll][Ee]\.[Ss][Yy][Ss]$|[Ss][Ww][Aa][Pp][Ff][Ii][Ll][Ee]\.[Ss][Yy][Ss])' -print0| tar -rvf  $output_dir/filegrab.tar --null -T - |tee -a  $output_dir/filegrab.log.txt && makegreen "Complete!" 
}
# GZip all files
function gzip_filegrab(){
    makegreen "Packaging Acquisition"
    [ -f $output_dir/filegrab.tar ] && gzip -1 $output_dir/filegrab.tar
	makegreen "~Complete~"
}
# Basic Collection  
function get_all(){
           #####################################################################
           ######              Default Acquisition                        ######
           #####################################################################
           ######  Add and Remove "#" to disable/enable acquisition types ######
           #####################################################################
           get_mft
           get_usnjrnl
           get_registry
           get_ntuser
           get_Usrclass
           get_Amcache.hve
           get_srumdb
           get_setupapi
           get_evtx
           get_scheduled_tasks
           get_prefetch
           get_Recycle.Bin
           get_documents
		   get_volatile
           get_appdata
		   gzip_filegrab
}
# Fast Data Collection
function get_fast(){
           #####################################################################
           ######               Fast Acquisition                          ######
           #####################################################################
           ######  Add and Remove "#" to disable/enable acquisition types ######
           #####################################################################
           get_mft
           get_registry
           get_ntuser
           get_Amcache.hve
           get_srumdb
           get_setupapi
           get_scheduled_tasks
           get_evtx
           get_prefetch
           get_lnk_files
           get_Recycle.Bin
           get_chrome_history
           get_firefox_history
           get_webcache.dat
		   get_skype
		   gzip_filegrab
}
# Minimal Data Collection
function get_minimal(){
           #####################################################################
           ######               Fast Acquisition                          ######
           #####################################################################
           ######  Add and Remove "#" to disable/enable acquisition types ######
           #####################################################################
           get_registry
           get_ntuser
           get_Usrclass
           get_Amcache.hve
           get_srumdb	
           get_setupapi
           get_evtx		   
		   gzip_filegrab
}
# Collect Documents
function get_userdata(){
           #####################################################################
           ######   Acquire All Documents and Exchange Mail PST/OST       ######
           #####################################################################
           ######  Add and Remove "#" to disable/enable acquisition types ######
           #####################################################################
           get_outlook
           get_documents
		   gzip_filegrab
}		   
output_dir=$(pwd)
[ "$1" == "-h" ] && echo "USAGE: filegrab.sh [optional -d (documents and mail files only) -q (quick)] " && exit
set_source_path
echo ""
set_windir
echo ""
[ "$1" == "" ] && get_all
[ "$1" == "-d" ] && get_userdata
[ "$1" == "-q" ] && type="Quick" && get_fast
[ "$1" == "-m" ] && type="minimal" && get_minimal

read -n1 -r -p "Press a key to continue..." key