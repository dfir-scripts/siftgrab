#!/bin/bash
function read_me(){
echo "
##################################################################################
#
# Siftgrab.sh is a Triage Tool for Windows Forensic Images using SANS Sift
#
# A single script (siftgrab.sh) to mount images, collect and extract image artifacts.
# Process single or multiple computer excerpts (including volume shadow copies) into a single csv and TLN timelines complete with computer and user names
# Copy Siftgrab.sh copy the files to usr/local/bin and make the following updates to SANS Sift:
# 
# Tested on SANS Sift 3.0 v2018.28.0 (Ubuntu 16.04) and SANS Sift 3.0 (Ubuntu 14.04)
# INSTALLATION:
# Download Siftgrab and copy to /usr/local/bin
# "git clone https://github.com/siftgrab/siftgrab.git"
# "chmod +x siftgrab/*.sh"
# "cp siftgrab/* /usr/local/bin/"
# 
# Install Sqlite (required for chrome, firefox and skype history)
# "sudo apt-get install sqlite3"
# 
# Update Regripper: (Regripper has lots of new plugins and capabilities)
# "git clone https://github.com/keydet89/RegRipper2.8.git"
# "sudo cp RegRipper2.8/shellitems.pl /usr/local/bin/shellitems.pl"
# "sudo cp RegRipper2.8/plugins/* /usr/local/src/regripper/plugins"
# 
# Patch the latest version of rip.pl so it will work in Sift:
# "siftgrab/rip.pl2linux.sh" (creates an updated rip.pl called rip.new)
# "sudo cp rip.new /usr/local/bin/rip.pl"
# "sudo cp rip.new /usr/share/regripper/rip.pl"
# 
# Download pylnker.py and copy to /usr/local/bin: (lnk file extraction)
# "git clone https://github.com/HarmJ0y/pylnker.git "
# "chmod +x pylnker/pylnker.py"
# "sudo cp pylnker/pylnker.py /usr/local/bin/pylnker.py"
# 
# Download http://github.com/bromiley/tools/tree/master/win10_prefetch/w10pf_parse.py and copy to /usr/local/bin: (Windows 8+ prefetch parser)
# "wget http://github.com/bromiley/tools/tree/master/win10_prefetch/w10pf_parse.py"
# "chmod +x w10pf_parse.py"
# "sudo cp w10pf_parse.py /usr/local/bin/w10pf_parse.py"
# 
# Recommended: Install Sushi to use space bar preview
# "sudo apt-get install gnome-sushi"
# 
# 
# MOUNTING:
# Selection 1 from siftrgrab menu or use ermount.sh from the command line
# ACQUISITION:
# After mounting image, choose menu item 2, 3, 4 and or 5 as needed
# Or use filegrab.sh from Sift or a Live Boot USB/DVD to acquire files
# PROCESSING:
# Single or multiple cases procesessing produces timelines and other extracted registry information
# Will process data exported from tools like cylr and for most artifacts, data to process does not have to folllow Windows heirarchy.
# Use individual scripts below to directly parse mounted volumes
# To maintain identity when processing multiple cases, place evidence items in separate
# directories to identify each computer or dataset and a parent folder named cases.
# 
# Use the default /cases folder on Sift or follow the directory structure listed below to process metadata from multiple Windows computers:
# Select Number 6 from the Siftgrab menu and set /mnt/hgfs/F/cases as your source 
#
#          /mnt/hgfs/F/cases/Server1
#          /mnt/hgfs/F/cases/CONTROLLER
#          /mnt/hgfs/F/cases/myLabtop
#          /mnt/hgfs/F/cases/DESKTOP-Q8822
#
# 
# Individual scripts to perform specific tasks
# 
# ads2tln.sh Lists Alternate Data Streams on a mounted NTFS Volume
# chrome2tln.sh Extracts Chrome History, downloads and cookies
# ermount.sh Mounts an E01 or raw image using ewfmount
# filegrab.sh Creates an image excerpt from a mounted Windows disk image
# firefox2tln.sh Extract FireFox History, Downloads,cookies
# recbin2tln.sh Extracts metadata from the recycle bin "$I" files
# skype2tln.sh Extracts Skype Logs
# tln2csv.sh Converts a TLN file to CSV with human readable timestamps
# csv2tln.sh Converts a five columnar CSV timeline file to TLN
# rip.pl2linux Changes and then copies original rip.pl (Rip v.2.8_20180406) to rip.new
# Then replace old version of rip.pl( e.g. cp rip.new /usr/local/bin/rip.pl && cp rip.new /usr/share/regripper/rip.pl)
# rip.new Latest rip.pl (v.2.8_20180406) modified for use in SANS Sift
#
#
# Automation and extraction is made possible by using and the following tools/libraries found on Sift:
#  https://github.com/sans-dfir/sift
#  https://github.com/dkovar/analyzeMFT
#  https://github.com/keydet89/RegRipper2.8
#  https://github.com/obsidianforensics/hindsight
#  https://github.com/PoorBillionaire/Windows
#  https://github.com/bromiley/tools/blob/master/win10_prefetch
#  https://github.com/HarmJ0y/pylnker
#  https://github.com/libyal/libesedb/tree/master/esedbtools
#  https://github.com/keydet89/Tools/tree/master/source/Parseie.pl
#  https://github.com/keydet89/Tools/tree/master/source/rfc.pl
#  https://github.com/keydet89/Tools/tree/master/source/bodyfile.pl
#  https://www.clamAV.net
#  https://github.com/libyal/libpff/blob/master/pfftools
#  http://download.savannah.gnu.org/releases/attr/
#  https://github.com/libyal/libevtx
#  https://github.com/decalage2/oletools/
#  https://github.com/libyal/libewf/
#
#
#  Individual functions can be enable or disabled with a comment "#" in the menu selection area
#  The following acquisition and processing functions are disabled by default
#  and can be re-enabled by removing the comment "#" that calls the function
#      get_logfiles       (Acquires c:\Windows\System32\Logs\* \inetpub\..\..\ *.log)
#      get_browser_cache  (Acquires Firefox,IE and Chrome Browser Cache)
#      extract_webcacheV  (Extract WebcacheV...dat using EseDBExport )
#      parse_index.dat    (Extract index.dat using parseie.pl) 
#
# Software Deleted keys do not extracted by default 
# (search for key word "performance" within the scriptand un-comment the command to enable)
# 
################################################################################
"
}      
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
##  Main Proccif Display Menu Function
echo ""
function show_menu(){
    GRAY=`echo "\033[0;37m"`
    GREEN=`echo "\033[0;32m"`
    NORMAL=`echo "\033[m"`
    RED=`echo "\033[31m"`
    echo -e "${GREEN}  Siftgrab${NORMAL}"
    echo -e "*****************************************************"
    echo -e "${GRAY}Mount Images and Aqcuire Image Excerpts${NORMAL}"
    echo -e "*****************************************************"
    echo -e "** 1) ${GREEN}Mount an E01 or Raw Disk Image${NORMAL}"
    echo -e "** 2) ${GREEN}Acquire a Basic Image Excerpt from Mounted Image(s)${NORMAL}"
    echo -e "** 3) ${GREEN}Acquire \$USNJRNL and \$LOGFILE from Mounted Image(s)${NORMAL}"
    echo -e "** 4) ${GREEN}Find and Extract Outlook OST/PST Mail Files ${NORMAL}"
    echo -e "** 5) ${GREEN}Find and Acquire Volatile Data${NORMAL}"
    echo -e "**    ${GREEN}(hiberfil.sys, dmp, pagefile, Swap,)${NORMAL}"
    echo -e "*****************************************************${NORMAL}"
    echo -e "${GRAY}Process Windows Artifacts${NORMAL}"
    echo -e "*****************************************************"
    echo -e "** 6)${GREEN} Extract Registry and File Artifacts${NORMAL}"
    echo -e "** 7)${GREEN} Create TLN Timeline from \$MFT${NORMAL}"
    echo -e "** 8)${GREEN} Scan Volume or files with ClamAV${NORMAL}"
    echo -e "** 9)${GREEN} Readme${NORMAL}"
    echo ""
    echo -e "Select a menu option number or ${RED}enter to exit. ${NORMAL}"
    read opt
while [ opt != '' ]
    do
    if [[ $opt = "" ]]; then 
            exit;
    else
        case $opt in
        #Menu Selection 1: Mount E01 or RAW disk image to $MOUNT_DIR 
        1) clear;
           makegreen "Mount an E01 or RAW disk image file"
           mount_prefs
           set_msource_path
           set_image_offset
           mount_image
           mount_vss
           read -n1 -r -p "Press any key..." key
           clear
            show_menu;
            ;;
        #Menu Selection 2: Acquire Data from Mounted Disks or Image Excerpts
        2) clear; 
           ###### Set Acquisition Source and Destination Paths ######
           echo ""
           makegreen "Acquire Data from Mounted Disks or Image Excerpts"
           set_msource_path
           set_dsource_path
           echo ""
           set_windir
           is_it_XP
           get_computer_name
           create_artifact_dir
           vss_create_artifact_dir
           makegreen "COLLECTING METADATA STAND BY..."
           #####################################################################
           ######                 Acquisition Functions                   ######
           #####################################################################
           ######  Add and Remove "#" to disable/enable acquisition types ######
           #####################################################################
           get_mft              
           get_registry         
           get_ntuser           
           get_usrclass.dat     
           get_Amcache.hve      
           get_setupapi         
           get_scheduled_tasks  
           get_evtx            
           get_webcache.dat     
           get_chrome_history   
           #get_browser_cache 
           get_ff_places.sqlite
           get_skype   
           get_flash_cookies    
           get_index.dat        
           get_lnk_files        
           get_prefetch         
           get_Recycle.Bin      
           #get_logfiles
           ADS_extract 
           #####################################################################
           #####  End of Acquisition Funtions                              #####
           #####################################################################
           remove_dupes
           makegreen "Data Acquisition Complete!"
           du -sh /$CASE_DIR/$COMPNAME/Artifact
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;  
            ;; 
        #Menu Slection 3: Extract $USNJRNL Files a from Mounted Image(s)
        3) clear;
           set_msource_path
           set_dsource_path
           set_windir
           get_computer_name
           echo ""
           create_artifact_dir
           vss_create_artifact_dir
           makered "COLLECTING $USNJRNL FILES FROM MOUNTED DISKS AND VSC(s)"
           get_usnjrnl
           remove_dupes
           makegreen "Data Acquisition Complete!"
           du -sh /$CASE_DIR/$COMPNAME/Artifact
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;  
            ;; 
        #Menu Selection 4: Collect Outlook Email OST/PST files
        4) clear; 
           set_msource_path
           set_dsource_path
           makered "COLLECTING OUTLOOK OST AND PST FILES"
           set_windir
           is_it_XP
           get_computer_name
           create_artifact_dir
           vss_create_artifact_dir
           get_outlook_data
           extract_Outlook_pst_ost
           find /$CASE_DIR/$COMPNAME/Artifact -type f| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
           find /$CASE_DIR/$COMPNAME -empty -delete
           makegreen "Data Acquisition Complete!"
           du -sh /$CASE_DIR/$COMPNAME/Artifact
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;  
            ;; 
        #Menu Selection 5:  Collect files containing volatile data from mounted image
        5) clear; 
           set_msource_path
           set_dsource_path
           echo ""
           set_windir
           is_it_XP
           get_computer_name
           create_artifact_dir
           vss_create_artifact_dir
           makered "COLLECTING VOLATILE DATA FILES"
           get_volatile
           vss_get_volatile
              makegreen "Data Acquisition Complete!"
           du -sh /$CASE_DIR/$COMPNAME/Artifact
           read -n1 -r -p "Press any key to continue..." key
           remove_dupes
           clear;
           show_menu;  
            ;; 
        #Menu Selection 6: Process Artifacts Collected using RegRipper and other Tools
        6) clear;
           makegreen "Process Artifacts for Triage"
           set_psource_path
           create_triage_dir
           get_last_logged_on
           get_winverinfo
           get_network_info
           get_profiles
           get_proxy
           #####################################################################
           ######                 Processing Functions                    ######
           #####################################################################
           ######  Add and Remove "#" to disable/enable acquisition types ######
           #####################################################################
           regrip_ntuser_tln
           regrip_sam
           regrip_security_tln  
           regrip_sam_tln
           regrip_system_tln  
           regrip_usrclass_tln
           regrip_software_tln
           regrip_amcache_tln
           regrip_services
           regrip_USB
           regrip_USB_device_list
           regrip_shellbags
           regrip_Amcache
           regrip_shimcache
           regrip_userassist
           regrip_runkeys
           regrip_comdlg
           regrip_wordwheel
           regrip_typedpaths
           regrip_cortana
           regrip_typedurls
           regrip_typedurlstime
           parse_recycle.bin
           extract_Chrome
           extract_Firefox
           #extract_webcacheV
           regrip_autostart
           extract_Jobs
           analyze_lnk_files
           parse_prefetch
           #parse_index.dat
           export_evtx
           Security_evtx_IDs
           timeline_TLN
           echo ""
           makered "RUN REGRIPPER FILE PLUGINS (ntuser, software, system, security)?" && yes-no
           [ "$YES_NO" == "yes" ] && regrip_software
           [ "$YES_NO" == "yes" ] && regrip_system
           [ "$YES_NO" == "yes" ] && regrip_security
           [ "$YES_NO" == "yes" ] && regrip_NTUSER
           # Find and remove any empty Triage directories
           find /$CASE_DIR/Triage -empty -delete
           makegreen "Removing Duplicates..."
           echo "Please Wait..."
           fdupes -rdN /$CASE_DIR/Triage
           makegreen "Processed Artifacts Located in /$CASE_DIR/Triage"
           du -sh /$CASE_DIR/Triage
           makegreen Process Complete!
           read -n1 -r -p "Press any key to continue..." key
           clear     
           show_menu;
            ;;
        #Menu Selection 7: Run AnalyzeMFT and parseusn.py
        7) clear;
           makegreen "Create TLN from $MFT";
           set_psource_path
           analyze_mft
           read -n1 -r -p "Press any key to continue..." key
           clear 
           show_menu;
            ;;
        #Menu Selection 10: Scan Mounted Drive with ClamAV
        8) clear; 
           makegreen "Scan with ClamAV";
           set_msource_path
           set_dsource_path
           set_windir
           is_it_XP
           get_computer_name
           create_artifact_dir
           clamscan -h
           makered "SCAN FILES WITH CLAMAV"        
           find /var/lib/clamav/|grep -i c.d$|while read d; do printf "$d\t" && stat -c %y "$d";done
           makegreen "Verify the above ClamAV Signatures are up to date"
           makegreen "Run freshclam or remove/replace old signature files to update"
           echo ""
           echo ""
           makegreen "Enter to start scan or change cmd line as needed"
           mkdir -p /$CASE_DIR/$COMPNAME/AVScan
           [ "$(ls -A $MOUNT_DIR)" ] && read -e -p "" -i "clamscan -rzi  $MOUNT_DIR -l /$CASE_DIR/$COMPNAME/AVScan/Clam-Scan-Results.txt" clam_scan_cmd 
           [ "$(ls -A $MOUNT_DIR)" ] && run_clam_scan
           echo ""
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;  
            ;;
        #Menu Selection 9: ReadMe
        9) clear;
           read_me
           read -n1 -r -p "Press any key to continue..." key
           clear 
           show_menu;
            ;;
        x)exit;
        ;;
        \n)clear;
           exit;
        ;;
        *)clear;
        makered "Pick an option from the menu";
        show_menu;
        ;;
    esac
fi
done
}
############################################
#########DRIVE MOUNTING FUNCTIONS###########
############################################
# Identify image file and set mount points 
function set_msource_path(){
      # Set Data Source or mount point"
      echo ""
      makered "SET MOUNT POINT"
      echo "Set Path or Enter to Accept Default:"
      read -e -p "" -i "/mnt/windows_mount" MOUNT_DIR  
      [ ! -d "${MOUNT_DIR}" ] && makered "Path does not exist.." && sleep 1 && exit
}
# Enter Image file to process
function mount_prefs(){
makered "ENTER PATH AND IMAGE FILE NAME TO MOUNT"
      read -e -p "Image File: " -i "" IPATH
      [ ! -f "${IPATH}" ] && makered "File does not exist.." && sleep 1 && clear && exit
      IMG_TYPE=$(echo "$IPATH"|awk -F . '{print $NF}'|grep -i e01$)
      # Set source image and destination mount point for E01 
      [ "$IMG_TYPE" != "" ] &&  IMG_SRC="/mnt/ewf/ewf1" || IMG_SRC="${IPATH}"
      [ "$IMG_TYPE" != "" ] && [ ! -f /mnt/ewf/ewf1 ] || sudo umount /mnt/ewf 
      [ -f /mnt/ewf/ewf1 ] && echo "EWF mount point in use, try manual unmount or reboot" && sleep 2 && exit
      echo ""
      makered "FILE SYSTEM TYPE"
      echo "Defaults is ntfs, see mount man pages for others fs types "
      read -e -p "File System:  " -i "ntfs" FSTYPE
      [ "$FSTYPE" == "ntfs" ] && ntfs_support=",show_sys_files,streams_interface=windows"
}
# Run mmls to find any partition offsets
function set_image_offset(){
      makered "RUNNING MMLS TO IDENTIFY OFFSET"
      mmls "${IPATH}" 2>/dev/null|| FULLIMG="No"
      #[ -e $MOUNT_DIR ] &&  [ -e /mnt/ewf ] && echo "Ready to Mount!" || echo "mount point(s) busy, try manually unmounting" && sleep 2 && exit
      [ "$FULLIMG" != "No" ] && read -e -p "Enter the starting block: "  SBLOCK
      [ "$FULLIMG" != "No" ] && read -e -p "Set disk block size:  " -i "512" BSIZE
      [ "$FULLIMG" != "No" ] && POFFSET=$(echo $(($SBLOCK * $BSIZE)))
      [ "$FULLIMG" != "No" ] && makegreen "CALCULATING FOR OFFSET: $SBLOCK * $BSIZE = $POFFSET"
      [ "$FULLIMG" != "No" ] && makered "PARTITION OFFSET = $POFFSET"
      [ "$FULLIMG" != "No" ] && OFFSET=",offset=$POFFSET"
}

# Issue Mount commands for E01 and raw image types
 function mount_image(){
      echo ""
      makered "EXECUTING MOUNT COMMAND(S)....."
      # Mount E01 to /mnt/ewf
      [ "$IMG_TYPE" == 'E01' ] || [ "$IMG_TYPE" == "e01" ]  && ewfmount "${IPATH}" /mnt/ewf

      # Mount image to $MOUNT_DIR
      makegreen "mount -t $FSTYPE -o ro,loop$ntfs_support$OFFSET $IMG_SRC $MOUNT_DIR" 
      mount -t $FSTYPE -o ro,loop$ntfs_support$OFFSET $IMG_SRC $MOUNT_DIR
      echo ""
      [ "$(ls -A $MOUNT_DIR)" ] && makegreen "DIRECTORY LISTING OF MOUNTED IMAGE:  $MOUNT_DIR"
      echo ""
      ls $MOUNT_DIR
      echo ""
      [ "$(ls -A $MOUNT_DIR)" ] && makegreen "IMAGE SUCCESSFULLY MOUNTED!" || makered "IMAGE DID NOT MOUNT!"
      [ "$(ls -A $MOUNT_DIR)" ] &&  [ -e /mnt/ewf/ewf1 ]
}

#Identify and choose whether to mount any vss volumes
function mount_vss(){
      echo "vshadowmount /dev/loop0 /mnt/vss"
      [ "$FSTYPE" == "ntfs" ] && [ "$(ls -A $MOUNT_DIR)" ] && vshadowmount /dev/loop0 /mnt/vss
      ls /mnt/vss
      [ "$(ls -A /mnt/vss)" ] && makegreen "vsc(s) detected"  && echo "Mount all Volume Shadow Copies?" && yes-no 
      [ "$YES_NO" == "yes" ] && ls /mnt/vss|while read i; 
      do 
        mount -t ntfs -o ro,loop,show_sys_files,streams_interface=windows /mnt/vss/$i /mnt/shadow_mount/$i;
      done 
}
######### END DRIVE MOUNTING FUNCTIONS ###########

#Set destination folder for acquisition
function set_dsource_path(){
      # Set Case Destination Folder (Default = /cases/)
      makered "SET CASE DESTINATION FOLDER (Default = /cases/)"
      echo "Set Path or Enter to Accept:"
      read -e -p "" -i "/cases/" CASE_DIR   
      [ ! -d "${CASE_DIR}" ] && makered "Path does not exist.." && sleep 2 && show_menu  
      echo "Case Folder =>  $CASE_DIR"
      cd $CASE_DIR 
}
#Locates "Windows" and "System32" to compensate for case mismatches in directory names 
function set_windir(){
      WINDIR=$(find $MOUNT_DIR -maxdepth 1 -type d |grep -io windows$) 
      WINSYSDIR=$(find $MOUNT_DIR -maxdepth 2 -type d |grep -io windows\/system32)
      [ "$WINDIR" == "" ] || [ "$WINSYSDIR" == "" ] && makered "No Windows Directory Path Found on Source..." && sleep 2 && show_menu
      echo "Windows System32 Dir => $MOUNT_DIR/$WINSYSDIR"
}
# Determines if Windows OS is Windows XP by testing for a symbolic link to Users
function is_it_XP(){
    XP=$(file $MOUNT_DIR/Documents\ and\ Settings |grep symbolic)
    [ "$XP" != "" ] && USER_DIR="Users" || USER_DIR="Documents and Settings"
    echo "Users Directory => $MOUNT_DIR/$USER_DIR" 
}
# Runs Regripper "Compname" plugin on System registry hive
function get_computer_name(){
   [ "$DRV" == "" ]  && COMPNAME=$(find $MOUNT_DIR/$WINSYSDIR -maxdepth 4 -type f |egrep -m1 -i config\/system$| while read d; do rip.pl -r "$d" -p compname 2>/dev/null |grep -i "computername   "|awk -F'= ' '{ print $2 }';done) 
   [ "$COMPNAME" == "" ] && COMPNAME=$(date +'%Y-%m-%d-%H%M')
   echo "ComputerName:" $COMPNAME
}
# Creates Output Directories
function create_artifact_dir(){ 
    [ "$DRV" == "" ]  && DRV="LOCAL" 
    mkdir -p /$CASE_DIR/$COMPNAME/Artifact/$DRV
    [ "$(ls -A /mnt/vss)" ] && ls /mnt/vss|while read DRV; do [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && mkdir -p /$CASE_DIR/$COMPNAME/Artifact/$DRV ;done
}
# Creates Output Directories for any mounted VSS volumes 
function vss_create_artifact_dir(){
    [ "$(ls -A /mnt/vss)" ] && ls /mnt/shadow_mount|while read DRV; do [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && create_artifact_dir;done
}
# Creates directories to hold Triage data
function create_triage_dir(){ 
    [ -d "${CASE_DIR}" ] && mkdir -p $CASE_DIR/Triage/Program_Execution && mkdir -p $CASE_DIR/Triage/File_Access 
    [ -d "${CASE_DIR}" ] && mkdir -p $CASE_DIR/Triage/USB_Access && mkdir -p $CASE_DIR/Triage/Account_Usage && mkdir -p $CASE_DIR/Triage/Browser_Activity/Proxy
    [ -d "${CASE_DIR}" ] && mkdir -p $CASE_DIR/Triage/User_Searches && mkdir -p $CASE_DIR/Triage/Regripper && mkdir -p $CASE_DIR/Triage/Timeline/TLN
    [ -d "${CASE_DIR}" ] && mkdir -p $CASE_DIR/Triage/Persistence && mkdir -p $CASE_DIR/Triage/WinEvent_Logs
}
###############################################################
##############ACQUISITION FUNCTIONS############################
###############################################################

#Copies $MFT from mounted volume to cases directory
function get_mft(){
    makegreen "Copying \$MFT " 
    cp $MOUNT_DIR/\$MFT /$CASE_DIR/$COMPNAME/Artifact/$DRV && ls /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$MFT 
    [ -f "/$CASE_DIR/$COMPNAME/Artifact/$DRV/\$MFT" ]  && makegreen "complete!" || echo "\$MFT Info not acquired"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
} 
#Copies Windows Registry Files to cases directory
function get_registry(){
    [ "$DRV" == "LOCAL" ] && cd $MOUNT_DIR  
    makegreen "Copying $DRV WINDOWS REGISTRY"
    find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i \/system$ |sed 's|^\./||' |while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
    find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i \/software$ |sed 's|^\./||' |while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
    find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i \/security$ |sed 's|^\./||' |while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done     
    find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i \/sam$ |sed 's|^\./||' |while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f |grep -i windows\/system32\/config && makegreen "complete!"  || echo "NO $DRV REGISTRY FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
      cd /mnt/shadow_mount/$DRV
      makegreen "Copying $DRV REGISTRY"
      [ -d /mnt/shadow_mount/$DRV/$WINSYSDIR ] && find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i system$|while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
      [ -d /mnt/shadow_mount/$DRV/$WINSYSDIR ] && find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i software$|while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
      [ -d /mnt/shadow_mount/$DRV/$WINSYSDIR ] && find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i security$|while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done     
      [ -d /mnt/shadow_mount/$DRV/$WINSYSDIR ] && find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i sam$|while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null|grep -i windows\/system32\/config && makegreen "complete!" ||echo "NO $DRV REGISTRY FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
# Copies User profile registry hives (NTUSER.DAT) for each user to the cases directory
function get_ntuser(){
    makegreen "Copying $DRV NTUSER.DAT"
    [ "$USER_DIR" == "Users" ] && cd $MOUNT_DIR/$USER_DIR && find . -maxdepth 2 -type f| grep -i ntuser.dat$| sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" != "Users" ] && cd $MOUNT_DIR/Documents\ and\ Settings && find . -maxdepth 2 -type f| grep -i ntuser.dat$| sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents and Settings" || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "\/ntuser.dat$" && makegreen "complete!"  || echo "NO $DRV NTUSER.DAT FILES!" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
     makegreen "Copying $DRV NTUSER.DAT"
     cd /mnt/shadow_mount/$DRV
     [ "$USER_DIR" == "Users" ] && cd $USER_DIR && find . -maxdepth 2 -type f| grep -i ntuser.dat$| sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings && find . -maxdepth 2 -type f| grep -i ntuser.dat$| sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents and Settings"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "\/ntuser.dat$" && makegreen "complete!" || echo "NO $DRV NTUSER.DAT FILES!" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     sleep .5
     echo ""
    done
}
#Copies USRCLASS.DAT files to the cases directory
function get_usrclass.dat(){
    makegreen "Copying $DRV USRCLASS.DAT"
    cd $MOUNT_DIR
    [ "$USER_DIR" == "Users" ] && cd $USER_DIR
    [ "$USER_DIR" == "Users" ] && find ./*/AppData/Local/Microsoft/Windows -type f 2>/dev/null | grep -i \/UsrClass.dat$ | sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR";done
    [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
    [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Microsoft/Windows -type f 2>/dev/null | grep -i \/UsrClass.dat$  | sed 's|^\./||'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR" || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\/UsrClass.dat$" && makegreen "complete!" || echo "NO $DRV USRCLASS.DAT FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV USRCLASS.DAT"
      cd /mnt/shadow_mount/$DRV/$USER_DIR
      [ "$USER_DIR" == "Users" ] && find ./*/AppData/Local/Microsoft/Windows -type f 2>/dev/null | grep -i "\/UsrClass.dat$" | sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$USER_DIR" != "Users" ] && cd /mnt/shadow_mount/Documents\ and\ Settings
      [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Microsoft/Windows -type f 2>/dev/null | grep -i \/UsrClass.dat$ | sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\/UsrClass.dat$" &&  makegreen "complete!" || echo "NO $DRV USRCLASS.DAT FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
#Copies Amcache.hve and or Recentfilecache.bcf to cases directory
function get_Amcache.hve(){
    makegreen "Copying $DRV AMCACHE.HVE and RECENTFILECACHE.BCF" 
    [ "$USER_DIR" == "Users" ] && cd $MOUNT_DIR
    [ "$USER_DIR" == "Users" ] && find $WINDIR/AppCompat/Programs -maxdepth 1 -type f 2>/dev/null |grep -i \/Amcache.hve$ |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" == "Users" ] && find $WINDIR/AppCompat/Programs -maxdepth 1 -type f 2>/dev/null |grep -i \/Recentfilecache.bcf$ |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR/AppCompat/Programs -type f 2>/dev/null && makegreen "complete!" || echo "NO $DRV AMCACHE or RECENTFILECACHE FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV AMCACHE.HVE/RECENTFILECACHE.BCF" 
      cd /mnt/shadow_mount/$DRV
      find $WINDIR/AppCompat/Programs -type f  2>/dev/null|grep -i \/Amcache.hve$ |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find $WINDIR/AppCompat/Programs -type f  2>/dev/null|grep -i \/Recentfilecache.bcf$ |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR/AppCompat/Programs -type f && makegreen "complete!" || echo "NO $DRV AMCACHE or RECENTFILECACHE FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
#Copies Setupapi logs to cases directory
function get_setupapi(){
    cd $MOUNT_DIR
    makegreen "Copying $DRV SETUPAPIDEV.LOG"
    [ -f $WINDIR/setupapi.log 2>/dev/null ] && cp $MOUNT_DIR/$WINDIR/setupapi.log /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR 
    find $WINDIR/[I,i][N,n][F,f] 2>/dev/null |grep -i setupapi|sed 's|^\./||'|while read d; do rsync -aRq  $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "setupapi" && makegreen "complete!" || echo "NO $DRV SETUPAPI LOGS!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV SETUPAPIDEV.LOG"
      cd /mnt/shadow_mount/$DRV
      [ -f /mnt/shadow_mount/$DRV/setupapi.log ] && cp $MOUNT_DIR/$WINDIR/setupapi.log /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR
      find  Windows/[I,i][N,n][F,f] 2>/dev/null|grep -i setupapi|sed 's|^\./||'|while read d; do rsync -aRq  $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR -type f | grep setupapi && makegreen "complete!" || echo "$DRV NO SETUPAPILOG FOUND" |tee -a /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      sleep .5
      echo ""
    done
}
#Copies Scheduled Tasks to cases directory
function get_scheduled_tasks(){
    makegreen "Copying $DRV SCHEDULED TASKS"
    cd $MOUNT_DIR
    find $WINSYSDIR -maxdepth 1 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find $WINDIR -maxdepth 1 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find $WINDIR/SysWow64 -maxdepth 1 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find $WINDIR -maxdepth 1 -type f 2>/dev/null | grep -i SchedLgU.Txt|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR -type f | grep Tasks && makegreen "complete!" || echo "NO SCHEDULED TASKS FOUND" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV SCHEDULED TASKS"
      cd /mnt/shadow_mount/$DRV
      find $WINSYSDIR -maxdepth 1 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find $WINDIR -maxdepth 1 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find $WINDIR/SysWow64 -maxdepth 1 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find $WINDIR -maxdepth 1 -type f 2>/dev/null | grep -i SchedLgU.Txt|sed 's|^\./||'|while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f | grep Tasks |while read d; do echo "$d";done 
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR -type f | grep Tasks && makegreen "complete!" || echo "$DRV NO SCHEDULED TASKS FOUND" |tee -a /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      sleep .5
      echo ""
    done
}
# Copies Windows System Security and Application Evtx and or Evt event logs to cases directory
function get_evtx(){
    makegreen "Copying $DRV WINDOWS EVENT LOGS"
    cd $MOUNT_DIR
    find $WINSYSDIR/[W,w]inevt/[L,l]ogs -type f -size +500M 2>/dev/null| grep -i evtx$| while read d; do echo "FILE OVER 500MB NOT COPIED!! $d" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" == "Users" ] && find $WINSYSDIR/[W,w]inevt/[L,l]ogs -maxdepth 1 -type f 2>/dev/null| grep -i '\.evtx$' | sed 's|^\./||'| while read d; do rsync -aRq --max-size=500M "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f |grep -Ei "\.evt$"\|"\.evtx$" && makegreen "complete!" || echo "NO $DRV WINDOWS EVENT LOGS!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
     makegreen "Copying $DRV WINDOWS EVT/EVTX"
     cd /mnt/shadow_mount/$DRV
     find $WINSYSDIR/[W,w]inevt/[L,l]ogs -type f -size +500M 2>/dev/null|grep -i evtx$| while read d; do echo "FILE OVER 500MB NOT COPIED!! $d" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ -d /mnt/shadow_mount/$DRV/$WINSYSDIR ] && [ "$USER_DIR" == "Users" ] && find $WINSYSDIR/[W,w]inevt/[L,l]ogs -maxdepth 1 -type f 2>/dev/null | grep -i '\.evtx$'| sed 's|^\./||'|sed 's/ /\\ /g'| while read d; do rsync -aRq --max-size=500M "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ -d /mnt/shadow_mount/$DRV/$WINSYSDIR ] && [ "$USER_DIR" != "Users" ] && find $WINSYSDIR/[C,c]onfig -maxdepth 1 -type f  |grep -i '\.evt$'|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null |grep -i "\.evtx$" && makegreen "complete!" || echo "NO $DRV WINDOWS EVENT LOGS!" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     sleep .5
     echo "" 
    done
}
# Copies Internet Explorer 10+/Edge browser WebcacheV...dat file to the cases directory
function get_webcache.dat(){
    makegreen "Copying $DRV WEBCACHEV0x.DAT"
    [ "$USER_DIR" == "Users" ] && cd $MOUNT_DIR/$USER_DIR
    [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Microsoft/Windows/WebCache -maxdepth 1 -type f 2>/dev/null| grep -i 'WebcacheV...dat$' |sed 's|^\./||'| sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR" || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i 'WebcacheV...dat$' && makegreen "complete!" || echo "NO $DRV IE WEBCACHEV0x.DAT FILES!"|tee -a /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
      makegreen "Copying $DRV WEBCACHEV0x.DAT"
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] &&  cd /mnt/shadow_mount/$DRV/$USER_DIR
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Microsoft/Windows/WebCache -type f 2>/dev/null | grep -i 'WebcacheV*.dat$' |sed 's|^\./||'| sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i 'WebcacheV...dat$' &&  makegreen "complete!" || echo "NO $DRV IE WEBCACHEV0x.DAT FILES!"|tee -a /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
# Copies Chrome History, Cookies, Bookmarks, Web Data, Login Data and other files to the cases directory
function get_chrome_history(){
     makegreen "Copying $DRV CHROME HISTORY"
     cd $MOUNT_DIR
     [ "$USER_DIR" == "Users" ] && cd $USER_DIR
     [ "$USER_DIR" == "Users" ] && find ./*/AppData/Local/Google/Chrome/User\ Data/Default -maxdepth 1 -type f 2>/dev/null|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR" || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
     [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Google/Chrome/User\ Data/Default -maxdepth 1 -type f 2>/dev/null| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i '\/Google\/Chrome' && makegreen "complete!" ||  echo "NO $DRV CHROME HISTORY FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
     makegreen "Copying $DRV CHROME HISTORY"
     cd /mnt/shadow_mount/$DRV 
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] && cd /mnt/shadow_mount/$DRV/$USER_DIR
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] && find ./*/AppData/Local/Google/Chrome/User\ Data/Default -maxdepth 1 -type f  2>/dev/null|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && cd /mnt/shadow_mount/$DRV/Documents\ and\ Settings
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Google/Chrome/User\ Data -type d 2>/dev/null| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type d 2>/dev/null | grep -i "\/Google\/Chrome\/User\ Data" &&  makegreen "complete!"|| echo "NO $DRV CHROME HISTORY FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5 
    done
}
#Copies Firefox sqlite databases to the cases directory
function get_ff_places.sqlite(){
     makegreen "Copying $DRV FIREFOX HISTORY"
     [ "$USER_DIR" == "Users" ] &&  cd $MOUNT_DIR/$USER_DIR
     [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Roaming/Mozilla/Firefox/Profiles -type f 2>/dev/null | grep -i "\.sqlite$" |sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] &&  cd $MOUNT_DIR/Documents\ and\ Settings
     [ "$USER_DIR" != "Users" ] &&  find ./*/Application\ Data/Mozilla/Firefox/Profiles/*/ -type f 2>/dev/null | grep -i "\.sqlite$" |sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.sqlite$" && makegreen "complete!" || echo "NO $DRV FIREFOX SQLITE DB FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
      makegreen "Copying $DRV FIREFOX HISTORY"
     [ "$USER_DIR" == "Users" ] && cd /mnt/shadow_mount/$DRV/$USER_DIR
     [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Mozilla/Firefox/Profiles -type f 2>/dev/null | grep -i "\.sqlite$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && cd /mnt/shadow_mount/$DRV/Documents\ and\ Settings
     [ "$USER_DIR" != "Users" ] && find ./*/Application\ Data/Mozilla/Firefox/Profiles -type f 2>/dev/null | grep -i "\.sqlite$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done 
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.sqlite$" &&  makegreen "complete!" || echo "NO $DRV FIREFOX SQLITE DB FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    done
}
#copiet the Skype's main.db file to the cases directory
function get_skype(){
     makegreen "Copying $DRV Skype Main.db"
     cd $MOUNT_DIR
     [ "$USER_DIR" == "Users" ] && cd $USER_DIR
     [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Skype -type f 2>/dev/null| grep -i 'main.db$'|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
     [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Skype -type f 2>/dev/null| grep -i 'main.db$'| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i '\/Google\/Chrome' && makegreen "complete!" ||  echo "NO $DRV SKYPE LOGS FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV;
    do 
     makegreen "Copying $DRV Skype Main.db"
     cd /mnt/shadow_mount/$DRV
     cd $MOUNT_DIR
     [ "$USER_DIR" == "Users" ] && cd $USER_DIR
     [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Skype -type f 2>/dev/null| grep -i 'main.db$'|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
     [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Skype -type f 2>/dev/null| grep -i 'main.db$'| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i 'main.db$' && makegreen "complete!" ||  echo "NO $DRV SKYPE LOGS FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    done
} 
#copies Flash Cookies to the cases directory
function get_flash_cookies(){
     makegreen "Copying $DRV FLASH COOKIES"
     cd $MOUNT_DIR
    [ "$USER_DIR" == "Users" ] && cd $USER_DIR 
    [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Macromedia/Flash\ Player -type f 2>/dev/null | grep -i "\.sol$"| sed 's|^\./||'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
    [ "$USER_DIR" != "Users" ] && find ./*/Application\ Data/Macromedia/Flash\ Player -type f | grep -i "\.sol$"| sed 's|^\./||'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents and Settings"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "sol$" && makegreen "complete!"  || echo "NO $DRV FLASH COOKIES FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV;
    do 
      makegreen "Copying $DRV FLASH COOKIES"
      cd /mnt/shadow_mount/$DRV 
      [ "$USER_DIR" == "Users" ] && cd $USER_DIR 
      [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Macromedia/Flash\ Player -type f 2>/dev/null | grep -i "\.sol$"| sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
      [ "$USER_DIR" != "Users" ] && find ./*/Application\ Data/Macromedia/Flash\ Player -type f 2>/dev/null | grep -i "\.sol$"| sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents and Settings"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "sol$" && makegreen "complete!"  || echo "NO $DRV FLASH COOKIES FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
# Copies any index.dat (Internet Explorer 9 and below) files to the cases directory
function get_index.dat(){
     makegreen "Copying $DRV INDEX.DAT"
     cd $MOUNT_DIR
    [ "$USER_DIR" == "Users" ] && cd $USER_DIR 
    [ "$USER_DIR" == "Users" ] && find ./*/AppData -type f 2>/dev/null | grep -i "\/index.dat$"| sed 's|^\./||'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
    [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings -type f 2>/dev/null | grep -i "\/index.dat$"| sed 's|^\./||'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents and Settings"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "\/index.dat$" && makegreen "complete!"  || echo "NO $DRV INDEX.DAT FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
     makegreen "Copying $DRV INDEX.DAT"
     cd /mnt/shadow_mount/$DRV 
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] && cd $USER_DIR && find ./*/AppData find -type f -size +5k 2>/dev/null| grep -i index.dat$ | sed 's|^\./||'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
     [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && find -type f -size +5k 2>/dev/null| grep -i index.dat$ |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq "$d" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents and Settings"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "\/index.dat$" &&  makegreen "complete!"|| echo "NO $DRV INDEX.DAT FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    done   
}
# Copies Browser cache from Chrome and Firefox to the cases directory 
function get_browser_cache(){
     makegreen "Copying $DRV BROWSER CACHE"
     cd $MOUNT_DIR
     [ "$USER_DIR" == "Users" ] && cd $USER_DIR
     [ "$USER_DIR" == "Users" ] && find ./*/AppData/Local/Google/Chrome/User\ Data/Default/Cache -type f 2>/dev/null|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Mozilla/Firefox/Profiles/*/Cache -type f 2>/dev/null | sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Microsoft/Windows/Temporary\ Internet\ Files/Content.IE5 -type f 2>/dev/null | sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo """$d""" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Microsoft/Windows/INetCache -type f 2>/dev/null | sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
     [ "$USER_DIR" != "Users" ] && find ./*/Application\ Data/Google/Chrome/User\ Data/Default/Cache -type f | sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] &&  find ./*/Application\ Data/Mozilla/Firefox/Profiles/*/Cache -type f |sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i '\/Google\/Chrome' &&  makegreen "complete!" || echo "NO $DRV GOOGLE CHROME CACHE FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i 'Firefox\/Profiles\/.\/Cache' &&  makegreen "complete!" || echo "NO $DRV FIREFOX CACHE FILES!" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
       makegreen "Copying $DRV BROWSER CACHE"
       cd $MOUNT_DIR
       [ "$USER_DIR" == "Users" ] && cd $USER_DIR
       [ "$USER_DIR" == "Users" ] && find ./*/AppData/Local/Google/Chrome/User\ Data/Default/Cache -type f 2>/dev/null|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq "\""$d"\"" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
       [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Mozilla/Firefox/Profiles/*/Cache -type f 2>/dev/null | sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq "\""$d"\"" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
       [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Microsoft/Windows/Temporary\ Internet\ Files/Content.IE5 -type f 2>/dev/null | sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
       [ "$USER_DIR" == "Users" ] &&  find ./*/AppData/Local/Microsoft/Windows/INetCache -type f 2>/dev/null | sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
       [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
       [ "$USER_DIR" != "Users" ] && find ./*/Local\ Settings/Application\ Data/Google/Chrome/User\ Data/Default/Cache -type f | sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
       [ "$USER_DIR" != "Users" ] &&  find ./*/Local\ Settings/Application\ Data/Mozilla/Firefox/Profiles/./Cache -type f 2>/dev/null |sed 's|^\./||'|sed 's/ /\\ /g' |while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
       find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i '\/Google\/Chrome'  &&  makegreen "complete!" || echo "NO $DRV GOOGLE CHROME CACHE FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
       find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i 'Firefox\/Profiles\/.\/Cache' &&  makegreen "complete!" || echo "NO $DRV FIREFOX CACHE FILES!" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
       echo ""
       sleep .5
    done 
}
#Copies lnk files to the cases directory
function get_lnk_files(){
    makegreen "Copying $DRV LNK FILES"
    [ "$USER_DIR" == "Users" ] && cd $MOUNT_DIR/$USER_DIR
    [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Microsoft/Windows/Recent -type f 2>/dev/null|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Microsoft/Office/Recent -type f 2>/dev/null|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" == "Users" ] && find -type f 2>/dev/null|grep -vi AppData|grep -i "\.lnk$"| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    [ "$USER_DIR" != "Users" ] && cd $MOUNT_DIR/Documents\ and\ Settings
    [ "$USER_DIR" != "Users" ] && find ./*/Recent -maxdepth 1 -type f 2>/dev/null | grep -i "\.lnk$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents\ and\ Settings|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.lnk$" && makegreen "complete!" || echo "NO LNK FILES FOUND! "| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
   [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV;  
    do 
      makegreen "Copying $DRV LNK FILES"
      [ "$USER_DIR" == "Users" ] && cd /mnt/shadow_mount/$DRV/$USER_DIR
      [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Microsoft/Windows/Recent -type f 2>/dev/null |grep -i "lnk$"|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Microsoft/Windows/Recent/ -type f 2>/dev/null |grep -i "destinations-ms$"|sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$USER_DIR" == "Users" ] && find ./*/AppData/Roaming/Microsoft/Office/Recent -type f 2>/dev/null| grep -i \.lnk$ |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$USER_DIR" != "Users" ] && cd $MOUNT_DIR/Documents\ and\ Settings
      [ "$USER_DIR" != "Users" ] && find ./*/Recent -type f 2>/dev/null | grep -i "\.lnk$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do echo "\""$d"\"" && rsync -aRq """$d""" "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR"|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR -type f |grep -i "\.lnk$" &&  makegreen "complete!" || echo "NO $DRV LNK FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
 #Copies Prefetch files to the cases directory
function get_prefetch(){
     makegreen "Copying $DRV PREFETCH"
     cd $MOUNT_DIR
     find $WINDIR/Prefetch -maxdepth 1 -type f 2>/dev/null | grep -i "\pf$"| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt ;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.pf$" && makegreen "complete!" || echo "NO $DRV PREFETCH FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV PREFETCH"
      cd /mnt/shadow_mount/$DRV
      find $WINDIR/Prefetch -type f 2>/dev/null | grep -i "\.pf$"| sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -aRq  "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.pf$" && makegreen "complete!" || echo "NO $DRV PREFETCH FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
#Copies metadata in the Windows Recycle.bin/Recycler Extracts to the cases directory
function get_Recycle.Bin(){
     makegreen "Copying $DRV RECYCLE BIN"
     cd $MOUNT_DIR
     [ "$USER_DIR" == "Users" ] && find \$[Rr]*[Nn]/ -type f|grep \/\$I|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ "$USER_DIR" != "Users" ] && find [Rr]*[Rr]/ -type f| grep -i "INFO2$"|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f 2>/dev/null | grep -i "recycle" && makegreen "complete!" || echo "NO $DRV RECYCLED FILES!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$| while read DRV; 
    do 
      makegreen "Copying $DRV RECYCLE BIN"
      cd /mnt/shadow_mount/$DRV
      [ "$USER_DIR" == "Users" ] && find -type f 2>/dev/null |grep -i \$I |while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$USER_DIR" != "Users" ] && find $MOUNT_DIR/\RECYCLER -type f 2>/dev/null |grep -i INFO2 |while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      ls -R /$CASE_DIR/$COMPNAME/Artifact/$DRV |grep -i "\$recycle" &&  makegreen "complete!" || echo "NO $DRV RECYCLED FILES FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      sleep .5
     echo ""
    done  
} 
#Copies Windows Log files to cases directory
function get_logfiles(){
     cd $MOUNT_DIR
     makegreen "Copying $DRV LOG FILES"
     [ -d "inetpub" ] && find inetpub -type f -size +100M 2>/dev/null | grep -i "\.log$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -trRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     [ -d "$WINSYSDIR/LogFiles" ]  && find $WINSYSDIR/LogFiles -size +100M -type f 2>/dev/null | grep -i "\.log$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -trRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find -maxdepth 1 -type f -size +100M  2>/dev/null | grep -i "pfirewall.log$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -trRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR -type f -size +100M |grep -vi setupapi |grep -i "\.log$" && makegreen "complete!" || echo "NO WINDOWS LOGS FOUND!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
     echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do 
      makegreen "Copying $DRV LOGS "
      cd /mnt/shadow_mount/$DRV
      [ -d "inetpub" ] && find inetpub -type f 2>/dev/null | grep -i "\.log$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -tvrRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ -d "$WINSYSDIR/LogFiles" ]  && find $WINSYSDIR/LogFiles -type f 2>/dev/null | grep -i "\.log$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -tvrRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find -maxdepth 1 -type f 2>/dev/null | grep -i "pfirewall.log$" |sed 's|^\./||'|sed 's/ /\\ /g'|while read d; do rsync -tvrRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV/$WINDIR -type f 2>/dev/null|grep -vi setupapi |grep -i "\.log$" && makegreen "complete!"|| echo "$DRV NO LOG FILES FOUND" |tee -a /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      echo ""
      sleep .5
    done
}
#Scans mounted volumes and extracts file names and timestamps of Alternate Data Streams to the cases directory 
function ADS_extract(){
    cd $MOUNT_DIR
    makegreen "Extracting Alternate Data Streams from $DRV"
    #  scan mounted disk for ntfs streams
    [ "$(mountpoint $MOUNT_DIR|grep -vi not)" ] && getfattr -Rn ntfs.streams.list . 2>/dev/null |grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'|while read d; 
    do 
      printf %s "$d"|sed 's/.*# file: /\"\n"/g'|sed 's/"//g'>>/$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt;
    done
    echo "" >>  /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt 
    cat /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt |while read d; 
    do 
      a="$(stat --format "%X" "$MOUNT_DIR/$d" 2>/dev/null)" && echo "$a|ADS|$COMPNAME||[ADS]: /$d" |tee -a /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt;
    done
    sed -i '/||/!d' /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt
    [ -f "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt" ] && makegreen "complete!"  || echo "ADS Info not extracted for $DRV" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
    sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      cd /mnt/shadow_mount/$DRV
      makegreen "Extracting $DRV Alternate Data Streams"
      [ "$(mountpoint $MOUNT_DIR|grep -vi not)" ] && getfattr -Rn ntfs.streams.list . 2>/dev/null|grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'|while read d; 
        do 
          printf %s "$d"|sed 's/.*# file: /\"\n"/g'|sed 's/"//g'>>/$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt;
        done
      echo "" >>  /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt
      cat /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt |while read d; 
      do 
        a="$(stat --format "%X" "$MOUNT_DIR/$d" 2>/dev/null)" && echo "$a|ADS|$COMPNAME||[ADS]: /$d" |tee -a /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt;
      done
      sed -i '/||/!d' /$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt
      [ -f "/$CASE_DIR/$COMPNAME/Artifact/$DRV/$COMPNAME.ADS.txt" ] && makegreen "complete!"  || makered "ADS Info not extracted for $DRV" 
      echo ""
      sleep .5
    done
}
#Copies Copies Windows Journal file: USNJRNL:$J to cases directory
function get_usnjrnl(){
    makegreen "Copying $DRV \$UsnJrnl:\$J"
    [ -f /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL ]  || cp $MOUNT_DIR/\$Extend/\$UsnJrnl:\$J /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL  && ls /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL
    [ -f /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$LOGFILE ]  ||cp $MOUNT_DIR/\$LogFile /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$LogFile  && ls /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$LogFile
    [ -f "/$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL" ] && makegreen "complete!" || echo "Journal Info not extracted for $DRV" | tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    echo ""
     sleep .5
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV \$UsnJrnl:\$J"
      cd /mnt/shadow_mount/$DRV
      [ -f /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL ]  || cp /mnt/shadow_mount/$DRV/\$Extend/\$UsnJrnl:\$J /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL && ls /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$USNJRNL || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      [ -f /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$LogFile ] || cp /mnt/shadow_mount/$DRV/\$LogFile /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$LogFile  && ls /$CASE_DIR/$COMPNAME/Artifact/$DRV/\$LogFile || echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV -type f |grep -iq "\$USNJRNL$" && makegreen "complete!"|| makered "$DRV Journal Info not extracted!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt 
      echo ""
      sleep .5
    done    
}
#Locates and Copies any Outlook mail files to cases directory and then extracts mail files using pffexport
function get_outlook_data(){
    makegreen "Copying OUTLOOK OST/PST files"
    cd $MOUNT_DIR
    [ "$USER_DIR" == "Users" ] && cd $USER_DIR
    [ "$USER_DIR" == "Users" ] && find . -type f 2>/dev/null | grep -i "\.[p,o]st$"|sed 's|^\./||'|while read d; do echo "$d" && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR;done
    [ "$USER_DIR" != "Users" ] && cd Documents\ and\ Settings
    [ "$USER_DIR" != "Users" ] && find . -type f 2>/dev/null | grep -i "\.[p,o]st$"|sed 's|^\./||'|while read d; do echo "$d" && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents\ and\ Settings;done
    find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.[p,o]st$" && makegreen "complete!" || echo "No Outlook Mail Files Found!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV; 
    do
      makegreen "Copying $DRV OUTLOOK OST/PST files"
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] &&  cd /mnt/shadow_mount/$DRV/$USER_DIR
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] && find . -type f 2>/dev/null | grep -i "\.ost$" |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" == "Users" ] && find . -type f 2>/dev/null | grep -i "\.pst$" |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/$USER_DIR|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && cd /mnt/shadow_mount/$DRV/Documents\ and\ Settings
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && find . -type f 2>/dev/null | grep -i "\.ost$" |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents\ and\ Settings|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      [ "$(ls -A /mnt/shadow_mount/$DRV)" ] && [ "$USER_DIR" != "Users" ] && find . -type f 2>/dev/null | grep -i "\.pst$" |sed 's|^\./||'|while read d; do rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV/Documents\ and\ Settings|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
      find /$CASE_DIR/$COMPNAME/Artifact/$DRV 2>/dev/null | grep -i "\.[p,o]st$" && makegreen "complete!" || echo "NO Outlook Mail Files Found!"| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    done
}
# Collect Volatilile data files and copies them to the cases folder
function get_volatile(){
    cd $MOUNT_DIR
    makegreen "Searching for DMP files"
    find . -type f 2>/dev/null| grep -i "\.dmp$" |while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    makegreen "Searching for HIBERFIL.SYS"
    find . -maxdepth 1 -type f 2>/dev/null | grep -i hiberfil.sys | while read d; do echo "copying $d" && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    makegreen "Searching for PAGEFILE.SYS"
    find . -maxdepth 1 -type f 2>/dev/null | grep -i pagefile.sys | while read d; do echo "copying $d" && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    makegreen "Searching for SWAPFILE.SYS files"
    find . -maxdepth 1 -type f 2>/dev/null | grep -i swapfile.sys | while read d; do echo "copying $d" && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
    makegreen "$DRV Volatile Acquisition Complete!"
    [ "$(ls -A /mnt/vss)" ] && ls /$CASE_DIR/$COMPNAME/Artifact |grep -v LOCAL$ | while read DRV;
    do
     makegreen "Collecting Volatile Data From $DRV"
     cd /mnt/shadow_mount/$DRV
     find . -type f| grep -i "\.dmp$" |while read d; do rsync -aRq $d /$CASE_DIR/$COMPNAME/Artifact/$DRV;done
     find . -maxdepth 1 -type f 2>/dev/null| grep -i hiberfil.sys | while read d; do echo $d && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find . -maxdepth 1 -type f 2>/dev/null| grep -i pagefile.sys | while read d; do echo $d && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     find . -maxdepth 1 -type f 2>/dev/null| grep -i swapfile.sys | while read d; do echo $d && rsync -aRq "$d" /$CASE_DIR/$COMPNAME/Artifact/$DRV|| echo "RSYNC COPY ERROR!!! $d" |tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt;done
     makegreen "$DRV Volatile Completed!"
    done
}
########END DATA ACQUISITION FUNCTIONS######
    
#########DATA PROCESSING FUNCTIONS##############
# reusable interactive yes-no function 
function yes-no(){
      read -p "(Y/N)?"
      [ "$(echo $REPLY | tr [:upper:] [:lower:])" == "y" ] &&  YES_NO="yes";
}
# Set Processing Source Path
function set_psource_path(){
      echo ""
      makegreen  "Default Case Destination Folder"
      # Default case folder is /cases
      # Edit or add Find Statement(s) to customize case folder location 
      find /cases/* -maxdepth 0 -type d 2>/dev/null
      echo ""
      echo "Enter Source Path of Evidence to Process:"
      read -e -p "" -i "" CASE_DIR
      cd $CASE_DIR
      echo $CASE_DIR |sed 's/\/$//'|grep -oi \/cases$ && CASE_ID=$(ls -1d */ |sed 's/\/$//'|sed '/^\/.*/d'|while read d; do echo $d;done)
      [ "$CASE_ID" == "" ] && MULTI_CASE="no" && COMPNAME=$( echo "$CASE_DIR"|sed 's/\/$//'|awk -F"/" '{print $NF}')
      [ ! -d "${CASE_DIR}" ] && makered "Path does not exist.." && sleep 1 && show_menu  
      cd $CASE_DIR 
}
## Run RegRipper to get Windows version info from Registry ##
function get_winverinfo(){
    cd $CASE_DIR
    makegreen "Searching for GENERAL INFORMATION about System(s)"
    sleep 1  
    [ -d "${CASE_DIR}/Triage/Regripper" ] && rip.pl -c -l 2>/dev/null >> $CASE_DIR/Triage/Regripper/_RegRipperPlugins.txt
    [ "$MULTI_CASE" == "no" ] && [ -d "${CASE_DIR}/Triage" ] && find $CASE_DIR -type f 2>/dev/null | grep -m1 -i "\/software$"| while read d; 
    do  
        rip.pl -r $d -p winnt_cv |tee -a $CASE_DIR/Triage/Windows_Ver_Info-$COMPNAME.txt;
      done
    [ "$MULTI_CASE" != "no" ] && [ -d "${CASE_DIR}/Triage" ] && echo "$CASE_ID" | while read COMPNAME; 
      do 
        find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -m1 -i "\/software$"| while read d; 
          do 
            rip.pl -r $d -p winnt_cv |tee -a $CASE_DIR/Triage/Windows_Ver_Info-$COMPNAME.txt;
          done 
      done 
}
## Run RegRipper to get Last Logged on Users ##
function get_last_logged_on(){
    cd $CASE_DIR
    makegreen "Searching for LAST LOGGED ON USER (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] && [ -d "${CASE_DIR}/Triage/Account_Usage" ] && find $CASE_DIR -type f 2>/dev/null | grep -m1 -i "\/software$"| while read d; 
      do 
        rip.pl -r $d -p lastloggedon |tee -a $CASE_DIR/Triage/Account_Usage/Last-Logged-On-$COMPNAME.txt;
      done 
    [ "$MULTI_CASE" != "no" ] && [ -d "${CASE_DIR}/Triage/Account_Usage" ] && echo "$CASE_ID" | while read COMPNAME;
      do 
        find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -m1 -i "\/software$"| while read d; 
          do 
            rip.pl -r $d -p lastloggedon |tee -a $CASE_DIR/Triage/Account_Usage/Last-Logged-On-$COMPNAME.txt;
          done 
      done
}
## Run RegRipper to get Network Connection info from Registry ##
function get_network_info(){
    cd $CASE_DIR
    makegreen "Searching for NETWORK Info and profiles (Regripper)"
    sleep 1 
    #  Get Last Network and Share information 
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -m1 -i "\/system$"| while read d; 
      do 
        rip.pl -r $d -p nic2 2>/dev/null |tee -a $CASE_DIR/Triage/Account_Usage/Last-Networks-$COMPNAME.txt;
        rip.pl -r "$d" -p shares 2>/dev/null|tee -a $CASE_DIR/Triage/Account_Usage/Share-Info-$COMPNAME.txt;
      done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
      do 
        find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -m1 -i "\/system$"| while read d; 
        do 
          rip.pl -r $d -p nic2 2>/dev/null |tee -a $CASE_DIR/Triage/Account_Usage/Last-Networks-$COMPNAME.txt;
          rip.pl -r "$d" -p shares 2>/dev/null|tee -a $CASE_DIR/Triage/Account_Usage/Share-Info-$COMPNAME.txt;
        done
      done
    # GetNetwork List 
    [ "$MULTI_CASE" == "no" ]  && find $CASE_DIR -type f 2>/dev/null | grep -m1 -i "\/software$"| while read d; 
      do 
        rip.pl -r "$d" -p networklist 2>/dev/null |tee -a $CASE_DIR/Triage/Account_Usage/Network-List-$COMPNAME.txt;
        rip.pl -r $d -p profilelist 2>/dev/null |tee -a $CASE_DIR/Triage/Account_Usage/User-Profiles-$COMPNAME.txt;
      done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
      do 
        find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -m1 -i "\/software$"| while read d; 
        do 
          rip.pl -r "$d" -p networklist 2>/dev/null |tee -a $CASE_DIR/Triage/Account_Usage/Network-List-$COMPNAME.txt;
          rip.pl -r $d -p profilelist 2>/dev/null |tee -a $CASE_DIR/Triage/Account_Usage/User-Profiles-$COMPNAME.txt;
        done
      done
}
## Run RegRipper to get User's Proxy configurations from Registry ##
function get_proxy(){
    cd $CASE_DIR
    makegreen "Searching for USER PROXY SETTINGS (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\/ntuser.dat$"| while read d; 
    do
      USER_NAME=$(echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
  rip.pl -r $d -p proxysettings |tee -a $CASE_DIR/Triage/Browser_Activity/Proxy/Proxy-Settings-$COMPNAME-$USER_NAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/ntuser.dat$"| while read d; 
      do
        USER_NAME=$(echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
        rip.pl -r $d -p proxysettings |tee -a $CASE_DIR/Triage/Browser_Activity/Proxy/Proxy-Settings-$COMPNAME-$USER_NAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
      done
    done
}
## Run RegRipper to Account info from SAM##
function regrip_sam(){
    cd $CASE_DIR
    makegreen "Searching for SAM (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\/sam$"| while read d; 
    do 
      rip.pl -r "$d" -p samparse |tee -a $CASE_DIR/Triage/Regripper/SAM-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/sam$"| while read d; 
      do 
        rip.pl -r "$d" -p samparse |tee -a $CASE_DIR/Triage/Regripper/SAM-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
      done
    done
}  
## Run RegRipper on NTUSER.DAT files ##
function regrip_NTUSER(){
    cd $CASE_DIR
    makegreen "Regripper is Extracting NTUSER.DATs"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] && [ -d "${CASE_DIR}/Triage/Regripper" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\/ntuser.dat$" |while read d; 
    do
      USER_NAME=$(echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      rip.pl -r "$d" -f ntuser >> $CASE_DIR/Triage/Regripper/NTUSER-"$COMPNAME"-"$USER_NAME"-"$COUNTER".txt && COUNTER=$((COUNTER +1));
    done
    [ "$MULTI_CASE" != "no" ] && [ -d "${CASE_DIR}/Triage/Regripper" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/ntuser.dat$" |while read d;
      do
        USER_NAME=$(echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
        rip.pl -r "$d" -f ntuser >> $CASE_DIR/Triage/Regripper/NTUSER-"$COMPNAME"-"$USER_NAME"-"$COUNTER".txt && COUNTER=$((COUNTER +1));
      done
    done  
}
## Run RegRipper on SYSTEM registry files ##
function regrip_system(){
    cd $CASE_DIR
    makegreen "Searching for SYSTEM (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\/system$"| while read d; 
    do 
      rip.pl -r "$d" -f system |tee -a $CASE_DIR/Triage/Regripper/SYSTEM-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
      do
        cd $CASE_DIR/$COMPNAME
        COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/system$"| while read d; 
          do 
            rip.pl -r "$d" -f system |tee -a $CASE_DIR/Triage/Regripper/SYSTEM-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
          done
      done
}
## Run RegRipper on SOFTWARE registry files ##
function regrip_software(){
    cd $CASE_DIR
    makegreen "Searching for SOFTWARE (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\/software$"| while read d; 
    do 
      rip.pl -r "$d" -f software |tee -a $CASE_DIR/Triage/Regripper/SOFTWARE-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
      do 
        cd $CASE_DIR/$COMPNAME  
        COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i software$| while read d; 
          do 
            rip.pl -r "$d" -f software |tee -a $CASE_DIR/Triage/Regripper/SOFTWARE-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
          done
      done
}  
## Run RegRipper on SECURITY registry files ##
function regrip_security(){
    cd $CASE_DIR
    makegreen "Searching for SECURITY (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\/security$"| while read d; 
    do 
      rip.pl -r "$d" -f security |tee -a $CASE_DIR/Triage/Regripper/SECURITY-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
      do
        cd $CASE_DIR/$COMPNAME  
        COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/security$"| while read d; 
        do 
          rip.pl -r "$d" -f security |tee -a $CASE_DIR/Triage/Regripper/SECURITY-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
        done
      done
}  
# Create Timelines Using RegRipper's TLN plugins 
function regrip_security_tln(){
    cd $CASE_DIR
    # Process Security registry hives and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -ia "\/security$"| while read d; 
    do
      rip.pl -r "$d" -p secrets_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SECRETS.TLN.TMP
      rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/security$"| while read d;
      do
        rip.pl -r "$d" -p secrets_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SECRETS.TLN.TMP;
        rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
      done
    done
    cat $CASE_DIR/Triage/Timeline/TLN/SECRETS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SECRETS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SECRETS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    makegreen "SAM TLN Complete!"
} 
# Run Regripper samparse_tln 
function regrip_sam_tln(){ 
    cd $CASE_DIR
    # Process Sam registry hives and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -i "\/sam$"| while read d; 
    do
      rip.pl -r "$d" -p samparse_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|SAM||/|SAM|${COMPNAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SAM.TLN.TMP;
      rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|SAM||/|SAM|${COMPNAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/sam$"| while read d;
      do
        rip.pl -r "$d" -p samparse_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|SAM||/|SAM|${COMPNAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SAM.TLN.TMP;
        rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|SAM||/|SAM|${COMPNAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
      done
    done
    makegreen "Sorting..."
    cat $CASE_DIR/Triage/Timeline/TLN/SAM.TLN.TMP | sort -rn| uniq | tee -a $CASE_DIR/Triage/Timeline/TLN/SAM.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SAM.TLN.TMP
    cat $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    makegreen "SAM TLN Complete!"
}
function regrip_system_tln(){ 
    cd $CASE_DIR
    # Process System registry hives and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -i "\/system$"| while read d; 
    do
      rip.pl -r "$d" -p bthport_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/BLUETOOTH.TLN.TMP;
      rip.pl -r "$d" -p svc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SERVICE.TLN.TMP;
      rip.pl -r "$d" -p legacy_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/LEGACY.TLN.TMP;
      rip.pl -r "$d" -p appcompatcache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPCOMPATCACHE.TLN.TMP;
      rip.pl -r "$d" -p shimcache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SHIMCACHE.TLN.TMP;
      rip.pl -r "$d" -p bam_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/BAM.TLN.TMP;
      rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/system$"| while read d;
      do
        rip.pl -r "$d" -p bthport_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/BLUETOOTH.TLN.TMP;
        rip.pl -r "$d" -p svc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SERVICE.TLN.TMP;
        rip.pl -r "$d" -p legacy_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/LEGACY.TLN.TMP;
        rip.pl -r "$d" -p appcompatcache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPCOMPATCACHE.TLN.TMP;
        rip.pl -r "$d" -p shimcache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SHIMCACHE.TLN.TMP;
        rip.pl -r "$d" -p bam_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/BAM.TLN.TMP;
        rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
      done
    done
    makegreen "Sorting..."
    cat $CASE_DIR/Triage/Timeline/TLN/BLUETOOTH.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/BLUETOOTH.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/BLUETOOTH.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/SERVICE.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SERVICE.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SERVICE.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/LEGACY.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/LEGACY.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/LEGACY.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/APPCOMPATCACHE.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/APPCOMPATCACHE.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/APPCOMPATCACHE.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/SHIMCACHE.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SHIMCACHE.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SHIMCACHE.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/BAM.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/BAM.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/BAM.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    makegreen "SYSTEM TLN Complete!"

}  
function regrip_usrclass_tln(){ 
    cd $CASE_DIR
    # Process UsrClass.dat and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -i "\/usrclass.dat$"| while read d; 
    do
      rip.pl -r "$d" -p muicache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP;
      rip.pl -r "$d" -p legacy_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SHELLBAGS.TLN.TMP;
      rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/usrclass.dat$"| while read d;
      do  
        rip.pl -r "$d" -p muicache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP;
        rip.pl -r "$d" -p legacy_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SHELLBAGS.TLN.TMP;
        rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
      done
    done
    makegreen "Sorting..."
    cat $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/SHELLBAGS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SHELLBAGS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SHELLBAGS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    makegreen "UsrClass.data TLN Complete!"
} 
function regrip_amcache_tln(){ 
    cd $CASE_DIR
    # Process Amcache.hve and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -i "\/amcache.hve$"| while read d; 
    do
      rip.pl -r "$d" -p amcache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.TMP;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/amcache.hve$" | while read d;
      do
        rip.pl -r "$d" -p amcache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.TMP;
      done
    done
    makegreen "Recent File Cache TLN Complete!"
    #Process Recentfilecache.bcf and add to TLN 
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null |  grep -i "\/Recentfilecache.bcf$" | while read d;
    do
      perl /usr/local/bin/rfc.pl "$d"|while read rfc;
      do
        echo "0|shimcache|$COMPNAME||[Program Execution] RecentFileCache.bcf - "$rfc"" | tee -a $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.TMP;
      done
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      perl /usr/local/bin/rfc.pl "$d"|while read rfc;
      do
        echo "0|shimcache|$COMPNAME||[Program Execution] RecentFileCache.bcf - "$rfc"" | tee -a $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.TMP;
      done
    done
    makegreen "Sorting..."
    cat $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/RECENTFILECACHE.TLN.TMP;
    makegreen "Amcache/Recentfilecach TLN Complete!"
}
function regrip_software_tln(){ 
    cd $CASE_DIR
    # Process Software registry hives and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -i "\/software$" | while read d; 
    do
      rip.pl -r "$d" -p at_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/AT_JOBS.TLN.TMP;
      rip.pl -r "$d" -p networklist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/NETWORK_LIST.TLN.TMP;
      rip.pl -r "$d" -p urun_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SRUN.TLN.TMP;
      rip.pl -r "$d" -p appkeys_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP;
      rip.pl -r "$d" -p silentprocessexit_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SILENT_PROCESS_EXIT.TLN.TMP;
      rip.pl -r "$d" -p cmd_shell_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/CMD_SHELL.TLN.TMP;
      rip.pl -r "$d" -p uninstall_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP;
      rip.pl -r "$d" -p tracing_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TRACING.TLN.TMP; 
      rip.pl -r "$d" -p winlogon_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/WINLOGON.TLN.TMP;
      rip.pl -r "$d" -p landesk_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/LANDESK.TLN.TMP;
      rip.pl -r "$d" -p direct_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DIRECT.TLN.TMP;
      rip.pl -r "$d" -p logmein_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/LOGMEIN.TLN.TMP;
      rip.pl -r "$d" -p gpohist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/GPOHIST.TLN.TMP;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/software$" | while read d; 
      do  
        rip.pl -r "$d" -p at_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/AT_JOBS.TLN.TMP;
        rip.pl -r "$d" -p networklist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/NETWORK_LIST.TLN.TMP;
        rip.pl -r "$d" -p urun_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SRUN.TLN.TMP;
        rip.pl -r "$d" -p appkeys_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP;
        rip.pl -r "$d" -p silentprocessexit_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SILENT_PROCESS_EXIT.TLN.TMP;
        rip.pl -r "$d" -p cmd_shell_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/CMD_SHELL.TLN.TMP;
        rip.pl -r "$d" -p uninstall_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP;
        rip.pl -r "$d" -p tracing_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TRACING.TLN.TMP;
        rip.pl -r "$d" -p winlogon_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/WINLOGON.TLN.TMP;
        rip.pl -r "$d" -p landesk_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/LANDESK.TLN.TMP;
        rip.pl -r "$d" -p direct_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DIRECT.TLN.TMP;
        rip.pl -r "$d" -p logmein_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/LOGMEIN.TLN.TMP;
        rip.pl -r "$d" -p gpohist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/GPOHIST.TLN.TMP;
        # Disabled due to slow performance
        #rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
      done
    done
    makegreen "Sorting..."
    cat $CASE_DIR/Triage/Timeline/TLN/AT_JOBS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/AT_JOBS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/AT_JOBS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/NETWORK_LIST.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/NETWORK_LIST.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/NETWORK_LIST.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/SRUN.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SRUN.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SRUN.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/SILENT_PROCESS_EXIT.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SILENT_PROCESS_EXIT.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SILENT_PROCESS_EXIT.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/CMD_SHELL.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/CMD_SHELL.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/CMD_SHELL.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/TRACING.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/TRACING.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/TRACING.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/WINLOGON.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/WINLOGON.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/WINLOGON.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/LANDESK.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/LANDESK.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/LANDESK.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/DIRECT.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DIRECT.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DIRECT.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/LOGMEIN.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/LOGMEIN.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/LOGMEIN.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/GPOHIST.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/GPOHIST.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/GPOHIST.TLN.TMP;
    #cat $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP 2>/dev/null | sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    makegreen "SOFTWARE TLN Complete!"
}
function regrip_ntuser_tln(){ 
    cd $CASE_DIR
    # Process NTUSER registry hives and add to TLN  
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null | grep -i "\/ntuser.dat$" | while read d; 
    do
      USER_NAME=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      [ TLNSuuport="Yes" ] && [ "USER_NAME" != "" ] && USER="-u $USER_NAME" || USER=""
      rip.pl -r "$d" -p cmdproc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/CMD_PROC.TLN.TMP;
      rip.pl -r "$d" -p cached_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/CACHED.TLN.TMP;
      rip.pl -r "$d" -p recentapps_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RECENT_APPS.TLN.TMP;
      rip.pl -r "$d" -p typedpaths_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TYPED_PATHS.TLN.TMP;
      rip.pl -r "$d" -p trustrecords_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TRUST_RECORDS.TLN.TMP;
      rip.pl -r "$d" -p mmc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MMC.TLN.TMP;
      rip.pl -r "$d" -p osversion_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/OS_VER.TLN.TMP;
      rip.pl -r "$d" -p winrar_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/WINRAR.TLN.TMP;
      rip.pl -r "$d" -p mixer_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MIXER.TLN.TMP;
      rip.pl -r "$d" -p appkeys_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP;
      rip.pl -r "$d" -p officedocs2010_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/OFFICE_DOCS.TLN.TMP;
      rip.pl -r "$d" -p uninstall_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP;
      rip.pl -r "$d" -p attachmgr_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/ATTACH_MGR.TLN.TMP;
      rip.pl -r "$d" -p muicache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP;
      rip.pl -r "$d" -p typedurlstime_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TYPEDURLSTIME.TLN.TMP;
      rip.pl -r "$d" -p applets_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPLETS.TLN.TMP;
      rip.pl -r "$d" -p urun_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"|tee -a $CASE_DIR/Triage/Timeline/TLN/URUN.TLN.TMP;
      rip.pl -r "$d" -p typedurls_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TYPEDURLS.TLN.TMP;
      rip.pl -r "$d" -p userassist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/USERASSIST.TLN.TMP;
      rip.pl -r "$d" -p recentdocs_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RECENTDOCS.TLN.TMP;
      rip.pl -r "$d" -p sysinternals_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SYSINTERNALS.TLN.TMP;
      rip.pl -r "$d" -p tsclient_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TSCLIENT.TLN.TMP;
      rip.pl -r "$d" -p mndmru_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MNDMRU.TLN.TMP;
      rip.pl -r "$d" -p runmru_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RUNMRU.TLN.TMP;
      rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/ntuser.dat$" | while read d; 
      do
        USER_NAME=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
        [ TLNSuuport="Yes" ] && [ "USER_NAME" != "" ]  && USER="-u $USER_NAME"
        rip.pl -r "$d" -p cmdproc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/CMD_PROC.TLN.TMP;
        rip.pl -r "$d" -p cached_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/CACHED.TLN.TMP;
        rip.pl -r "$d" -p recentapps_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RECENT_APPS.TLN.TMP;
        rip.pl -r "$d" -p typedpaths_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TYPED_PATHS.TLN.TMP;
        rip.pl -r "$d" -p trustrecords_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TRUST_RECORDS.TLN.TMP;
        rip.pl -r "$d" -p mmc_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MMC.TLN.TMP;
        rip.pl -r "$d" -p osversion_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/OS_VER.TLN.TMP;
        rip.pl -r "$d" -p winrar_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/WINRAR.TLN.TMP;
        rip.pl -r "$d" -p mixer_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MIXER.TLN.TMP;
        rip.pl -r "$d" -p appkeys_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP;
        rip.pl -r "$d" -p officedocs2010_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/OFFICE_DOCS.TLN.TMP;
        rip.pl -r "$d" -p uninstall_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP;
        rip.pl -r "$d" -p attachmgr_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/ATTACH_MGR.TLN.TMP;
        rip.pl -r "$d" -p muicache_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP;
        rip.pl -r "$d" -p typedurlstime_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TYPEDURLSTIME.TLN.TMP;
        rip.pl -r "$d" -p applets_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/APPLETS.TLN.TMP;
        rip.pl -r "$d" -p urun_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"|tee -a $CASE_DIR/Triage/Timeline/TLN/URUN.TLN.TMP;
        rip.pl -r "$d" -p typedurls_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TYPEDURLS.TLN.TMP;
        rip.pl -r "$d" -p userassist_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/USERASSIST.TLN.TMP;
        rip.pl -r "$d" -p recentdocs_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RECENTDOCS.TLN.TMP;
        rip.pl -r "$d" -p sysinternals_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/SYSINTERNALS.TLN.TMP;
        rip.pl -r "$d" -p tsclient_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/TSCLIENT.TLN.TMP;
        rip.pl -r "$d" -p mndmru_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/MNDMRU.TLN.TMP;
        rip.pl -r "$d" -p runmru_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/RUNMRU.TLN.TMP;
        rip.pl -r "$d" -p del_tln 2>/dev/null |  grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}|${USER_NAME}|/"| tee -a $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP
      done
    done
    makegreen "Sorting..."
    cat $CASE_DIR/Triage/Timeline/TLN/CMD_PROC.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/CMD_PROC.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/CMD_PROC.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/CACHED.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/CACHED.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/CACHED.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/RECENT_APPS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/RECENT_APPS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/RECENT_APPS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/TYPED_PATHS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/TYPED_PATHS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/TYPED_PATHS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/TRUST_RECORDS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/TRUST_RECORDS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/TRUST_RECORDS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/MMC.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/MMC.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/MMC.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/OS_VER.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/OS_VER.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/OS_VER.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/WINRAR.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/WINRAR.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/WINRAR.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/MIXER.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/MIXER.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/MIXER.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/APPKEYS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/OFFICE_DOCS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/OFFICE_DOCS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/OFFICE_DOCS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/UNINSTALL.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/ATTACH_MGR.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/ATTACH_MGR.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/ATTACH_MGR.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/MUICACHE.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/TYPEDURLSTIME.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/TYPEDURLSTIME.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/TYPEDURLSTIME.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/APPLETS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/APPLETS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/APPLETS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/URUN.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/URUN.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/URUN.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/TYPEDURLS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/TYPEDURLS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/TYPEDURLS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/USERASSIST.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/USERASSIST.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/USERASSIST.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/RECENTDOCS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/RECENTDOCS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/RECENTDOCS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/SYSINTERNALS.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/SYSINTERNALS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/SYSINTERNALS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/TSCLIENT.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/TSCLIENT.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/TSCLIENT.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/MNDMRU.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/MNDMRU.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/MNDMRU.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/RUNMRU.TLN.TMP  2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/RUNMRU.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/RUNMRU.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/DELETED-KEYS.TLN.TMP;
    makegreen "NTUSER.DAT TLN Complete!"
}
# Consolidating TLN Output and consolidating timelines
function timeline_TLN(){
    echo ""
    makegreen "Consolidating TLN Files"
    echo ""
    find $CASE_DIR -type f 2>/dev/null| grep ADS.txt$ | while read d;
    do
      cat $d | tee -a $CASE_DIR/Triage/Timeline/TLN/ALTERNATE-DATA-STREAMS.TLN.TMP
      cat $d | grep Zone.Identifier| sort -rn |uniq |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}' |tee -a $CASE_DIR/Triage/Browser_Activity/Zone.Identifier.TLN.TMP;
    done 
    cat $CASE_DIR/Triage/Timeline/TLN/ALTERNATE-DATA-STREAMS.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/ALTERNATE-DATA-STREAMS.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/ALTERNATE-DATA-STREAMS.TLN.TMP;
    cat $CASE_DIR/Triage/Browser_Activity/Zone.Identifier.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Browser_Activity/Zone.Identifier.TLN.txt && rm $CASE_DIR/Triage/Timeline/TLN/ALTERNATE-DATA-STREAMS.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP | sort -rn |uniq | tee -a | tee -a $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.txt;
    cat $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|sort -rn | uniq| tee -a $CASE_DIR/Triage/Timeline/Triage-Timeline.csv.txt;
    find $CASE_DIR/Triage -type f 2>/dev/null| grep TLN.TMP$ |while read d; 
    do 
      rm $d;
    done
    makegreen "Complete!"
}
####################### PreProcessing ################################
# Remove File Duplicates and empty files
function remove_dupes(){
    makegreen "Removing duplicate files and empty files"
    find /$CASE_DIR/$COMPNAME/Artifact -maxdepth 1 -type d|grep vss.$ |while read d; 
    do 
      fdupes /$CASE_DIR/$COMPNAME/Artifact/LOCAL/ --recurse $d -d -N;
    done 
    find /$CASE_DIR/$COMPNAME/Artifact -type f| tee -a  /$CASE_DIR/$COMPNAME/Acquisition.log.txt
    find /$CASE_DIR/$COMPNAME -empty -delete
    makegreen "log file updated!   /$CASE_DIR/$COMPNAME/Acquisition.log.txt"
}

####################### Triage Processing ############################
### Run the Regripper Shellbags Plugin
function regrip_shellbags(){
    cd $CASE_DIR
    makegreen "Searching for USRCLASS.DAT (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null |grep -v "Documents\ and\ Settings" | grep -i usrclass.dat$| while read d; 
    do 
      rip.pl -r "$d" -f usrclass |tee -a $CASE_DIR/Triage/File_Access/Shellbags-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME; 
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null |grep -v "Documents\ and\ Settings" | grep -i usrclass.dat$| while read d;
      do
        rip.pl -r "$d" -f usrclass |tee -a $CASE_DIR/Triage/File_Access/Shellbags-$COMPNAME.txt;
      done 
    done
} 
### Run the Regripper Amcache Plugin
function regrip_Amcache(){
    cd $CASE_DIR
    makegreen "Searching for AMCACHE.HVE/Recentfilecache.bcf (Regripper)"
    sleep 1   
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i amcache.hve$| while read d; 
    do 
      rip.pl -r "$d" -p amcache |tee -a $CASE_DIR/Triage/Program_Execution/RecentFileCache-$COMPNAME.txt;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i amcache.hve$| while read d; 
        do 
          rip.pl -r "$d" -p amcache |tee -a $CASE_DIR/Triage/Program_Execution/RecentFileCache-$COMPNAME.txt;
        done
    done
}
### Run Jobparse.py and Extract Windows Event Log: TaskScheduler%4operational.evtx
function extract_Jobs(){
    cd $CASE_DIR
    makegreen "Searching for SCHEDULED TASKS (jobparser.py)" 
    sleep 1
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f  |grep -i "\.job$" |while read d; 
    do 
      python /usr/local/bin/jobparser.py -f "$d" |tee -a $CASE_DIR/Triage/Persistence/Jobs-$COMPNAME.txt; 
    done
      COUNTER="0" && find $CASE_DIR -type f  |grep -i "TaskScheduler\%4operational\.evtx$" |while read line; 
    do  
      evtxexport -f xml $line |tee -a $CASE_DIR//Triage/Persistence/TaskScheduler\%4operational\.evtx.xml-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f  |grep -i "\.job$" |while read d; 
      do 
        python /usr/local/bin/jobparser.py -f "$d" |tee -a $CASE_DIR/Triage/Persistence/Jobs-$COMPNAME.txt; 
      done;
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f  |grep -i "TaskScheduler\%4operational\.evtx$" |while read line; 
      do  
        evtxexport -f xml $line |tee -a $CASE_DIR/Triage/Persistence/TaskScheduler\%4operational\.evtx.xml-$COMPNAME-$COUNTER.txt && COUNTER=$((COUNTER +1));
      done;
    done;
    echo "Microsoft-Windows-TaskScheduler%4Operational.evtx
    106 - Task scheduled
    200 - Task executed
    201 - Task completed
    202 - Task Failed to complete
    140 - Task Updated
    141 - Task Deleted
    142 - Task Disabled
    145 - Computer woke up by TaskScheduler
    300 - Task Scheduler Started
    400 - Task Scheduler Service Started" |tee  $CASE_DIR//Triage/Persistence/_TaskScheduler.EventIDs.txt
}
## Run RegRipper softruns plugin ##
function regrip_autostart(){
    cd $CASE_DIR
    makegreen "Searching for AUTOSTART values (RegRipper)" 
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i software$| while read d; 
    do 
      rip.pl -r "$d" -p soft_run |tee -a $CASE_DIR/Triage/Persistence/Softruns-$COMPNAME.txt;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i software$| while read d; 
      do 
        rip.pl -r "$d" -p soft_run |tee -a $CASE_DIR/Triage/Persistence/Softruns-$COMPNAME.txt;
      done
    done  
}
### Run the Regripper Shimcache/Bam Plugins 
function regrip_shimcache(){
    cd $CASE_DIR
    makegreen "Searching for SHIMCACHE and BAM (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i system$| while read d; 
    do 
      rip.pl -r "$d" -p shimcache |tee -a $CASE_DIR/Triage/Program_Execution/Shimcache-$COMPNAME.txt;
      rip.pl -r "$d" -p bam |tee -a $CASE_DIR/Triage/Program_Execution/Bam-$COMPNAME.txt;
    done 
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i system$| while read d; 
      do 
        rip.pl -r "$d" -p shimcache |tee -a $CASE_DIR/Triage/Program_Execution/Shimcache-$COMPNAME.txt;
        rip.pl -r "$d" -p bam |tee -a $CASE_DIR/Triage/Program_Execution/Bam-$COMPNAME.txt;
      done
    done  
} 
### Run the Regripper Userassist Plugin
function regrip_userassist(){
    cd $CASE_DIR
    makegreen "Searching for USERASSIST entries (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p userassist |tee -a $CASE_DIR/Triage/Program_Execution/UserAssist-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p userassist |tee -a $CASE_DIR/Triage/Program_Execution/UserAssist-$COMPNAME.txt;
      done
    done
}
### Run the Regripper User_run Plugin
function regrip_runkeys(){
    cd $CASE_DIR
    makegreen "Searching for USER RUN KEYS (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p user_run |grep -v "^$"|tee -a $CASE_DIR/Triage/Persistence/UserRun-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p user_run |grep -v "^$"|tee -a $CASE_DIR/Triage/Persistence/UserRun-$COMPNAME.txt;
      done
    done
}
## Extract recycle.bin timestamps
function parse_recycle.bin(){
    cd $CASE_DIR
    makegreen "Parsing \$Recycle.Bin"
    [ "$MULTI_CASE" == "no" ] && find $CASE_DIR -type f 2>/dev/null|grep "\$I"|sed 's|^\.||'|while read d; 
    do  
      ls $d 
      name=$(strings -el -f $d) 
      hexsize=$(cat "$d"|xxd -s8 -l8 -ps| sed -e 's/[0]*$//g')
      size=$(echo $((0x$hexsize)))
      hexdate=$(cat "$d"|xxd -s16 -l8 -ps|awk '{gsub(/.{2}/,"& ")}1'|awk '{for(i=NF; i>0;i--)printf "%s",$i}' && echo "")
      date=$(date -d@$((((0x$hexdate)/10000000)-11644473600)) +"%s")
      echo "$date|Recycle|"$COMPNAME"||[Deleted] "$name " FILE SIZE: "$size| tee -a  $CASE_DIR/Triage/Timeline/TLN/RECYCLE.BIN.TLN.TMP
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null|grep "\$I"|sed 's|^\.||'|while read d; 
      do  
        ls $d 
        name=$(strings -el -f $d) 
        hexsize=$(cat "$d"|xxd -s8 -l8 -ps| sed -e 's/[0]*$//g')
        size=$(echo $((0x$hexsize)))
        hexdate=$(cat "$d"|xxd -s16 -l8 -ps|awk '{gsub(/.{2}/,"& ")}1'|awk '{for(i=NF; i>0;i--)printf "%s",$i}' && echo "")
        date=$(date -d@$((((0x$hexdate)/10000000)-11644473600)) +"%s")
        echo "$date|Recycle|"$COMPNAME"||[Deleted] "$name " FILE SIZE: "$size| tee -a  $CASE_DIR/Triage/Timeline/TLN/RECYCLE.BIN.TLN.TMP
      done
    done
    cat $CASE_DIR/Triage/Timeline/TLN/RECYCLE.BIN.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/RECYCLE.BIN.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/RECYCLE.BIN.TLN.TMP;
} 
function extract_Chrome(){
     cd $CASE_DIR
    [ "$MULTI_CASE" == "no" ] &&  find -type d 2>/dev/null |grep  "\/User\ Data\/Default$"|while read d;
    do
      USER_NAME=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
      makegreen "Searching for CHROME HISTORY and DOWNLOADS (sqlite3)" 
      #Extract Chrome Browsing info 
      [ "$d" != "" ] && sqlite3 "$d/History" "select (last_visit_time/1000000-11644473600),url, title, visit_count from urls ORDER BY last_visit_time" |awk -F'|' '{print $1"|chrome|||[URL]:"$2",TITLE: "$3", VISIT COUNT:"$4}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/Chrome-History.TLN.TMP  
      [ "$d" != "" ] && sqlite3 "$d/History" "select (start_time/1000000-11644473600), url, target_path, total_bytes FROM downloads INNER JOIN downloads_url_chains ON downloads_url_chains.id = downloads.id ORDER BY start_time" |awk -F'|' '{print $1"|chrome|||[DOWNLOAD]-"$2",TARGET:-"$3", BYTES TRANSFERRED:-"$4}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $CASE_DIR/Triage/Timeline/TLN/Chrome-Downloads.TLN.TMP 
      [ "$d" != "" ] && sqlite3 "$d/Cookies" "select (cookies.creation_utc/1000000-11644473600), cookies.host_key,cookies.path, cookies.name, datetime(cookies.last_access_utc/1000000-11644473600,'unixepoch','utc'), cookies.value FROM cookies"|awk -F'|' '{print $1"|chrome|||[Cookie Created]:"$2" LASTACCESS: "$5" VALUE: "$4}' 2>/dev/null| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $CASE_DIR/Triage/Timeline/TLN/Chrome-Cookies.TLN.TMP 
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type d 2>/dev/null |grep  "\/User\ Data\/Default$"|while read d;
      do
        USER_NAME=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
        makegreen "Searching for CHROME HISTORY and DOWNLOADS (sqlite3)" 
        #Extract Chrome Browsing info 
        [ "$d" != "" ] && sqlite3 "$d/History" "select (last_visit_time/1000000-11644473600),url, title, visit_count from urls ORDER BY last_visit_time" |awk -F'|' '{print $1"|chrome|||[URL]:"$2",TITLE: "$3", VISIT COUNT:"$4}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/Chrome-History.TLN.TMP  
        [ "$d" != "" ] && sqlite3 "$d/History" "select (start_time/1000000-11644473600), url, target_path, total_bytes FROM downloads INNER JOIN downloads_url_chains ON downloads_url_chains.id = downloads.id ORDER BY start_time" |awk -F'|' '{print $1"|chrome|||[DOWNLOAD]-"$2",TARGET:-"$3", BYTES TRANSFERRED:-"$4}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $CASE_DIR/Triage/Timeline/TLN/Chrome-Downloads.TLN.TMP 
        [ "$d" != "" ] && sqlite3 "$d/Cookies" "select (cookies.creation_utc/1000000-11644473600), cookies.host_key,cookies.path, cookies.name, datetime(cookies.last_access_utc/1000000-11644473600,'unixepoch','utc'), cookies.value FROM cookies"|awk -F'|' '{print $1"|chrome|||[Cookie Created]:"$2" LASTACCESS: "$5" VALUE: "$4}' 2>/dev/null| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" |tee -a $CASE_DIR/Triage/Timeline/TLN/Chrome-Cookies.TLN.TMP 
      done
    done
    cat $CASE_DIR/Triage/Timeline/TLN/Chrome-History.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/Chrome-History.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/Chrome-History.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/Chrome-Downloads.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/Chrome-Downloads.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/Chrome-Downloads.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/Chrome-Cookies.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/Chrome-Cookies.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/Chrome-Cookies.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/Chrome-History.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|tee -a  $CASE_DIR/Triage/Browser_Activity/Chrome-History.txt
    cat $CASE_DIR/Triage/Timeline/TLN/Chrome-Downloads.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|tee -a  $CASE_DIR/Triage/Browser_Activity/Chrome-Downloads.txt 
    cat $CASE_DIR/Triage/Timeline/TLN/Chrome-Cookies.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}' |tee -a  $CASE_DIR/Triage/Browser_Activity/Chrome-Cookies.txt 
}
function extract_Firefox(){
    #Extract Firefox Browsing info to Text File
    cd $CASE_DIR
    makegreen "Searching for Firefox HISTORY and DOWNLOADS (sqlite3)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f |grep -i places.sqlite$ |sed 's/\/places.sqlite//' |while read d;
    do
      USER_NAME=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
      sqlite3 "$d/places.sqlite" "select (moz_historyvisits.visit_date/1000000), moz_places.url, moz_places.title, moz_places.visit_count FROM moz_places,moz_historyvisits where moz_historyvisits.place_id=moz_places.id order by moz_historyvisits.visit_date;" |awk -F'|' '{print $1"|FireFox|||[URL]:"$2"  TITLE:"$3" VISIT-COUNT:" $4}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/FireFox-History.TLN.TMP;
      sqlite3 "$d/downloads.sqlite" "select (startTime/1000000), source,target,currBytes,maxBytes FROM moz_downloads" |awk -F'|' '{print $1"|FireFox|||[Download]:"$2"=>"$3" BYTES DOWNLOADED=>"$4" TOTAL BYTES=>"$5}' | sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/FireFox-Downloads.TLN.TMP;
      sqlite3 "$d/cookies.sqlite" "select (creationTime/1000000), host,name,datetime((lastAccessed/1000000),'unixepoch','utc'),datetime((expiry/1000000),'unixepoch','utc') FROM moz_cookies" |awk -F'|' '{print $1"|FireFox||| [Cookie Created]: "$2" NAME:"$3" ,LAST ACCESS:"$4", EXPIRY: "$5}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/FireFox-Cookies.TLN.TMP;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f |grep -i places.sqlite$ |sed 's/\/places.sqlite//' |while read d;
      do
        USER_NAME=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
        sqlite3 "$d/places.sqlite" "select (moz_historyvisits.visit_date/1000000), moz_places.url, moz_places.title, moz_places.visit_count FROM moz_places,moz_historyvisits where moz_historyvisits.place_id=moz_places.id order by moz_historyvisits.visit_date;" |awk -F'|' '{print $1"|FireFox|||[URL]:"$2"  TITLE:"$3" VISIT-COUNT:" $4}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/FireFox-History.TLN.TMP;
        sqlite3 "$d/downloads.sqlite" "select (startTime/1000000), source,target,currBytes,maxBytes FROM moz_downloads" |awk -F'|' '{print $1"|FireFox|||[Download]:"$2"=>"$3" BYTES DOWNLOADED=>"$4" TOTAL BYTES=>"$5}' | sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/FireFox-Downloads.TLN.TMP;
        sqlite3 "$d/cookies.sqlite" "select (creationTime/1000000), host,name,datetime((lastAccessed/1000000),'unixepoch','utc'),datetime((expiry/1000000),'unixepoch','utc') FROM moz_cookies" |awk -F'|' '{print $1"|FireFox||| [Cookie]: "$2" NAME:"$3" ,LAST ACCESS:"$4", EXPIRY: "$5}'| sed "s/|||/|${COMPNAME}|${USER_NAME}|/" | tee -a $CASE_DIR/Triage/Timeline/TLN/FireFox-Cookies.TLN.TMP;
      done
    done
    cat $CASE_DIR/Triage/Timeline/TLN/FireFox-History.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/FireFox-History.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/FireFox-History.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/FireFox-Downloads.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/FireFox-Downloads.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/FireFox-Downloads.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/FireFox-Cookies.TLN.TMP 2>/dev/null| sort -rn| uniq | tee -a  $CASE_DIR/Triage/Timeline/TLN/FireFox-Cookies.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Timeline/TLN/FireFox-Cookies.TLN.TMP;
    cat $CASE_DIR/Triage/Timeline/TLN/FireFox-History.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}' |tee -a  $CASE_DIR/Triage/Browser_Activity/FireFox-History.txt
    cat $CASE_DIR/Triage/Timeline/TLN/FireFox-Downloads.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}' |tee -a  $CASE_DIR/Triage/Browser_Activity/FireFox-Downloads.txt 
    cat $CASE_DIR/Triage/Timeline/TLN/FireFox-Cookies.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}' |tee -a  $CASE_DIR/Triage/Browser_Activity/FireFox-Cookies.txt 
}
function extract_webcacheV(){
    cd $CASE_DIR
    makegreen "Searching for IE WebcacheV (esedbexport)"
    sleep 1 
    [ -d "${CASE_DIR}/Triage/Browser_Activity" ]  &&  COUNTER="0" && find $CASE_DIR -type f 2>/dev/null |grep -i webcachev...dat$ |while read d; 
    do
      /usr/bin/esedbexport -m all -t $CASE_DIR/Triage/Browser_Activity/WebcacheV-$COMPNAME-$COUNTER $d && COUNTER=$((COUNTER +1)) ;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null |grep -i webcachev...dat$ |while read d;
      do
        /usr/bin/esedbexport -m all -t $CASE_DIR/Triage/Browser_Activity/WebcacheV-$COMPNAME-$COUNTER $d && COUNTER=$((COUNTER +1)) ;
      done
    done
}                                  

#added Win10_prefetch from http://github.com/bromiley/tools/tree/master/win10_prefetch file added: /usr/local/bin/w10pf_parse.py for prefetch files on OS versions > Windows 8
function parse_prefetch(){
    cd $CASE_DIR
    makegreen "Searching for PREFETCH (w10pf_parse.py and prefetch.py)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type d -name "Prefetch" |sed 's/$/\//'| while read d; 
    do 
      python /usr/local/bin/prefetch.py -d "$d" && python /usr/local/bin/prefetch.py -d "$d" |tee -a $CASE_DIR/Triage/Program_Execution/Prefetch-$COMPNAME.txt;
      python /usr/local/bin/w10pf_parse.py -d "$d" && python /usr/local/bin/w10pf_parse.py -d $d |awk -v cname="$COMPNAME" -F',' '{printf $4",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $5",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $6",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $7",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $8",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $9",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $10",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n"}' |tee -a $CASE_DIR/Triage/Program_Execution/Prefetch.CSV.TMP
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type d -name "Prefetch" |sed 's/$/\//'| while read d; 
      do 
        python /usr/local/bin/prefetch.py -d "$d" && python /usr/local/bin/prefetch.py -d "$d" |tee -a $CASE_DIR/Triage/Program_Execution/Prefetch-$COMPNAME.txt;
        python /usr/local/bin/w10pf_parse.py -d "$d" && python /usr/local/bin/w10pf_parse.py -d $d |awk -v cname="$COMPNAME" -F',' '{printf $4",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $5",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $6",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $7",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $8",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $9",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n" $10",prefetch,"cname",,FILE:"$1" Run Count:"$2" PFHASH: "$3"\n"}' |tee -a $CASE_DIR/Triage/Program_Execution/Prefetch.CSV.TMP
      done
    done
    [ -f $CASE_DIR/Triage/Program_Execution/Prefetch.CSV.TMP ] && cat $CASE_DIR/Triage/Program_Execution/Prefetch.CSV.TMP | grep -Ea '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]' |sort -rn |uniq | tee -a $CASE_DIR/Triage/Program_Execution/Prefetch.csv.txt && rm $CASE_DIR/Triage/Program_Execution/Prefetch.CSV.TMP 
    [ -f $CASE_DIR/Triage/Program_Execution/Prefetch.csv.txt ] && cat $CASE_DIR/Triage/Program_Execution/Prefetch.csv.txt | while read d; 
    do
      timestamp=$(echo $d| awk -F',' '{print $1}'| grep -Eo '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
      [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
      tlninfo=$(echo $d| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')
      [ "$timestamp" != "" ] && echo $tlntime$tlninfo | tee -a $CASE_DIR/Triage/Timeline/TLN/Prefetch.TLN.txt
    done
}
## Run RegRipper comdlg32 plugin ##
function regrip_comdlg(){
    cd $CASE_DIR
    makegreen "Searching for OPEN/SAVE file artifacts (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p comdlg32 |tee -a $CASE_DIR/Triage/File_Open-Save/COMDLG-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p comdlg32 |tee -a $CASE_DIR/Triage/File_Open-Save/COMDLG-$COMPNAME.txt;
      done
    done
}
## Run RegRipper recentdocs_timeline plugin ##
function recentdocs(){
    cd $CASE_DIR
    makegreen "Searching for RECENT DOCUMENTS file artifacts (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p recentdocs_timeline |tee -a $CASE_DIR/Triage/File_Open-Save/Recent-Docs-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p recentdocs_timeline |tee -a $CASE_DIR/Triage/File_Open-Save/Recent-Docs-$COMPNAME.txt;
      done
    done
}
## Run RegRipper wordwheel plugin ##
function regrip_wordwheel(){
    cd $CASE_DIR
    makegreen "Searching for WORDWHEELQUERY entries (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p wordwheelquery 2>/dev/null| grep -v " not found\." |tee -a $CASE_DIR/Triage/User_Searches/WordWheel-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p wordwheelquery 2>/dev/null| grep -v " not found\." |tee -a $CASE_DIR/Triage/User_Searches/WordWheel-$COMPNAME.txt;
      done
    done
}
## Run RegRipper usbstor3 plugin ##
function regrip_USB(){
    cd $CASE_DIR
    makegreen "Searching for USBStor information (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i system$| while read d; 
    do 
      rip.pl -r "$d" -p usbstor3 |tee -a $CASE_DIR/Triage/USB_Access/USBStor-$COMPNAME.txt;
    done 
    find $CASE_DIR -type f 2>/dev/null | grep -i setupapi.dev.log | grep -i log$ |while read d; 
    do 
      cp "$d" $CASE_DIR/Triage/USB_Access/setupapi.dev.log-$COMPNAME.txt 2>/dev/null;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i system$| while read d; 
      do 
        rip.pl -r "$d" -p usbstor3 |tee -a $CASE_DIR/Triage/USB_Access/USBStor-$COMPNAME.txt;
      done 
      find $CASE_DIR -type f 2>/dev/null | grep -i setupapi.dev.log | grep -i log$ |while read d; 
      do 
        cp "$d" $CASE_DIR/Triage/USB_Access/setupapi.dev.log-$COMPNAME.txt 2>/dev/null;
      done
    done
} 
## Run RegRipper portdev plugin ##
function regrip_USB_device_list(){
    cd $CASE_DIR
    makegreen "Searching for USB DEVICE information (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i software$| while read d; 
    do 
      rip.pl -r "$d" -p port_dev |tee -a $CASE_DIR/Triage/USB_Access/USB_Device_List-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i software$| while read d; 
      do 
        rip.pl -r "$d" -p port_dev |tee -a $CASE_DIR/Triage/USB_Access/USB_Device_List-$COMPNAME.txt;
      done
    done
}
## Run RegRipper services plugin ##
function regrip_services(){
    cd $CASE_DIR
    makegreen "Searching for SERVICES (Regripper)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i system$| while read d; 
    do 
      rip.pl -r "$d" -p svc  |tee -a $CASE_DIR/Triage/Persistence/Services-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i system$| while read d; 
      do 
        rip.pl -r "$d" -p svc  |tee -a $CASE_DIR/Triage/Persistence/Services-$COMPNAME.txt;
      done
    done
} 
## Run RegRipper typedpaths plugin ##
function regrip_typedpaths(){
    cd $CASE_DIR
    makegreen "Searching for TYPED PATHS entries (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p typedpaths |tee -a $CASE_DIR/Triage/User_Searches/Typed-Paths-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p typedpaths |tee -a $CASE_DIR/Triage/User_Searches/Typed-Paths-$COMPNAME.txt;
      done
    done
}
## Run RegRipper cortana plugin ##
function regrip_cortana(){
    cd $CASE_DIR
    makegreen "Searching for CORTANA SEARCH entries (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p cortana |tee -a $CASE_DIR/Triage/User_Searches/Cortana-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;  
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p cortana |tee -a $CASE_DIR/Triage/User_Searches/Cortana-$COMPNAME.txt;
      done
    done
}
## Run RegRipper typedurls plugin ##
function regrip_typedurls(){
    cd $CASE_DIR
    makegreen "Searching for TYPED URLS (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p typedurls |tee -a $CASE_DIR/Triage/User_Searches/Typed-URLs-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p typedurls |tee -a $CASE_DIR/Triage/User_Searches/Typed-URLs-$COMPNAME.txt;
      done
    done
}
## Run RegRipper typedurlstime plugin ##
function regrip_typedurlstime(){
    cd $CASE_DIR
    makegreen "Searching for TYPED URLS (Win8+) entries (Regripper)"
    sleep 1 
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
    do 
      rip.pl -r "$d" -p typedurlstime |tee -a $CASE_DIR/Triage/User_Searches/Typed-URLs-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i ntuser.dat$|while read d; 
      do 
        rip.pl -r "$d" -p typedurlstime |tee -a $CASE_DIR/Triage/User_Searches/Typed-URLs-$COMPNAME.txt;
      done
    done
}
#Extract MFT to body file and then to TLN 
function analyze_mft(){
    cd $CASE_DIR
    makegreen "Analyzing \$MFT Standby..."
    mkdir -p $CASE_DIR/Triage/Timeline/MFT
    # AnalyzeMFT Outputs to bodyfile then converted to TLN
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i "\$MFT$" |while read d; 
    do
      makegreen "Creating a bodyfile from $d" && analyzeMFT.py -p -f "$d" --bodyfull --bodyfile=$CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.body;
      bodyfile.pl -f $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.body -s $COMPNAME | tee $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.TLN.txt;
      cat $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| tee -a $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.csv.txt;
      COUNTER=$((COUNTER +1))
    done  
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i -m1 "\$MFT$" |while read d; 
      do
        makegreen "Creating a bodyfile from $d" && analyzeMFT.py -p -f "$d" --bodyfull --bodyfile=$CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.body;
        bodyfile.pl -f $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.body -s $COMPNAME | tee -a $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.TLN.txt;
        cat $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| tee -a $CASE_DIR/Triage/Timeline/MFT/\$MFT.$COUNTER.csv.txt;
      done
    done
    [ "$(ls -A $CASE_DIR/Triage/Timeline/MFT)" ] && makegreen "$MFT Extraction Complete!" || makered "\$MFT info not extracted!!"
}
# Find and extract Outlook files
function extract_Outlook_pst_ost(){
    mkdir -p /$CASE_DIR/$COMPNAME/Triage/Outlook
    cd $CASE_DIR/$COMPNAME/Triage/Outlook
    makegreen "Searching for OUTLOOK EMAIL Files to extract (pffexport)" 
    [ -d "${CASE_DIR}/$COMPNAME/Triage/Outlook" ] && find $CASE_DIR/$COMPNAME/Artifact -type f 2>/dev/null |grep -v \/vss.\/|grep -Ei "\.pst$"\|"\.ost$"|while read d; 
    do 
      pffexport "$d";
    done
    [ -d "${CASE_DIR}/$COMPNAME/Triage/Outlook" ] && find $CASE_DIR/$COMPNAME/Artifact -maxdepth 1 -type d 2>/dev/null|grep -o vss.$|while read d; 
    do
      mkdir -p $d && cd $d
      echo $PWD
      find $CASE_DIR/$COMPNAME/Artifact/$d -type f| grep -Ei "\.pst$"\|"\.ost$" 2>/dev/null|while read line; 
      do 
        pffexport "$line";
      done
      cd ..
    done
}
## Run Pylnker.py on link files ##
function analyze_lnk_files(){
    cd $CASE_DIR
    #added pylnker.py to /usr/local/bin   https://gitub.com/HarmJ0y/pylnker
    makegreen "Searching for LNK files (pylnker.py)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find $CASE_DIR -type f 2>/dev/null | grep -i "\.lnk$"| while read d; 
    do 
      /usr/local/bin/pylnker.py "$d"  |tee -a $CASE_DIR/Triage/File_Access/LNK-Files-$COMPNAME.txt;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\.lnk$"| while read d; 
      do 
        /usr/local/bin/pylnker.py "$d"  |tee -a $CASE_DIR/Triage/File_Access/LNK-Files-$COMPNAME.txt;
      done
    done
}
## Run Parseie.pl on index.dat files ##
function parse_index.dat(){
    cd $CASE_DIR
    makegreen "Searching for INDEX.DAT files (parseie.pl)"
    sleep 1  
    [ "$MULTI_CASE" == "no" ] &&  find -type f -size +5k|grep -i index.dat$|while read d; 

    do 
      parseie.pl -t -f "$d"|grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"|tee  -a $CASE_DIR/Triage/Timeline/TLN/index.dat.TLN.TMP;
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      find $CASE_DIR/$COMPNAME -type f -size +5k|grep -i index.dat$|while read d; 
      do 
        parseie.pl -t -f "$d"|grep -Ea "^[0-9]{10}\|"| sed "s/|||/|${COMPNAME}||/"|tee  -a $CASE_DIR/Triage/Timeline/TLN/index.dat.TLN.TMP;
      done
    done
    cat $CASE_DIR/Triage/Browser_Activity/index.dat.TLN.TMP 2>/dev/null| sort -rn| uniq | $CASE_DIR/Triage/Browser_Activity/index.dat.TLN.txt |tee -a  $CASE_DIR/Triage/Timeline/Triage-Timeline.TLN.TMP && rm $CASE_DIR/Triage/Browser_Activity/index.dat.TLN.TMP;
    cat $CASE_DIR/Triage/Browser_Activity/index.dat.TLN.txt|awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}' |tee -a  $CASE_DIR/Triage/Browser_Activity/index.dat.txt 
}
#Run evtexport to convert evtx file to XML
function export_evtx(){
    cd $CASE_DIR
    makegreen "Exporting Security Evtx to XML"
    makegreen "Standby...."
    [ -d "${CASE_DIR}/Triage" ] && mkdir -p $CASE_DIR/Triage/WinEvent_Logs
    [ "$MULTI_CASE" == "no" ] &&  COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i \/security.evtx$|while read d; 
    do 
      makegreen "Processing $d" && evtxexport -f xml $d |tee -a  $CASE_DIR/Triage/WinEvent_Logs/Security.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
    done
    makegreen "Security.evtx.xml  Done!"
    makegreen "Exporting Application Evtx to XML"
    makegreen "Standby..."
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i \/application.evtx$|while read d; 
    do 
      makegreen "Processing $d" && evtxexport -f xml $d|tee -a  $CASE_DIR/Triage/WinEvent_Logs/Application.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
    done
    makegreen "Application.evtx.xml  Done!"
    makegreen "Exporting System Evtx to XML"
    makegreen "Standby..."
    [ "$MULTI_CASE" == "no" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i \/system.evtx$|while read d; 
    do 
      makegreen "Processing $d" && evtxexport -f xml $d|tee -a  $CASE_DIR/Triage/WinEvent_Logs/System.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
    done
    makegreen "System.evtx.xml  Done!"
    makegreen "Exporting PowerShell Evtx to XML"
    makegreen "Standby..."
    [ "$MULTI_CASE" == "no" ] && COUNTER="0"&& find $CASE_DIR -type f 2>/dev/null | grep -i \/Windows\PowerShell.evtx$|while read d;
    do
      makegreen "Processing $d" && evtxexport -f xml "$d"|tee -a  $CASE_DIR/Triage/WinEvent_Logs/WindowsPowerShell.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
    done
    [ -d "${CASE_DIR}/Triage/WinEvent_Logs" ] && COUNTER="0" && find $CASE_DIR -type f 2>/dev/null | grep -i Microsoft-Windows-PowerShell.4Operational.evtx$ |while read d;
    do
      makegreen "Processing $d" && evtxexport -f xml "$d"|tee -a  $CASE_DIR/Triage/WinEvent_Logs/Microsoft-Windows-PowerShell4Operational.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
    done
    [ "$MULTI_CASE" != "no" ] && echo "$CASE_ID" | while read COMPNAME;
    do
      cd $CASE_DIR/$COMPNAME
      makegreen "Exporting Security Evtx to XML"
      makegreen "Standby...."
      [ -d "${CASE_DIR}/Triage" ] && mkdir -p $CASE_DIR/Triage/WinEvent_Logs
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i \/security.evtx$|while read d; 
      do 
        makegreen "Processing $d" && evtxexport -f xml $d |tee -a  $CASE_DIR/Triage/WinEvent_Logs/Security.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
      done
      makegreen "Security.evtx.xml  Done!"
      makegreen "Exporting Application Evtx to XML"
      makegreen "Standby..."
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i \/application.evtx$|while read d; 
      do 
        makegreen "Processing $d" && evtxexport -f xml $d|tee -a  $CASE_DIR/Triage/WinEvent_Logs/Application.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
      done
      makegreen "Application.evtx.xml  Done!"
      makegreen "Exporting System Evtx to XML"
      makegreen "Standby..."
      COUNTER="0" && find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i \/system.evtx$|while read d; 
      do 
        makegreen "Processing $d" && evtxexport -f xml $d|tee -a  $CASE_DIR/Triage/WinEvent_Logs/System.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
      done
      makegreen "System.evtx.xml  Done!"
      makegreen "Exporting PowerShell Evtx to XML"
      makegreen "Standby..."
      COUNTER="0"&& find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i "\/Windows\ PowerShell.evtx"|while read d;
      do
      makegreen "Processing $d" && evtxexport -f xml "$d"|tee -a  $CASE_DIR/Triage/WinEvent_Logs/WindowsPowerShell.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
       done
      COUNTER="0"&& find $CASE_DIR/$COMPNAME -type f 2>/dev/null | grep -i Microsoft-Windows-PowerShell.4Operational.evtx$ |while read d;
      do
        makegreen "Processing $d" && evtxexport -f xml "$d"|tee -a  $CASE_DIR/Triage/WinEvent_Logs/Microsoft-Windows-PowerShell4Operational.evtx.xml-$COUNTER-$COMPNAME.txt && COUNTER=$((COUNTER +1));
      done
    done
    makegreen "Event Log Extraction Complete!"
}
# Copy Windows Event Log CheatSheet to Event Logs Directory
function Security_evtx_IDs(){
echo "*********************************************
** WINDOWS EVENTLOG QUICK REFERENCE (EVTX) **
*********************************************

https://www.ultimatewindowssecurity.com/ 
https :// staticl.squarespace.com/static/552092d5e4 b0661088167e5c/t/580595db9f745688be7477f6/147676107 
http ://www. deer-run.com/~hal/IREventLogAnalysis.pdf 
https://github.com/dchad/fineline-computer-forensics-timeline-tools 
https://www.mindmeister.com/841877457/event-log 
http://www.redblue.team/2015/09/spotting-adversary-with-windows-event.html 
http://www.redblue.team/2015/09/spotting-adversary-with-windows-event_21.html 
http://kb.eventtracker.com/evtpass/evtbksearch_result.asp 
http://www.eventid.net/ 
https://github.com/iadgov/Event-Forwarding-Guidance/blob/master/Events/RecommendedEvents.csv

*******************
** SECURITY EVTX **
*******************
FILE, NETWORK OR LOG CLEARING EVENTS
1102 - Log Clearing 
4688 - Process Created (Program Execution) 
4656 - Access to File or Other Object Requested 
4663 - Attempt made to access a file or object 
4658 - Access to a File or object closed 
4697 - New Service has been Installed 
4782 - Password Hash of an Account has been Accessed 
5140 - Network Share Accessed 
LOGIN EVENTS 
4624 - Network logon 
4625 - Login Failed 
4634 - Logoff 
4648 - Attempted Login 
4672 - Administrator has Logged in 
4776 - Credential Authentication (Success/Fail) 
4778 - Session Reconnect (RDP or FastUser Switch) 
4770 - Kerberos Ticket Renewed 
4793 - Password Policy Checking API called 
CHANGE TO ACCOUNT OR ACCOUNT STATUS EVENTS
4704 - User Right Assigned 
4720 - New User Account Created 
4722 - New User Account Enabled 
4725 - User Account Disabled 
4726 - User Account Deleted 
4728 - Member Added to Global Group 
4731- Security-enabled Group Created 
4732 - Member Added to local Group 
4733 - Account removed from Local Sec. Group 
4765 - SID History added to Account 
4634 - Local Group Deleted 
4735 - Local Group Changed 
4740 - Account Locked out 
4748 - Local Group Deleted 
4756 - Member Added to Universal Group 
4766 - SID History add attempted on Account 
4767 - User Account Unlocked 
4781 - Account Name Changed 
CHANGES TO FIREWALL
4946 - Firewall Rule has been Added 
4947 - Firewall Rule has been Modified 
4948 - Firewall Rule has been Deleted 
4950 - Firewall Rule has been Changed 

**********************
** APPLICATION.EVTX **
**********************
865 - GPO Blocked - Exe Default Security Level 
866 - GPO Blocked exe - Restricted Path 
867 - GPO Blocked Exe - Certificate rule 
868 - GPO Blocked Exe - zone or hash rule 
882 - GPO Blocke Exe by Policy Rule 
1000 - Application Error 1001 - WER Info 
1001 - EMET !=Warning 2=Error 
1002 - Application Hang Software Policy Events 

*******************
** SYSTEM.EVTX **
******************* 
1074 - System Halt 
7000 - Service failed to start: did not respond to the start control request 
7022 - Service hung on start
7023 - Service terminated with error 
7024 - Service terminated with error 
7026 - Service failed on system start 
7031 - Service terminated unexpectedly 
7034 - Service terminated unexpectedly
7035 - Service sent a request to Stop or Start
7036 - Service was Started or Stopped 
7045 - service Installed 
7040 - Service changed from "auto start" to "disabled" 

*******************************************************
** Microsoft-Windows-TaskScheduler%4Operational.evtx **
*******************************************************
106 - Task scheduled 
200 - Task executed 
201 - Task completed 
202 - Task Failed to complete 
140 - Task Updated 
141 - Task Deleted 
142 - Task Disabled 
145 - Computer woke up by TaskScheduler 
300 - Task Scheduler Started 
400 - Task Scheduler Service Started 

****************************************************
** MICROSOFT-WINDOWS-WINDOWS DEFENDER/OPERATIONAL **
****************************************************
1005 - Scan Failed 
1006 - Malware Detected 
1008 - Action on Malware Failed 
2000 - Signature Updated 
2001 - Signature Update Failed 
2003 - Engine Update Failed 
2004 - Reverting to Last Known Gadd Signatures 
3001- Real-Time Protection Stopped 
5008 - Unexpected Error 

*********************************************************************
** Microsoft-Windows-TerminalServices-RemoteConnectionManager.EVTX **
*********************************************************************
261 - Terminal Service Received Connection 
1006 - Large Number of Connection Attempts 
1149 - User authenticated 

*****************************************************************
** Microsoft-Windows-TerminalServices-LocalSessionManager.EVTX **
*****************************************************************
21 - logon success 
23 - logoff 
24 - disconnect 

*****************************************
** PtH Detection for lateral movement: **
*****************************************
Event ID: 4624 
Event level: Information
LogonType: 3 
Logon method NTLM
A local logon that is not ANONYMOUS

*************************************************************
"|tee -a $CASE_DIR/Triage/WinEvent_Logs/_Evtx-ID-CheatSheet.txt
}
#Run an AV Scan using CLavAV
function run_clam_scan(){
    makegreen "Clamscan is starting"
    sleep 1
    $clam_scan_cmd
}
clear
[ $(whoami) != "root" ] && makered "Siftgrab Requires Root!" && exit
show_menu
exit 0
