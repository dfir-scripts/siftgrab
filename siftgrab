#!/bin/bash
export TZ='Etc/UTC'
function read_me(){
echo "
##############################################################################################
Siftgrab
A collection of Open source and custom forensic scripts wrapped into a shell menu to mount,
extract and timeline Windows forensic metadata on mounted images and image excerpts from tools
like CYLR and Kape. Also can extracts image forensic data for later analysis.
Outputs Regripper results, CSV and TLNs and more.
Tested on Ubuntu 20.04, Kali but should work on any system using the Apt package manager.
##############################################################################################

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
# reusable interactive yes-no function
function yes-no(){
      read -p "(Y/N)?"
      [ "$(echo $REPLY | tr [:upper:] [:lower:])" == "y" ] &&  yes_no="yes";
}
##  Main Siftgrab Display Menu Function
echo ""
function show_menu(){
    GRAY=`echo "\033[0;37m"`
    GREEN=`echo "\033[0;32m"`
    NORMAL=`echo "\033[m"`
    RED=`echo "\033[31m"`
    echo -e "${GREEN} Siftgrab${NORMAL}"
    echo -e "*****************************************************"
    echo -e "${GRAY}Mount and Extract Information From Windows Disk Images${NORMAL}"
    echo -e "*****************************************************"
    echo -e "**  1) ${GREEN} Mount a Disk or Disk Image (E01, Raw, AFF, QCOW VMDK, VHDX)${NORMAL}"
    echo -e "**  2)${GREEN}  Process Windows Artifacts from Mounted Image or Offline Files${NORMAL}"
    echo -e "**  3)${GREEN}  Extract Windows Event Logs${NORMAL}"
    echo -e "**  4) ${GREEN} Acquire Windows Forensic Artifacts from Mounted Image(s)${NORMAL}"
    echo -e "**  5) ${GREEN} Find and Acquire Volatile Data Files${NORMAL}"
    echo -e "**     ${GREEN} (hiberfil.sys, pagefile, swapfile.sys,)${NORMAL}"
    echo -e "**  6) ${GREEN} Extract Outlook OST/PST Mail Files ${NORMAL}"
    echo -e "**  7) ${GREEN} Browse Files (lf)${NORMAL}"
    echo -e "**  8) ${GREEN} Readme${NORMAL}"
    echo ""
    echo -e "Select a menu option number or ${RED}enter to exit. ${NORMAL}"
    read opt
while [ opt != '' ]
    do
    if [[ $opt = "" ]]; then
            exit;
    else
        case $opt in
        #Menu Selection 1: Mount disk image to $mount_dir
        1) clear
           /usr/local/bin/ermount
            show_menu;
            ;;

        #Menu Selection 2: Process Artifacts Collected using RegRipper and other Tools
        2) clear;
           makegreen "Process Artifacts for Triage"
           set_msource_path
           set_windir
           get_computer_name
           set_dsource_path
           check_dsource_path
           create_triage_dir
           get_usnjrlnsize
           get_evtxsize
           regrip_software
           rip_system
           rip_security
           regrip_ntuser_usrclass
           regrip_user_plugins
           regrip_sam
           regrip_amcache.hve
           regrip_syscache.hve_tln
           prefetch_extract
           extract_objects_data
           del_no_result
           lnkinfo
           recbin2tln
           chrome2tln
           firefox2tln
           extract_webcacheV
           winservices
           extract_srudb
           parse_current.mdb
           # #bits_parser TODO
           [ "$evtx" ] && evtxdump           	
           extract_WinEVTX
           consolidate_timeline
           extract_winactivities
           ls /$mount_dir/Users/*/AppData/Local/Microsoft/Windows/WebCache 2>/dev/null || parse_index.dat
           cp_setupapi
           extract_Jobs
           ADS_extract
           analyze_mft
           [ "$usn" ] && parse_usn
           Clean-up
           find $case_dir -empty -delete
           makegreen "Removing Duplicates..."
           echo "Please Wait..."
           fdupes -rdN $case_dir
           makegreen "The Processed Artifacts are Located in $triage_dir"
           du -sh $triage_dir
           makegreen Process Complete!
           read -n1 -r -p "Press any key to continue..." key
           show_menu;
            ;;
        #Menu Selection 3: Extract Windows Event Log to jsonl
        3) clear;
           makegreen "Extract Windows Event Logs to jsonl"
           set_msource_path         
           set_dsource_path
           triage_dir=$case_dir
           makered "Exporting Windows Event Logs to jsonl"
           evtxdump
           read -n1 -r -p "Press any key to continue..." key
           clear
           show_menu;
            ;;
        #Menu Selection 4: Acquire Data from Mounted Disks or Image Excerpts
        4) clear;
           /usr/local/src/irit/grab-winfiles.sh
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;
            ;;
        #Menu Selection 5:  Collect Volatile files from mounted image
        5) clear;
           set_msource_path
           set_dsource_path
           set_windir
           get_computer_name
           makered "COLLECTING VOLITILE FILES (hiberfil.sys, swapfile.sys, pagefile.sys and *.dmp)"
           get_volatile
           read -n1 -r -p "Press any key to continue..." key
           clear;
           show_menu;
            ;;
        #Menu Selection 6: Collect Outlook Email OST/PST files
        6) clear;
           makegreen "Extract Windows PST/OST file"
           set_msource_path
           set_windir
           get_computer_name
           set_dsource_path
           create_triage_dir
           extract_Outlook_pst_ost
           find $case_dir -empty -delete
           read -n1 -r -p "Press any key to continue..." key
           makegreen "Complete!!"
           clear;
           show_menu;
            ;;
        #Menu Selection 7:Lf File Browser
        7) clear;
           cd /cases
           gnome-terminal -- bash -c "lf; exec bash"
           clear;
           show_menu;
            ;;
        #Menu Selection 8:Siftgrab Readme
        8) clear;
           read_me
           read -n1 -r -p "Press any key to continue..." key
           clear;
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

####### DATA ACQUISITION AND PROCESSING PREFERENCES #######

# Set Data Source or mount point
function set_msource_path(){
      echo ""
      makered "SET DATA SOURCE"
      echo "Set Path or Enter to Accept Default:"
      read -e -p "" -i "/mnt/image_mount/" mount_dir
      [ ! -d "${mount_dir}" ] && makered "Path does not exist.." && sleep 1 && exit
      mount_dir=$(echo $mount_dir |sed 's_.*_&\/_'|sed 's|//*|/|g')
      echo "Data Source =" $mount_dir
}

# Set Case Destination Folder (Default = /cases/)
function set_dsource_path(){
      makered "SET CASE DESTINATION FOLDER (Default = /cases/)"
      echo "Set Path or Enter to Accept:"
      read -e -p "" -i "/cases/" case_dir
      [ ! -d "${case_dir}" ] && makered "Path does not exist.." && sleep 2 && show_menu
      cd $case_dir
      [ ! -d "${case_dir}" ] && makered "Path does not exist.." && sleep 1 && show_menu
      case_dir="$case_dir/$comp_name"
      triage_dir="$case_dir/Triage"
}
function check_dsource_path(){
      [ -d "$triage_dir" ] && echo "$case_dir already exists! overwrite?" && yes-no && rm -r $triage_dir/ && quit="no"
      [ -d "$triage_dir" ] && [ "$quit" != "no" ] && exit
      mkdir -p $triage_dir
      echo "Case Folder =>  $case_dir"
}

#Find "Windows" directory paths
function set_windir(){
      cd $mount_dir
      windir=$(find $mount_dir -maxdepth 1 -type d |egrep -m1 -io windows$)
      winsysdir=$(find $mount_dir/$windir -maxdepth 1 -type d |egrep -m1 -io windows\/system32$)
      user_dir=$(find $mount_dir -maxdepth 1 -type d |grep -m1 -io users$)
      regdir=$(find $mount_dir/$winsysdir -maxdepth 1 -type d |egrep -m1 -io \/config$)
      evtxdir=$(find $mount_dir/$winsysdir -maxdepth 2 -type d |egrep -m1 -io \/winevt\/Logs$)
      [ "$windir" == "" ] || [ "$winsysdir" == "" ] && makered "No Windows Directory Path Found on Source..." && sleep 2 && show_menu
      echo "Windows System32 Directory => $mount_dir$winsysdir"
      echo  "Registry Directory" $mount_dir$winsysdir$regdir
      echo  "Windows Eventlog Directory" $mount_dir$winsysdir$evtxdir
}

#Get Computer Name using Regripper's "comp_name" plugin
function get_computer_name(){
   [ "$comp_name" == "" ] &&  \
   comp_name=$(find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f  |egrep -m1 -i /system$| while read d;
     do
       rip.pl -r "$d" -p compname 2>/dev/null |grep -i "computername   "|awk -F'= ' '{ print $2 }';done)
   [ "$comp_name" == "" ] && comp_name=$(date +'%Y-%m-%d-%H%M')
   echo "ComputerName:" $comp_name
   #cleanup and create a new new temp file to hold regripper output
   rm /tmp/$comp_name.* 2>/dev/null
   tempfile=$(mktemp /tmp/$comp_name.XXXXXXXX)
}

#Create Output Directory
function create_triage_dir(){
triage_dirs=("System_Info/Software" "System_Info/Network" "System_Info/Settings" "Account_Usage" "File_Access" "Malware" "Program_Execution"  "Regripper/NTUSER" "USB_Access" "Browser_Activity"  "Persistence" "WindowsEventLogs" "Timeline/MFT" "Timeline/USNJRNL" "User_Searches" "Alert" "ActivitiesCache" "Outlook")
    for dir_names in "${triage_dirs[@]}";
    do
      mkdir -p $triage_dir/$dir_names
    done
    find "/$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
      do
        user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
        mkdir -p "$triage_dir/Regripper/$user_name"
      done
}

##############ACQUISITION FUNCTIONS############################

#Check Size of Windows Logs and option to include in backup
function get_logsize(){
    cd $mount_dir
    find -maxdepth 1 -type d  -iname "inetpub"|while read d;
    do
      du -sh $d
    done
    find $winsysdir -maxdepth 2 -type d -iname "LogFiles"|while read d;
    do
      du -sh $d
    done
    makered "COPY WINDOWS LOGFILES?" && yes-no && get_logs="yes"
}

#Check USNJRNL Size and option to include in backup
function get_usnjrlnsize(){
    cd $mount_dir
    du -sh \$Extend/\$UsnJrnl:\$J
    makered "PROCESS \$USNJRNL File?"
    yes-no && usn="yes"
}

#Check Windows Event Logs Size
function get_evtxsize(){
    cd $mount_dir
    du -sh $mount_dir/$winsysdir/$evtxdir
    makered "EXPORT WINDOWS EVENT LOGS TO JSONL?"
    yes-no && evtx="yes"    
}

#Copy Windows Journal file: USNJRNL:$J
function get_usnjrnl(){
    makegreen "Copying \$LogFile and  \$UsnJrnl:\$J"
    echo "#### USNJRNL ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    tar -Prvf $case_dir/$comp_name-acquisition.tar \$Extend/\$UsnJrnl:\$J | tee -a  $case_dir/Acquisition.log.txt
    echo ""
    tar -Prvf $case_dir/$comp_name-acquisition.tar \$LogFile | tee -a  $case_dir/Acquisition.log.txt
    echo ""
}

#Copy $MFT
function get_mft(){
    makegreen "Saving \$MFT "
    echo "#### MFT ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    echo $mount_dir
    tar -Prvf $case_dir/$comp_name-acquisition.tar \$MFT |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Windows Event Logs
function get_evtx(){
    makegreen "Saving Windows Event Logs"
    echo "#### Windows Event Logs ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $winsysdir/[W,w]inevt/[L,l]ogs -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Windows Registry Files
function get_registry(){
    cd $mount_dir
    makegreen "Saving Windows Registry"
    echo "#### Windows Registry ####" >> $case_dir/Acquisition.log.txt
    find $winsysdir/[C,c]onfig -type f  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy User profile registry hives (NTUSER.DAT)
function get_ntuser(){
    makegreen "Saving NTUSER.DAT"
    echo "#### NTUSER.DAT ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir -maxdepth 2 -mindepth 2 -type f -iname "ntuser.dat" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Userclass.dat files
function get_usrclass.dat(){
    makegreen "Saving usrclass.dat"
    echo "#### USRCLASS.DAT ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Local/Microsoft/Windows -maxdepth 2 -type f -iname "UsrClass.dat" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy LNK and Jumplist file
function get_lnk_files(){
    makegreen "Saving LNK Files"
    echo "#### LNK AND JUMPLISTS ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Microsoft/Windows/Recent -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Prefetch files
function get_prefetch(){
    makegreen "Saving Windows Prefetch"
    echo "#### PREFETCH ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $windir/[P,p]refetch  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Amcache.hve and recentfilecache.bcf
function get_Amcache.hve(){
    makegreen "Saving Amcache.hve and Recentfilecache.bcf"
    echo "#### AMCACHE.HVE AND RECENTFILECACHE.BCF ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    # Get Amcache.hve
    find $windir/[a,A]*/[P,p]* -maxdepth 1 -type f -iname "Amcache.hve" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    # Get recentfilecache.bcf
    find $windir/[a,A]*/[P,p]* -maxdepth 1 -type f -iname "Recentfilecache.bcf" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy metadata files($I*.*) from Windows Recycle.bin
function get_Recycle.Bin(){
    makegreen "Copying RECYCLE BIN"
    echo "#### RECYCLEBIN $I ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find "\$Recycle.Bin" -type f -iname "*\$I*" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}
#Copy WebcacheV01.dat files
function get_webcachev(){
    makegreen "Saving WebcacheV01.dat"
    echo "#### MICROSOFT WEB BROWSER DB (WEBCACHEV01.DAT) ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Local/Microsoft/Windows/WebCache -maxdepth 2 -type f -iname "Webcach*.dat" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Skype main.db files
function get_skype(){
    makegreen "Saving Skype"
    echo "#### SKYPE HISTORY ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Skype/*/ -maxdepth 2 -type f -iname "main.db" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T -  |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy OBJECTS.DATA and *.mof files
function get_WMI_info(){
    # Get OBJECTS.DATA file
    makegreen "Saving OBJECTS.DATA and Mof files"
    echo "#### OBJECTS.DATA AND MOF ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $winsysdir/[W,w][B,b][E,e][M,m] -maxdepth 2 -type f  -iname "OBJECTS.DATA" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    # Get all Mof files
    find $winsysdir/[W,w][B,b][E,e][M,m]/*/ -maxdepth 2 -type f -iname "*.mof" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy SRU.dat
function get_srudb(){
    cd $mount_dir
    makegreen "Saving SRUDB.DAT"
    echo "#### SRUDB.DAT ####" >> $case_dir/Acquisition.log.txt
    find $winsysdir/[S,s][R,r][U,u]/ -maxdepth 1 -mindepth 1 -type f -iname "srudb.dat" 2>/dev/null -print0|\
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy ActivitiesCache.db
function get_ActivitiesCache(){
    cd $mount_dir
    makegreen "Saving ActivitiesCache.db"
    echo "#### ActivitiesCache.db ####" >> $case_dir/Acquisition.log.txt
    find $user_dir/*/AppData/Local/ConnectedDevicesPlatform/ -maxdepth 1 -mindepth 1 -type f -iname "ActivitiesCache.db" 2>/dev/null -print0|\
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}


#Copy Setupapi logs
function get_setupapi(){
    cd $mount_dir
    makegreen "Saving Setupapi.dev.log"
    echo "#### SETUPAPI LOG FILES ####" >> $case_dir/Acquisition.log.txt
    find $windir/[I,i][N,n][F,f] -type f -iname "setupapi*log" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Scheduled Tasks
function get_scheduled_tasks(){
    makegreen "Saving Scheduled Tasks List"
    echo "#### SCHEDULED TASKS ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    #Tasks dir in Windows directory
    find $windir/[t,T]asks -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    #Tasks dir in Windows/System32 directories
    find $winsysdir/[t,T]asks -type f 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
}

#Copy Windows log files
function get_logfiles(){
    makegreen "Saving Windows Log Files" && \
    echo "#### WINDOWS LOGFILES ####" >> $case_dir/Acquisition.log.txt
    find -maxdepth 1 -type d  -iname "inetpub" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    find $winsysdir -maxdepth 2 -type d -iname "LogFiles" -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Chrome metadata
function get_chrome(){
     makegreen "Copying CHROME Metadata"
    echo "#### CHROME ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Local/Google/Chrome/User\ Data/Default -maxdepth 2 -type f \
    \( -name "History" -o -name "Bookmarks" -o -name "Cookies" -o -name "Favicons" -o -name "Web\ Data" \
    -o -name "Login\ Data" -o -name "Top\ Sites" -o -name "Current\ *" -o -name "Last\ *" \)  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}

#Copy Firefox Metadata
function get_firefox(){
    makegreen "Copying FIREFOX Metadata"
    echo "#### FIREFOX ####" >> $case_dir/Acquisition.log.txt
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/ -maxdepth 2 -type f \
    \( -name "*.sqlite" -o -name "logins.json" -o -name "sessionstore.jsonlz4" \)  2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-acquisition.tar --null -T - |tee -a $case_dir/Acquisition.log.txt
    echo ""
}
########END DATA ACQUISITION FUNCTIONS######

######### PROCESSING FUNCTIONS##############

#Run select RegRipper plugins on Software Registry
function regrip_software(){
    cd $case_dir
    makegreen "Running select RegRipper plugins on the Software Registry Hive(s)"
    sleep 1
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/software$"| while read d;
    do
      rip.pl -r "$d" -p winver |tee -a $triage_dir/System_Info/Windows_Version_Info-$comp_name.txt;  # winnt_cv
      rip.pl -r "$d" -p lastloggedon |tee -a $triage_dir/Account_Usage/Last-Logged-On-$comp_name.txt;
      rip.pl -r "$d" -p networklist 2>/dev/null |tee -a $triage_dir/System_Info/Network/Network-List-$comp_name.txt;
      rip.pl -r $d -p profilelist 2>/dev/null |tee -a $triage_dir/Account_Usage/User-Profiles-$comp_name.txt;
      rip.pl -r $d -p pslogging 2>/dev/null |tee -a $triage_dir/System_Info/Settings/Powershell-logging-$comp_name.txt;
      rip.pl -r $d -p clsid 2>/dev/null |tee -a $triage_dir/System_Info/Settings/Clsid-logging-$comp_name.txt;
      rip.pl -r "$d" -p portdev |tee -a $triage_dir/USB_Access/USB_Device_List-$comp_name.txt;
      rip.pl -r "$d" -p runonceex |grep -va "^$"|tee -a $triage_dir/Persistence/Run-Once-$comp_name.txt;
      rip.pl -r "$d" -p appcertdlls |grep -va "^$"|tee -a $triage_dir/Persistence/Appcertsdlls-$comp_name.txt;
      rip.pl -r "$d" -p appinitdlls |grep -va "^$"|tee -a $triage_dir/Persistence/AppInitdlls-$comp_name.txt;
      rip.pl -r "$d" -p dcom |grep -va "^$"|tee -a $triage_dir/Persistence/ports-$comp_name.txt;
      rip.pl -r "$d" -p psscript |grep -va "^$"|tee -a $triage_dir/Persistence/Powershell-Script-$comp_name.txt;
      rip.pl -r "$d" -p listsoft |grep -va "^$"|tee -a $triage_dir/System_Info/Software/Software-Installed-$comp_name.txt;
      rip.pl -r "$d" -p msis |grep -va "^$"|tee -a $triage_dir/System_Info/Software/Msiexec-Installs-$comp_name.txt;
      rip.pl -r "$d" -p uninstall |grep -va "^$"|tee -a $triage_dir/System_Info/Software/Add-Remove-Programs-$comp_name.txt;
      rip.pl -r "$d" -p netsh |grep -va "^$"|tee -a $triage_dir/System_Info/Settings/Netsh-$comp_name.txt;
      rip.pl -r "$d" -p srum |grep -va "^$"|tee -a $triage_dir/Program_Execution/Srum-$comp_name.txt;
      rip.pl -r "$d" -p run |grep -va "^$"|tee -a $triage_dir/Persistence/Autorun-$comp_name.txt;
    done
    # rip all tlns to tempfile
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/software$"| while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run select RegRipper plugins on the System Registry
#######"System_Info/Software" "System_Info/Network" "System_Info/Settings" "Account_Usage"
function rip_system(){
    cd $case_dir
    makegreen "Running select RegRipper plugins on the System Registry Hive(s)"
    sleep 1
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i -m1 "\/system$"| while read d;
    do
      rip.pl -r $d -p nic2 2>/dev/null |tee -a $triage_dir/System_Info/Network/Last-Networks-$comp_name.txt;
      rip.pl -r "$d" -p shares 2>/dev/null|tee -a $triage_dir/System_Info/Network/Network-Shares-$comp_name.txt;
      rip.pl -r "$d" -p shimcache |tee -a $triage_dir/Program_Execution/Shimcache-$comp_name.txt;
      rip.pl -r "$d" -p usbstor |tee -a $triage_dir/USB_Access/USBStor-$comp_name.txt;
      rip.pl -r "$d" -p backuprestore |tee -a $triage_dir/System_Info/Settings/Not-In-VSS-$comp_name.txt;
      rip.pl -r "$d" -p ntds |tee -a $triage_dir/Persistence/ntds-$comp_name.txt;
      rip.pl -r "$d" -p devclass |tee -a $triage_dir/USB_Access/USBdesc-$comp_name.txt;
      rip.pl -r "$d" -p lsa |tee -a $triage_dir/System_Info/Settings/Lsa-$comp_name.txt;
      rip.pl -r "$d" -p rdpport |tee -a $triage_dir/System_Info/Settings/RDP-Port-$comp_name.txt;
      rip.pl -r "$d" -p remoteaccess |tee -a $triage_dir/System_Info/Settings/Remote-Access-Lockout-$comp_name.txt;
      rip.pl -r "$d" -p routes |tee -a $triage_dir/System_Info/Network/Routes-$comp_name.txt;
    done
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/system$"| while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run select RegRipper plugins on the Security Registry
function rip_security(){
    cd $case_dir
    makegreen "Running select RegRipper plugins on the Security Registry Hive(s)"
    sleep 1
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -m1 -i "\/security$"| while read d;
    do
      rip.pl -r $d -p auditpol 2>/dev/null |tee -a $triage_dir/System_Info/Settings/Audit-Policy-$comp_name.txt;
    done
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/security$" | while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run all RegRipper plugins on NTUSER.DAT and Usrclass.dat
function regrip_ntuser_usrclass(){
    find "/$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      usrclass_file=$(find /$mount_dir/$user_dir/"$user_name"/[aA]*[aA]/[lL]*[lL]/[mM][iI]*[tT]/[wW]*[sS] -maxdepth 3 -type f 2>/dev/null|grep -i -m1 "\/usrclass.dat$")
      echo $usrclass_file
      rip.pl -r "$ntuser_path" -a |tee -a "$triage_dir/Regripper/$user_name/$comp_name-$user_name-NTUSER.txt"
      rip.pl -aT -r "$ntuser_path" |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
      rip.pl -r "$usrclass_file" -a |tee -a "$triage_dir/Regripper/$user_name/$comp_name-$user_name-USRCLASS.txt"
      rip.pl -aT -r "$usrclass_file" |sed "s/|||/|${comp_name}|${user_name}|/" >> $tempfile
    done
}

#Run Select Regripper plugins on NTUSER.DAT
function regrip_user_plugins(){
    makegreen "Searching for NTUSER.DAT KEYS (Regripper)"
    sleep 1
    cd $mount_dir/$user_dir/
    find "/$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      rip.pl -r "$ntuser_path" -p userassist |tee -a "$triage_dir/Program_Execution/UserAssist-$user_name-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p recentdocs |tee -a "$triage_dir/File_Access/$user_name-RecentDocuments-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/User_Searches/ACMRU-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p runmru |grep -va "^$"|tee -a "$triage_dir/Program_Execution/Run-MRU-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/File_Access/opened-saved-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p comdlg32 |grep -va "^$"|tee -a "$triage_dir/File_Access/opened-saved-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/User_Searches/Wordwheel-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p wordwheelquery |grep -va "^$"|tee -a "$triage_dir/User_Searches/Wordwheel-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/User_Searches/Typedpaths-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p typedpaths |grep -va "^$"|tee -a "$triage_dir/User_Searches/Typedpaths-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/User_Searches/Typedurls-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p typedurls |grep -va "^$"|tee -a "$triage_dir/User_Searches/Typedurls-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/User_Searches/Typedurlstime-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p typedurlstime |grep -va "^$"|tee -a "$triage_dir/User_Searches/Typedurlstime-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/Program_Execution/Run_Open-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p run |grep -va "^$"|tee -a "$triage_dir/Program_Execution/Run-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/System_Info/Settings/Compatibility_Flags-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p appcompatflags |grep -va "^$"|tee -a  "$triage_dir/System_Info/Settings/Compatibility_Flags-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/Account_Usage/Logons-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p logonstats |grep -va "^$"|tee -a  "$triage_dir/Account_Usage/Logons-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/Program_Execution/Jumplist-Reg-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p jumplistdata |grep -va "^$"|tee -a  "$triage_dir/Program_Execution/Jumplist-Reg-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/File_Access/Mount-Points-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p mp2 |grep -va "^$"|tee -a  "$triage_dir/File_Access/Mount-Points-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/File_Access/Office-cache-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p oisc |grep -va "^$"|tee -a  "$triage_dir/File_Access/Office-cache-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/Persistence/Profiler-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p profiler |grep -va "^$"|tee -a "$triage_dir/Persistence/Profiler-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/Persistence/Load-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p load |grep -va "^$"|tee -a  "$triage_dir/Persistence/Load-$comp_name.txt"

      echo "######  "$user_name"  ######" |tee -a "$triage_dir/Alert/NTUSER-$comp_name.txt"
      rip.pl -r "$ntuser_path" -p rlo |grep -va "^$"|tee -a "$triage_dir/Alert/NTUSER-$comp_name.txt"
    done
}

#Run RegRipper on SAM Registry hive
function regrip_sam(){
    cd $mount_dir
    makegreen "Searching for SAM (Regripper)"
    sleep 1
    counter="0" && find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/sam$"| while read d;
    do
      rip.pl -r "$d" -a |tee -a $triage_dir/Account_Usage/SAM-$comp_name-$counter.txt && counter=$((counter +1));
    done
    find $mount_dir/$winsysdir/$regdir -maxdepth 1 -type f 2>/dev/null | grep -i "\/sam$" | while read d;
    do
      rip.pl -aT -r $d |sed "s/|||/|${comp_name}||/" >> $tempfile
    done
}

#Run RegRipper on AmCache.hve
function regrip_amcache.hve(){
    makegreen "Extracting Any RecentFileCache/AmCache (Regripper)"
    amcache_file=$(find $mount_dir/$windir/[a,A]*/[P,p]* -maxdepth 1 -type f |egrep -m1 -i \/amcache.hve$)

    [ "$amcache_file" ] && \
    rip.pl -aT -r "$amcache_file" |sed "s/|||/|${comp_name}|${user_name}|/"| tee -a $tempfile
    rip.pl -r "$amcache_file" -p amcache |tee -a "$triage_dir/Program_Execution/Amcache-$comp_name.txt"
}

#Run Regripper on SysCache.hve
function regrip_syscache.hve_tln(){
  syscache_file=$(find "$mount_dir" -maxdepth 0 -type f 2>/dev/null|grep -i -m1 "System\ Volume\ Information\syscache.hve$" )
  [ "$syscache_file" ] && \
  rip.pl -aT -r "$syscache_file" >> $tempfile
}

function del_no_result(){
  cd $case_dir
  grep -RL ".:." /cases/ |while read d;
  do
    rm $d
  done
}


function lnkinfo(){
  cd $mount_dir
  find $mount_dir/$user_dir/*/ -type f|grep lnk$ | while read d;
  do
    echo $d && \
    /usr/bin/lnkinfo -v "$d"  |tee -a $triage_dir/Program_Execution/lnkinfo-$comp_name.txt
  done
}


#Timeline recycle.bin metadata
function recbin2tln(){
    cd $mount_dir
    makegreen "Parsing \$Recycle.Bin"
    find $mount_dir/\$* -type f 2>/dev/null|grep "\$I"|sed 's|^\.||'|while read d;
    do
      ls $d
      sid=$(echo $d |sed 's|^\.||'|sed 's/^.*recycle.bin\///I'|awk -F'/' '{print $1}')
      name=$(strings -el -f $d)
      hexsize=$(cat "$d"|xxd -s8 -l8 -ps| sed -e 's/[0]*$//g')
      size=$(echo $((0x$hexsize)))
      hexdate0=$(cat "$d"|xxd -ps -s16 -l8 |grep -o .. |tac| tr -d '\n')
      #hexdate0=$(cat "$d"|xxd -s16 -l8 -ps|awk '{gsub(/.{2}/,"& ")}1'|awk '{for(i=NF; i>0;i--)printf "%s",$i}' && echo "")
      epoch=$(echo $((0x$hexdate0/10000000-11644473600)))
      #epoch=$(echo $(($hexdate1-11644473600)))
      date=$(date -d @$epoch +"%Y-%m-%d %H:%M:%S")
      echo "$epoch|Recycle|"$comp_name"||[Deleted] "$name " FILE SIZE: "$size| tee -a  >> $tempfile
      echo "$date,Recycle,"$comp_name",,[Deleted] "$name " FILE SIZE: "$size| tee -a $triage_dir/File_Access/Recycled.csv
      echo "hexdateraw" $hexdate0
    done
}

#Timeline Chrome metadata
function chrome2tln(){
    makegreen "Extracting Any CHROME HISTORY and DOWNLOADS (sqlite3)"
    cd $mount_dir
    find $user_dir/*/AppData/Local/Google/Chrome/User\ Data/Default -maxdepth 0 -type d |while read d;
    do
      echo $d
      user_name=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
      makegreen "Searching for CHROME HISTORY and DOWNLOADS (sqlite3)"


      #Extract Chrome Browsing history
      cd $mount_dir
      [ "$d/History" != "" ] && \
      sqlite3 "$d/History" "select datetime(last_visit_time/1000000-11644473600, 'unixepoch'),url, title, visit_count from urls ORDER BY last_visit_time" | \
      awk -F'|' '{print $1",chrome,,,[URL]:"$2",TITLE: "$3", VISIT COUNT:"$4}'| \
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$triage_dir/Browser_Activity/$user_name-Chrome-History-$comp_name.csv"

      # Extract Chrome Downloads
      [ "$d" != "" ] && \
      sqlite3 "$d/History" "select datetime(start_time/1000000-11644473600, 'unixepoch'), url, target_path, total_bytes FROM downloads INNER JOIN downloads_url_chains ON downloads_url_chains.id = downloads.id ORDER BY start_time" | \
      awk -F'|' '{print $1",chrome,,,[DOWNLOAD]-"$2",TARGET:-"$3", BYTES TRANSFERRED:-"$4}' | \
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$triage_dir/Browser_Activity/$user_name-Chrome-Download-$comp_name.csv"

      #Extract Chrome cookies
      [ "$d" != "" ] && \
      sqlite3 "$d/Cookies" "select datetime(cookies.creation_utc/1000000-11644473600, 'unixepoch'), cookies.host_key,cookies.path, cookies.name, datetime(cookies.last_access_utc/1000000-11644473600,'unixepoch','utc'), cookies.value FROM cookies"| \
      awk -F'|' '{print $1",chrome,,,[Cookie Created]:"$2" LASTACCESS: "$5" VALUE: "$4}'| \
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$triage_dir/Browser_Activity/$user_name-Chrome-Cookies-$comp_name.csv"

      #Extract Chrome Login Data
      [ "$d" != "" ] && \
      sqlite3 "$d/Login Data" "select datetime(date_created/1000000-11644473600, 'unixepoch'),  origin_url,username_value,signon_realm FROM logins"| \
      awk -F'|' '{print $1",chrome,,,[Login Data]:SITE_ORIGIN:"$2" USER_NAME: "$3" SIGNON_REALM "$4}' |\
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$triage_dir/Browser_Activity/$user_name-Chrome-LoginData-$comp_name.csv"
      #Extract Chrome Web Data
      [ "$d" != "" ] && \
      sqlite3 "$d/Web Data" "select datetime(date_last_used, 'unixepoch'), name,value, count, datetime(date_created, 'unixepoch') from autofill"|\
      awk -F'|' '{print $1",chrome,,,[WebData] CREATED:"$5" NAME:"$2" VALUE:"$3" COUNT:"$4}'| \
      sed "s/,,,/,${comp_name},${user_name},/" |tee -a "$triage_dir/Browser_Activity/$user_name-Chrome-WebData-$comp_name.csv"

      #Extract Chrome Bookmarks
      [ "$d" != "" ] && \
      cat "$d/Bookmarks" |jq -r '.roots[]|recurse(.children[]?)|select(.type != "folder")|{date_added,name,url}|join("|")'|\
      awk -F'|' '{print int($1/1000000-11644473600)"|"$2"|"$3}'| \
      awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1",Chrome,,,[Bookmark Created] NAME:"$2" URL:"$3}' |\
      sed "s/,,,/,${comp_name},${user_name},/" | tee -a "$triage_dir/Browser_Activity/$user_name-Chrome-Bookmarks-$comp_name.csv"

      #Run Hindsight on Chrome
      cd $triage_dir/Browser_Activity
      python /usr/local/src/Hindsight/hindsight.py -i "$mount_dir/$d" -o "$triage_dir/Browser_Activity/$user_name-Hindsight" -l "$triage_dir/Browser_Activity/hindsight.log"

    done

    # Copy Files to Timeline Temp File
    find $triage_dir/Browser_Activity/ -type d |grep "Chrome" | while read d;
    do
      echo "$d"| while read f;
        do
        timestamp=$(echo "$f"| awk -F',' '{print $1}'| grep -E '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
          [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
          tlninfo=$(echo "$f"| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')
          [ "$timestamp" != "" ] && echo $tlntime$tlninfo | >> $tempfile
        done
      done
}

#Timeline Firefox metadata
function firefox2tln(){
    makegreen "Extracting Any Firefox HISTORY, DOWNLOADS and COOKIES (sqlite3)"
    cd $mount_dir
    find $user_dir/*/AppData/Roaming/Mozilla/Firefox/Profiles/*/ -maxdepth 0 -type d 2>/dev/null|while read d;
    do
      user_name=$(echo "$d"|sed 's/\/AppData.*//'|sed 's/^.*\///')
      #Extract FireFox Browsing history (places.sqlite)
      [ -e "$d/places.sqlite" ] && \
      sqlite3 file:"$d/places.sqlite" "select (moz_historyvisits.visit_date/1000000), moz_places.url, moz_places.title, moz_places.visit_count FROM moz_places,moz_historyvisits where moz_historyvisits.place_id=moz_places.id order by moz_historyvisits.visit_date;" |\
      awk -F'|' '{print $1"|FireFox|||[URL]:"$2"  TITLE:"$3" VISIT-COUNT:" $4}'| sed "s/|||/|${comp_name}|${user_name}|/" |\
      tee -a "$triage_dir/Browser_Activity/$user_name-FireFox-History-$comp_name.csv"

      # Extract FireFox Downloads
      [ -e "downloads.sqlite" ] && \
      sqlite3 file:"$d/places.sqlite" "select (startTime/1000000), source,target,currBytes,maxBytes FROM moz_downloads" |awk -F'|' '{print $1"|FireFox|||[Download]:"$2"=>"$3" BYTES DOWNLOADED=>"$4" TOTAL BYTES=>"$5}' | sed "s/|||/|${comp_name}|${user_name}|/" | \
      tee -a "$triage_dir/Browser_Activity/$user_name-FireFox-Downloads-$comp_name.csv"

      #Extract FireFox cookies
      [ -e "cookies.sqlite" ] && \
      sqlite3 file:"$d/cookies.sqlite" "select (creationTime/1000000), host,name,datetime((lastAccessed/1000000),'unixepoch','utc'),datetime((expiry/1000000),'unixepoch','utc') FROM moz_cookies" |\
      awk -F'|' '{print $1"|FireFox||| [Cookie Created]: "$2" NAME:"$3" ,LAST ACCESS:"$4", EXPIRY: "$5}'| \
      sed "s/|||/|${comp_name}|${user_name}|/" | \
      tee -a "$triage_dir/Browser_Activity/$user_name-FireFox-Cookies-$comp_name.csv"
    done
    # Copy Files to Timeline Temp File
    find $triage_dir/Browser_Activity/ -type d |grep "FireFox" 2>/dev/null| while read d;
    do
      echo "$d"| while read f;
        do
        timestamp=$(echo "$f"| awk -F',' '{print $1}'| grep -E '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
          [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
          tlninfo=$(echo "$f"| awk -F',' '{print "|"$2"|"$3"|"$4"|"$5}')
          [ "$timestamp" != "" ] && echo $tlntime$tlninfo | >> $tempfile
        done
      done
}


function extract_webcacheV(){
    cd $mount_dir/$user_dir/
    makegreen "Extracting any IE WebcacheV0x.dat files (esedbexport)"
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      find /$mount_dir/$user_dir/$user_name/AppData/Local/Microsoft/Windows/WebCache -maxdepth 2 -type f -iname "WebcacheV*.dat" 2>/dev/null |while read d;
      do
        /usr/bin/esedbexport -t $triage_dir/Browser_Activity/IEWebcache-$user_name-$comp_name "$d";
      done
    done
}

function extract_srudb(){
    makegreen "Extract srudb.dat file"
    find /$mount_dir/$winsysdir/[S,s][R,r][U,u] -maxdepth 2 -type f -iname "srudb.dat" 2>/dev/null |while read d;
    do
      echo "/usr/bin/esedbexport -t $triage_dir/Browser_Activity/SRU-$comp_name "$d""
      /usr/bin/esedbexport -t $triage_dir/System_Info/Network/SRU-$comp_name "$d";
    done
    cd /$mount_dir
}


function parse_current.mdb(){
    cd $mount_dir
    makegreen "Parse Current.mdb file"
    find /$mount_dir/$winsysdir/[L,l]*[S,s]/[S,s][U,u][M,m] -type f -iname "Current.mdb"| while read d;
    do
      python /usr/local/src/KStrike/KStrike.py "$d" |tee -a $case_dir/Triage/File_Access/Current.mdb-$comp_name.txt
    done
}
    
#Run Bits_parser  TODO	

#Timeline Alternate Data Streams
function ADS_extract(){
    cd $mount_dir

    #  scan mounted NTFS disk Alternate Data Streams and Timestamps
    [ "$(getfattr -n ntfs.streams.list $mount_dir 2>/dev/null)" ]  && makegreen "Extracting Alternate Data Streams" &&\
    getfattr -Rn ntfs.streams.list . 2>/dev/null |\
    grep -ab1 -h ntfs.streams.list=|grep -a : |sed 's/.*ntfs.streams.list\="/:/g'|\
    sed 's/.*# file: //'|sed 's/"$//g'|paste -d "" - -|grep -v :$ | while read ADS_file;
    do
      base_file=$(echo "$ADS_file"|sed 's/:.*//')
      crtime=$(getfattr -h -e hex -n system.ntfs_times_be "$base_file" 2>/dev/null|grep "="|awk -F'=' '{print $2}'|grep -o '0x................')
      epoch_time=$(echo $(($crtime/10000000-11644473600)))
      [ $epoch_time ] || epoch_time="0000000000"
      MAC=$(stat --format=%y%x%z "$base_file" 2>/dev/null)
      [ "$ADS_file" ] && echo "$epoch_time|ADS|$comp_name||[ADS Created]: $ADS_file [MAC]: $MAC"|grep -va "ntfs.streams.list\="|tee -a $tempfile
      [ "$ADS_file" ] && echo "$epoch_time|ADS|$comp_name||[ADS Created]: $ADS_file [MAC]: $MAC" |grep -va "ntfs.streams.list\="|grep Zone.Identifier| tee -a $triage_dir/Browser_Activity/Zone.Identifier-$comp_name.csv
    done
}

#Timeline Prefetch and extract metadata
function prefetch_extract(){
    cd $mount_dir
    makegreen "Searching for PREFETCH (prefetchruncounts.py)"
    sleep 1
    find "/$mount_dir/$windir/" -maxdepth 1 -type d -iname "Prefetch" |sed 's/$/\//'| while read d;
    do
      python3 /usr/local/bin/prefetchruncounts.py "$d" -o $triage_dir/Program_Execution/Prefetch-$comp_name
    done

    find $triage_dir/Program_Execution |grep run_count |while read d;
    do
    cat $d | while read line;
      do
        timestamp=$(echo $line| awk -F',' '{print $1}'| grep -Eo '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
        [ "$timestamp" != "" ] && tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
        tlninfo=$(echo $line| awk -F',' '{print "[Program Execution] File:"$2" Run Count:"$4" Vol_ID:"$8" "$11}')
        [ "$timestamp" != "" ] && echo $tlntime"|prefetch|"$comp_name"||"$tlninfo | tee -a $tempfile
      done
    done
}

#Timeline Windows Services
function winservices(){
    cd $mount_dir
    makegreen "Searching for windows Services (winservices.py)"
    sleep 1
    counter="0" && find $mount_dir/$winsysdir/$regdir -type f 2>/dev/null | grep -i \/system$| while read d;
    do
      python3 /usr/local/bin/winservices.py "$d" |tee -a $triage_dir/Persistence/WindowsServices-$comp_name-$counter.txt && counter=$((counter +1));
    done

    find $triage_dir/Persistence/ -type f |grep "WindowsServices-" | while read d;
    do
      cat "$d" |while read f;
        do
          timestamp=$(echo "$f" awk -F',' '{print $1}'| grep -Eo '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) (2[0-3]|[01][0-9]):[0-5][0-9]:[0-5][0-9]')
          tlntime=$(date -d "$timestamp"  +"%s" 2>/dev/null)
          tlninfo=$(echo "$f"| awk -F',' '{print "||[Service Last Write]: "$2","$3","$5","$7}')
          echo $tlntime"|Reg|"$comp_name$tlninfo |tee -a $tempfile
        done
    done
}


#Consolidating TLN Output and consolidating timelines
function consolidate_timeline(){
    makegreen "Consolidating TLN Files"
    echo ""
    cat $tempfile | sort -rn |uniq | tee -a | tee -a $triage_dir/Timeline/Triage-Timeline-$comp_name.TLN;
    cat $tempfile |awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'|sort -rn | uniq| grep -va ",,,," |tee -a $triage_dir/Timeline/Triage-Timeline-$comp_name.csv.txt
    cat $triage_dir/Timeline/Triage-Timeline-$comp_name.csv.txt|grep -ia ",alert," |tee -a $triage_dir/Alert/RegRipperAlerts-$comp_name.csv
    makegreen "Complete!"
}

#copy setupapi logs
function cp_setupapi(){
    cd $mount_dir
    makegreen "Copying setupapi.dev.log"

    find $case_dir -type f 2>/dev/null | grep -i setupapi.dev.log | grep -i log$ |while read d;
    do
      cp "$d" $triage_dir/USB_Access/setupapi.dev.log-$comp_name.txt 2>/dev/null;
    done
}

#Run Jobparse.py and Extract Windows Event Log: TaskScheduler%4operational.evtx
function extract_Jobs(){
    cd $mount_dir
    makegreen "Searching for SCHEDULED TASKS (jobparser.py)"
    sleep 1
    find $windir -maxdepth 2 -type d 2>/dev/null  | grep -i '\/tasks$'|sed 's|^\./||'|while read d;
    do
      echo "######## $d ########" |tee -a $triage_dir/Persistence/Jobs-$comp_name.txt
      python2 /usr/local/bin/jobparser.py -d "$d" |tee -a $triage_dir/Persistence/Jobs-$comp_name.txt;
    done
}

#Parse OBJECTS.DATA file
extract_objects_data(){
    cd $mount_dir
    makegreen "Searching for Object.data file (PyWMIPersistenceFinder.py, CCM-RecentApps.py)"
    sleep 1
    find $winsysdir -maxdepth 3 -type f 2>/dev/null  | grep -i '\/objects.data$'|sed 's|^\./||'|while read d;
    do
      python2 /usr/local/bin/CCM_RUA_Finder.py -i "$d" -o $triage_dir/Program_Execution/CCM-RecentApps-$comp_name.csv
      python2 /usr/local/bin/PyWMIPersistenceFinder.py "$d" |tee -a $triage_dir/Persistence/WMI-Persistence-$comp_name.csv
    done
}

#Parse Windows History File
extract_winactivities(){
    cd $mount_dir
    makegreen "Searching for ActivitiesCache.db"
    cd $mount_dir/$user_dir/
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      find "$mount_dir/$user_dir/$user_name/AppData/Local/ConnectedDevicesPlatform" -maxdepth 5 -type f 2>/dev/null | \
      grep -i "ActivitiesCache.db$"| sed 's|^\./||'|while read d;
      do
        sqlite3 "$d" ".read /usr/local/src/kacos2000/WindowsTimeline/WindowsTimeline.sql" | tee -a $triage_dir/ActivitiesCache/Activity-$user_name-$comp_name.csv
      done
    done
}

#Parse IE History File Index.dat
parse_index.dat(){
    cd $mount_dir
    makegreen "Searching for any index.dat files"
    cd $mount_dir/$user_dir/
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      find "$mount_dir/$user_dir/$user_name/AppData" -size +5k -maxdepth 9 -type f 2>/dev/null | \
      grep -i \/index.dat$ | sed 's|^\./||'|while read d;
      do
        parseie.pl -t -s $comp_name -u $user_name -f "$d"| grep -Ev ietld\|iecompat >> $tempfile
        parseie.pl -t -s $comp_name -u $user_name -f "$d" | grep -Ev ietld\|iecompat |\
        awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| \
        tee -a $triage_dir/Browser_Activity/Index.dat-$user_name-$comp_name.csv
      done
    done
}

# Extract WindowsEvent Logs
function extract_WinEVTX(){
    cd $mount_dir
    makegreen "Searching for windows Event Logs"
    sleep 1
    #Microsoft-Windows-TaskScheduler4Operational.evtx
    find $mount_dir/$winsysdir/$evtxdir -type f 2>/dev/null | grep -i \/Microsoft-Windows-TaskScheduler\%4Operational.evtx$| while read d;
    do
      python3 /usr/local/bin/parse_evtx_tasks.py "$d" |tee -a $triage_dir/WindowsEventLogs/Task-Scheduler-evtx-$comp_name.txt;
    done
    find $mount_dir/$winsysdir/$evtxdir -type f 2>/dev/null | grep -i \/Microsoft-Windows-TerminalServices-LocalSessionManager\%4Operational.evtx| while read d;
    do
      python3 /usr/local/bin/parse_evtx_RDP_Local.py "$d" |tee -a $triage_dir/WindowsEventLogs/RDP-evtx-$comp_name.txt;
    done
    find $mount_dir/$winsysdir/$evtxdir -type f 2>/dev/null | grep -i \/Microsoft-Windows-TerminalServices-RemoteConnectionManager\%4Admin.evtx$| while read d;
    do
      python3 /usr/local/bin/parse_evtx_RDP_Remote.py "$d" -n |tee -a $triage_dir/WindowsEventLogs/RDP-evtx-$comp_name.txt;
    done  
    find $mount_dir/$winsysdir/$evtxdir -type f 2>/dev/null | grep -i \/Microsoft-Windows-Bits-Client\%4Operational.evtx$| while read d;
    do
      python3 /usr/local/bin/parse_evtx_BITS.py "$d" -n |tee -a $triage_dir/WindowsEventLogs/BITS-evtx-$comp_name.txt;
    done   
    #find $mount_dir/ -type f 2>/dev/null | grep -i \/Microsoft-Windows-RemoteDesktopServices-RdpCoreTS\%4Operational.evtx$| while read d;
    #do
    #  python3 /usr/local/bin/parse_evtx_RDP_Core.py "$d" |tee -a $triage_dir/WindowsEventLogs/RDP-evtx-$comp_name.txt;
    #done
}


# Extract WindowsEvent Logs to jsonl
function evtxdump(){
    cd $mount_dir
    makegreen "Searching for windows Event Logs"
    sleep 1
    mkdir -p "$triage_dir/WindowsEventLogs/jsonl"
    find $mount_dir/$winsysdir/$evtxdir -type f 2>/dev/null -size +70k -name '*.evtx' | while read d;
    do
      evtx_file=$(basename "$d")
      makegreen "Processing Windows Event Log $evtx_file"
      evtx_dump "$d" -o jsonl -f "$triage_dir/WindowsEventLogs/jsonl/$evtx_file.jsonl"
      head "$triage_dir/WindowsEventLogs/jsonl/$evtx_file.jsonl"
    done
    find $triage_dir/WindowsEventLogs/jsonl/ -type f 2>/dev/null | \
    grep Microsoft-Windows-PowerShell%4Operational.evtx.jsonl| while read d;
    do
      cat "$d" |jq -j '.Event|select(.EventData.ScriptBlockText !=null)|.System.Computer,.System.TimeCreated."#attributes".SystemTime,.EventData.Path,.System.Security."#attributes".UserID,.EventData.ScriptBlockText,.System.Channel' | \
      tee -a $triage_dir/WindowsEventLogs/PowerShellScriptBlocks.txt
    done
    
    find $triage_dir/WindowsEventLogs/jsonl/ -type f 2>/dev/null | \
    grep Windows.PowerShell.evtx.jsonl| while read d;
    do
      cat "$d" |    
          jq  '.Event|select(.EventData.Data."#text"!=null)|.System.Computer,.System.TimeCreated."#attributes".SystemTime,.EventData.Data,.System.Channel'| \
      tee -a $triage_dir/WindowsEventLogs/PowerShell-HostApplication.txt
    done
    
    find $triage_dir/WindowsEventLogs/jsonl/ -type f| while read d; 
    do 
    echo $d && grep -Eoa "\b(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b" "$d"|sort -u && echo "********************************************************";done| \
    tee -a $triage_dir/WindowsEventLogs/IPv4-Addresses-in-evtx.txt

}


#Extract MFT to body file and then to TLN and csv files
function analyze_mft(){
    cd $mount_dir
    makegreen "Analyzing \$MFT Standby..."
    [ -f "\$MFT" ] && \
    python2 /usr/local/bin/analyzeMFT.py -p -f \$MFT --bodyfull --bodyfile=$triage_dir/Timeline/MFT/MFT-$comp_name.body
    [ -f $triage_dir/Timeline/MFT/MFT-$comp_name.body ] && bodyfile.pl -f $triage_dir/Timeline/MFT/MFT-$comp_name.body -s $comp_name | \
    sort -rn |tee $triage_dir/Timeline/MFT/MFT-$comp_name.TLN.txt && \
    cat $triage_dir/Timeline/MFT/MFT-$comp_name.TLN.txt | awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| \
    tee -a $triage_dir/Timeline/MFT/MFT-$comp_name.csv
    mft_dump \$MFT -o csv -f $triage_dir/Timeline/MFT/MFT_Dump-$comp_name.csv
}

#Extract $USNJRNL:$J to TLN
function parse_usn(){
    cd $mount_dir
    makegreen "Extracting \$USNJRNL:$J Standby..."
    [ -f "\$Extend/\$UsnJrnl:\$J" ] && \
    python2 /usr/local/bin/usn.py -t -s $comp_name -f "\$Extend/\$UsnJrnl:\$J"  -o $triage_dir/Timeline/USNJRNL/USNJRNL-$comp_name.TLN.txt
    cat $triage_dir/Timeline/USNJRNL/USNJRNL-$comp_name.TLN.txt | awk -F'|' '{$1=strftime("%Y-%m-%d %H:%M:%S",$1)}{print $1","$2","$3","$4","$5}'| \
    tee -a $triage_dir/Timeline/USNJRNL/USNJRNL-$comp_name.csv
}

# Find and extract Outlook files
function extract_Outlook_pst_ost(){
    cd $mount_dir/$user_dir/
    counter=0
    find "$mount_dir/$user_dir/" -maxdepth 2 ! -type l 2>/dev/null|grep -i ntuser.dat$ |while read ntuser_path;
    do
      user_name=$( echo "$ntuser_path"|sed 's/\/$//'|awk -F"/" '{print $(NF-1)}')
      makegreen "Searching for OUTLOOK EMAIL Files to extract (pffexport)"
      find $mount_dir -type f 2>/dev/null |grep -Ei "\.pst$"\|"\.ost$"|while read d;
      do
        pffexport "$d" -t $triage_dir/Outlook/$user_name$counter && counter=$((counter +1))
      done
    done
}

# Collect Volatilile data files and copies them to the cases folder
function get_volatile(){
    cd $mount_dir
    find -maxdepth 1 -iname "*file.sys" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-volatile-files.tar --null -T -
    find -maxdepth 1 -iname "*hiberfil.sys" 2>/dev/null -print0| \
    tar -rvf  $case_dir/$comp_name-volatile-files.tar --null -T -
    gzip -f $case_dir/$comp_name-volatile-files.tar
    makegreen "Complete!!"
}

clear
[ $(whoami) != "root" ] && makered "Siftgrab Requires Root!" && exit
show_menu
exit 0
