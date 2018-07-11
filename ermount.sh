#!/bin/bash
# Mount E01 and Raw image Files 
# requires mmls if mounting full disk image
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
#User Interactive Function yes or no
function yes-no(){
      read -p "(Y/N)?"
      [ "$(echo $REPLY | tr [:upper:] [:lower:])" == "y" ] &&  YES_NO="yes";
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
      [ "$(ls -A $MOUNT_DIR)" ] && umount $MOUNT_DIR && echo "$MOUNT_DIR umount failed, try rebooting" && sleep 2 && exit
}
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
      [ "$YES_NO" == "yes" ] && ls /mnt/vss|while read i; do mount -t ntfs -o ro,loop,show_sys_files,streams_interface=windows /mnt/vss/$i /mnt/shadow_mount/$i;done 
}
######### END DRIVE MOUNTING FUNCTIONS ###########
           clear
           echo ""
           [ `whoami` != 'root' ] && makered "Requires Root Access!" && sleep 1 && exit
           makegreen "Mount an E01 or RAW disk image file"
           mount_prefs
           set_msource_path
           set_image_offset
           mount_image
           mount_vss