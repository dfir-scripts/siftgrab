#!/bin/bash
# Every ready disk mount disk utility:
# Mounts disk images (E01,vmdk, vdi, vmdk and Raw) in a linux evnironment using ewf_mount,qemu-ndb, affuse and mount 
# WARNING:  Forcefully disconnects and remounts images and network block devices! 
# Mounts everything in /tmp/ 
#Intended for use in a lab or forensic environment only
# Requires mmls, ewf_tools, affuse and qemu-utils 
# https://stackoverflow.com/questions/22327728/mounting-vmdk-disk-image

#Produce Red Text Color 
function makered() {
      COLOR='\033[01;31m' # bold red
      RESET='\033[00;00m' # normal white
      MESSAGE=${@:-"${RESET}Error: No message passed"}
      echo -e "${COLOR}${MESSAGE}${RESET}"
}
 
#Produce Green Text Color
function makegreen() {
      COLOR='\033[0;32m' # Green
      RESET='\033[00;00m' # normal white
      MESSAGE=${@:-"${RESET}Error: No message passed"}
      echo -e "${COLOR}${MESSAGE}${RESET}"
}

#Function ask yes or no
function yes-no(){
      read -p "(Y/N)?"
      [ "$(echo $REPLY | tr [:upper:] [:lower:])" == "y" ] &&  YES_NO="yes";
}

# Report mount status
mount_status(){
     mount_stat=$(echo " /tmp/ermount/" && [ "$(ls -A /tmp/ermount/ 2>/dev/null)" ] && makegreen " Mounted" || makered " Not Mounted" )
     ewf_stat=$(echo " /tmp/ewf/ewf1" && [ "$(ls -A /tmp/ewf/ 2>/dev/null)" ] && makegreen " Mounted"  || makered " Not Mounted")
     aff_stat=$(echo " /tmp/aff/" && [ "$(ls -A /tmp/aff/ 2>/dev/null)" ] && makegreen " Mounted"  || makered " Not Mounted")
     nbd_stat=$(echo " /dev/nbd1/" && [ "$(ls /dev/nbd1 2>/dev/null)" ] && makegreen " Active"  || makered " Inactive")
     vss_stat=$(echo " /tmp/vss/" && [ "$(ls /tmp/vss 2>/dev/null)" ] && makegreen " Active"  || makered " Inactive")
}

############################################
######### MOUNT PREFS ######################
############################################
# User input path of the image file 
function image_source(){
makered "ENTER PATH AND IMAGE FILE NAME TO MOUNT"
      read -e -p "Image File: " -i "" ipath
      [ ! -f "${ipath}" ] && makered "File does not exist.." && sleep 1 && clear && exit
      image_type=$(echo "$ipath"|awk -F . '{print toupper ($NF)}')
      vmdk_type=$(file "$ipath" | grep "ASCII text$") 
      image_name=$(echo $ipath|sed 's/\(.*\)\..*/\1\./')
      multi=$image_name"002"
      # Set source image and destination mount point for E01 && umount /tmp/ewf 2>/dev/null 
      echo ""
      echo "Image type " $image_type
      file "$ipath"
      echo ""
      makered "FILE SYSTEM TYPE (mount -t)"
      echo "Defaults is ntfs, see mount man pages for others fs types "
      read -e -p "File System:  " -i "ntfs" fstype
      [ $fstype == ntfs ] && umount_vss && echo "VSCs umounted"
}


# User input to set mount directories 
function mount_point(){
      # Set Data Source or mount point"
      echo ""
      makered "SET MOUNT POINT"
      echo "Set Path or Enter to Accept Default:"
      read -e -p "" -i "/tmp/ermount" mount_dir
      mkdir -p $mount_dir
      [ "$(ls -A $mount_dir)" ] && umount $mount_dir -f -A
      [ "$(ls -A $mount_dir)" ] && echo "$mount_dir busy, try different mount point or reboot" && sleep 2 && exit
      echo ""
}

############################################
######### IMAGE OFFSET #####################
############################################
# Runs mmls as needed to find any partition offsets
function set_image_offset(){
      makered "RUN MMLS IF NEEDED TO CHOOSE PARTITION OFFSET"
      mmls "${image_src}" 2>/dev/null && \
      read -e -p "Enter the starting block: "  starting_block && \
      read -e -p "Set disk block size:  " -i "512" block_size && \
      partition_offset=$(echo $(($starting_block * $block_size))) && \
      makegreen "OFFSET: $starting_block * $block_size = $partition_offset" && \
      offset=",offset=$partition_offset" || \
      echo "Single partition, mmls not needed"
}

############################################
######### IMAGE MOUNTING ###################
############################################
# Mount images in expert witness format as raw image to /tmp/ewf
function mount_e01(){
      image_src="/tmp/ewf/ewf1"
      makered "CURRENT MOUNT STATUS: "
      echo $ewf_stat
      echo $mount_stat
      [ "$(ls -A /tmp/ewf/)" ] && echo "Attempting to remount /tmp/ewf/ " && umount /tmp/ewf/ -f -A && makegreen "Sucessfully umounted previous E01"
      # Try mounting E01 to /tmp/ewf
      echo "" 
      makered "EXECUTING EWFMOUNT COMMAND....."
      # Mount image to $mount_dir
      makegreen "ewfmount "${ipath}" /tmp/ewf" 
      ewfmount "${ipath}" /tmp/ewf   && makegreen "Success!" || exit
}

#Mount vmdk, vdi and qcows2 Image types as a network block device
function mount_nbd(){
     makered "CURRENT MOUNT STATUS: "
     echo $nbd_stat
     echo $mount_stat
     [ -d "/dev/nbd1" ] && qemu-nbd -d /dev/nbd1 2>/dev/null && \
     rmmod nbd 2>/dev/null && echo "Warning: unloading and reloading nbd"
     modprobe nbd && echo "modprobe nbd"
     qemu-nbd -r -c /dev/nbd1 "${ipath}" && ls /dev/nbd1  && makegreen "Success!"
     image_src="/dev/nbd1"   
}

#Mount raw split images using affuse
function mount_aff(){
     [ "$(ls -A /tmp/aff/)" ] && fusermount -uz /tmp/aff/ 
     [ "$(ls -A /tmp/aff/)" ] && echo "AFF mount point in use, try manual unmount or reboot" && exit
     affuse "${ipath}" /tmp/aff && image_src=$(find /tmp/aff/ -type f) 
}


# Issue Mount command based on image type and prefs
 function mount_image(){
      echo ""
      makered "EXECUTING MOUNT COMMAND....."
      # Mount image to $mount_dir
      makegreen "mount -t $fstype -o ro,loop$ntfs_support$offset $image_src $mount_dir" 
      mount -t $fstype -o ro,loop$ntfs_support$offset "$image_src" $mount_dir
      echo ""
      [ "$(ls -A $mount_dir)" ] && \
      echo "$ipath Mounted at: $mount_dir"
      echo ""
      ls $mount_dir
      echo ""
      [ "$(ls -A $mount_dir)" ] && \
      makegreen "Success!" || makered "Mount Failed! Try reboot or mount -o "norecovery""
      echo ""
      [ "$(ls -A $mount_dir)" ] &&  [ -e /tmp/ewf/ewf1 ]
}

#Identify and choose whether to mount any vss volumes
function mount_vss(){
      vss_dir="/tmp/vss"
      shadow_dir="/tmp/shadow"
      vss_info=$(vshadowinfo $image_src 2>/dev/null |grep "Number of stores:") 
      [ "${vss_info}" != "" ] && echo "VSCs found! "$vss_info && \
      echo "Mount Volume Shadow Copies?" && yes-no && vsc="yes"
      [ "${offset}" == "yes" ] && offset="-o $offset "  
      [ "${vsc}" == "yes" ] && vshadowmount $image_src $offset$vss_dir && \
      ls $vss_dir && \
      [ "$(ls -A /tmp/vss)" ] && \
      ls /tmp/vss|while read vsc;
      do 
         [ -d "$shadow_dir" ]  || mkdir -p /tmp/shadow/$vsc
        mount -t ntfs -o ro,loop,show_sys_files,streams_interface=windows /tmp/vss/$vsc /tmp/shadow/$vsc
      done  
}

############################################
######### UNMOUNT IMAGES ###################
############################################
function umount_all(){
      [ "$(ls -A /tmp/ermount)" ] && umount /tmp/ermount -f -A
      [ "$(ls -A /tmp/ewf/)" ] && umount /tmp/ewf/ -f -A 
      qemu-nbd -d /dev/nbd1 2>/dev/null
      rmmod nbd 2>/dev/null && echo "Warning: unloading Network Block Device"
      [ "$(ls -A /tmp/aff)" ] && fusermount -uz /tmp/aff/ 2>/dev/null
      umount_vss 
      mount_status
}

#Identify and umount any previously mounted vss volumes
function umount_vss(){
      vss_dir="/tmp/vss"
      #umount any existing mounts
      ls $vss_dir 2>/dev/null|while read vsc;
      do 
        umount /tmp/shadow/$vsc
        echo $vsc
      done 
      [ "$(ls -A $vss_dir)" ] && umount $vss_dir
}


clear
#check root and software package requirements 
[ `whoami` != 'root' ] && makered "Requires Root Access!" && sleep 1 && exit
[ 'which qemu-nbd' == "" ] && makered "qemu-utils not installed" && sleep 1 && exit
[ 'which ewfmount' == "" ] && makered "ewf-tools not installed" && sleep 1 && exit
[ 'which affuse' == "" ] && makered "afflib-tools not installed" && sleep 1 && exit
mkdir -p /tmp/ewf 2>/dev/null  
mkdir -p /tmp/aff 2>/dev/null
mkdir -p /tmp/vss 2>/dev/null     
[ "${1}" == "-u" ] && mount_status && mount_dir="/tmp/ermount" && umount_all
[ "${1}" == "-u" ] && echo $mount_stat && echo $ewf_stat && echo $aff_stat && echo $nbd_stat && echo $vss_stat && echo $vsc_stat && exit
makegreen "Mount a disk image or Virtual Machine disk"
mount_status
image_source
mount_point


[ -f $image_name"002" ] &&  echo $multi "Multiple raw disk segments detected, mounting with affuse" && mount_aff
echo $image_type | grep -e "E01$" && echo $multi "EWF detected, mount with ewfmount" && mount_e01
echo $image_type | grep -e "VMDK$\|VDI$\|QCOW2$\VMDK$\|VMDKX" && mount_nbd
[ "$image_src" == "" ] && image_src="${ipath}"

file $multi
echo $image_src
set_image_offset
mount_image
[ "$fstype" == "ntfs" ] && mount_vss 

