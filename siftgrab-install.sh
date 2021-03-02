#! /bin/bash
# Siftgrab and basic IR triage tools download script

#directories created
#  /mnt/raw 
#  /mnt/image_mount
#  /mnt/vss
#  /mnt/shadow
#  /mnt/bde
#  /cases

#Basic Siftgrab Install	
# afflib-tools			# libvshadow-utils 
# AnalyzeMFT			# MFT_Dump
# attr					# net-tools 
# CCM_RUA_Finder.py		# oletools 
# curl					# pefile 
# Cylr					# pff-tools 
# ermount.sh			# prefetchruncounts.py
# ewf-tools				# python2
# exfat-utils			# python3
# fdupes				# python3-evtx 
# feh					# python-registry 
# gddrescue				# PyWMIPersistenceFinder.py
# git					# qemu-utils 
# iocextract			# regex 
# jobparser.py			# RegRipper 3.0
# kacos2000 scripts		# Siftgrab
# Keydet89/Tools		# sleuthkit 
# lf					# sqlite3
# libbde-utils			# usnparser
# libesedb-utils		# vim
# libevtx-utils			# Volatiliy 3 w/ symbol packs
# libfwsi-python		# winservices.py
# liblnk-python			# xmount
# liblnk-utils			# yara
# libscca-python

#
function pause(){
 read -s -n 1 -p "Command failed!!!! Press any key to continue . . ."
 echo ""
}

############### Irit Tools auto install ##########################
#Make Directories
mkdir -p /mnt/{raw,image_mount,vss,shadow,bde} 
mkdir -p /cases
mkdir -p /usr/local/src/{siftgrab,irit,keydet89/tools,kacos2000}

#apt update and install core package install toosls git, python2, curl, pip, pip3 
apt-get update || pause
apt-get upgrade -q -y -u  || pause
apt-get install git curl python2 -y || pause

#Set python3 as python and Install pip and pip3
cp /usr/bin/python3 /usr/local/bin/python
#curl https://bootstrap.pypa.io/get-pip.py --output /tmp/get-pip.py
#pip -V 2>/dev/null|| python2 /tmp/get-pip.py
pip3 -V 2>/dev/null || apt-get install python3-pip -y 
pip3 -V || pause

#pip package install and update
# PIP version 3 = pip3
sift_pip_pkgs="usnparser oletools libscca-python liblnk-python python-registry pefile libfwsi-python python3-evtx regex iocextract"
for pip_pkg in $sift_pip_pkgs;
do
  pip3 install $pip_pkg || pause
done

sift_apt_pkgs="net-tools curl git vim fdupes feh yara gddrescue sleuthkit attr ewf-tools afflib-tools qemu-utils libbde-utils exfat-utils libvshadow-utils xmount libesedb-utils liblnk-utils libevtx-utils pff-tools sleuthkit sqlite3"
for apt_pkg in $sift_apt_pkgs;
do
  sudo apt-get install $apt_pkg -y 
  dpkg -S $apt_pkg || pause
done

#Git and configure Package Installations and Updates

#Git analyzeMFT
[ "$(ls -A /usr/local/src/AnalyzeMFT/)" ] && \
git -C /usr/local/src/irit pull || \
git clone https://github.com/dkovar/analyzeMFT.git /usr/local/src/analyzeMFT
[ "$(ls -A /usr/local/src/analyzeMFT/)" ] || pause
cd /usr/local/src/analyzeMFT/ 
python2 setup.py install || pause

#Git IRIT Files
[ "$(ls -A /usr/local/src/irit/)" ] && \
git -C /usr/local/src/irit pull || \
git clone https://github.com/siftgrab/irit.git /usr/local/src/irit
[ "$(ls -A /usr/local/src/irit/)" ] || pause

#Git and configure Harlan Carvey tools
[ "$(ls -A /usr/local/src/keydet89/tools/)" ] && \
git -C /usr/local/src/keydet89/tools/ pull || \
git clone https://github.com/keydet89/Tools.git /usr/local/src/keydet89/tools/ 
chmod 755 /usr/local/src/keydet89/tools/source/* || pause
#set Windows Perl scripts in Keydet89/Tools/source 
find /usr/local/src/keydet89/tools/source -type f 2>/dev/null|grep pl$ | while read d;
do
  file_name=$( echo "$d"|sed 's/\/$//'|awk -F"/" '{print $(NF)}')
  sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' $d && sed -i "1i #!`which perl`" $d
  cp $d /usr/local/bin/$file_name || pause
done
cp /usr/local/src/keydet89/tools/source/*.pm /usr/share/perl/5.30/ || pause

#Git and configure WMI Forensics
[ "$(ls -A /usr/local/src/WMI_Forensics/)" ] && \
git -C /usr/local/src/WMI_Forensics pull || \
git clone https://github.com/davidpany/WMI_Forensics.git /usr/local/src/WMI_Forensics
chmod 755 /usr/local/src/WMI_Forensics/*.py
cp /usr/local/src/WMI_Forensics/CCM_RUA_Finder.py /usr/local/bin/CCM_RUA_Finder.py || pause
cp /usr/local/src/WMI_Forensics/PyWMIPersistenceFinder.py /usr/local/bin/PyWMIPersistenceFinder.py || pause

#Git Volatility3
[ "$(ls -A /usr/local/src/volatility3/)" ] && \
git -C /usr/local/src/volatility3 pull || \
git clone https://github.com/volatilityfoundation/volatility3.git /usr/local/src/volatility
chmod 755  /usr/local/src/volatility/*.py

#Download Volatility3 Symbol Files
wget -O /usr/local/src/volatility/volatility3/symbols/windows.zip https://downloads.volatilityfoundation.org/volatility3/symbols/windows.zip
wget -O /usr/local/src/volatility/volatility3/symbols/mac.zip https://downloads.volatilityfoundation.org/volatility3/symbols/mac.zip
wget -O /usr/local/src/volatility/volatility3/symbols/linux.zip https://downloads.volatilityfoundation.org/volatility3/symbols/linux.zip

#Git MFT_dump
curl -s https://api.github.com/repos/omerbenamram/mft/releases/latest | \
grep -E 'browser_download_url.*unknown-linux-gnu.tar.gz'|awk -F'"' '{system("wget -P /tmp "$4) }'
tar -xvf /tmp/mft*.gz -C /tmp
chmod 755 /tmp/mft_dump/mft_dump
mv /tmp/mft_dump/mft_dump /usr/local/bin/ || pause 

#Git CyLR
curl -s https://api.github.com/repos/orlikoski/CyLR/releases/latest | \
        grep browser_download_url |\
        grep CyLR_ |\
        cut -d '"' -f 4| while read d; 
        do 
          wget -P /usr/local/src/CyLR/ $d;
        done
[ "$(ls -A /usr/local/src/CyLR/)" ] || pause

#Git MFT_dump
curl -s https://api.github.com/repos/omerbenamram/mft/releases/latest| \
grep -E 'browser_download_url.*unknown-linux-gnu.tar.gz'|awk -F'"' '{system("wget -P /tmp "$4) }' && \
tar -xvf /tmp/mft*.gz -C /tmp && \
chmod 755 /tmp/mft_dump/mft_dump && \
mv /tmp/mft_dump/mft_dump /usr/local/bin/ || pause

#Git kacos200 Scripts
[ "$(ls -A /usr/local/src/kacos2000/Queries)" ] && \
git -C /usr/local/src/kacos2000/Queries pull|| \
git clone https://github.com/kacos2000/Queries.git /usr/local/src/kacos2000/Queries

[ "$(ls -A /usr/local/src/kacos2000/WindowsTimeline)" ] && \
git -C /usr/local/src/kacos2000/WindowsTimeline pull|| \
git clone https://github.com/kacos2000/WindowsTimeline.git /usr/local/src/kacos2000/WindowsTimeline

#wget
# Get IRIT Tools
wget -O /usr/local/src/siftgrab/ermount.sh https://raw.githubusercontent.com/siftgrab/EverReady-Disk-Mount/master/ermount.sh || pause 
wget -O /usr/local/src/siftgrab/prefetchruncounts.py https://raw.githubusercontent.com/siftgrab/prefetchruncounts/master/prefetchruncounts.py || pause 
wget -O /usr/local/src/siftgrab/winservices.py https://raw.githubusercontent.com/siftgrab/Python-Registry-Extraction/master/winservices.py || pause 
wget -O /usr/local/src/siftgrab/RegRipper30-apt-git-Install.sh https://raw.githubusercontent.com/siftgrab/siftgrab/master/regripper.conf/RegRipper30-apt-git-Install.sh  || pause
wget -O /usr/local/src/siftgrab/parse_evtx_tasks.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_tasks.py || pause
wget -O /usr/local/src/siftgrab/parse_evtx_logins.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_logins.py || pause
wget -O /usr/local/src/siftgrab/parse_evtx_accounts.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_accounts.py || pause
wget -O /usr/local/src/siftgrab/parse_evtx_processes.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_processes.py || pause
wget -O /usr/local/src/siftgrab/parse_evtx_BITS.py  https://raw.githubusercontent.com/siftgrab/WindowsEventLogs/master/parse_evtx_BITS.py || pause
chmod -R 755 /usr/local/src/irit/*  || pause 
chmod -R 755 /usr/local/src/siftgrab/*  || pause 
cp /usr/local/src/irit/siftgrab.sh /usr/local/bin/siftgrab
cp /usr/local/src/siftgrab/ermount.sh /usr/local/bin/ermount
cp /usr/local/src/siftgrab/*.py /usr/local/bin/

#Get lf File Browser
wget https://github.com/gokcehan/lf/releases/download/r17/lf-linux-amd64.tar.gz -O - | tar -xzvf - -C /tmp
sudo cp  /tmp/lf /usr/local/bin/

#install RegRipper.git and configure RegRipper
/usr/local/src/siftgrab/RegRipper30-apt-git-Install.sh
 
# Get Job Parser
wget -O /tmp/jobparser.py https://raw.githubusercontent.com/gleeda/misc-scripts/master/misc_python/jobparser.py || pause
mv /tmp/jobparser.py /usr/local/bin/

#Symbolic links
[ -d "/opt/share" ] || ln -s /usr/local/src/ /opt/share

history -c
