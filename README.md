# siftgrab
Siftgrab is a consolidation of open source tools and custom scripts. 
It is a basic DFIR triage tool for examining Windows system disk images in a 
Linux evnironment.  Tested on Ubuntu 20.04, Kali 2022.1, Windows WSL2 and SANS SiFT.  

<li> To install all the dependencies and extra tools, download and run the forensics tools install script:

    wget https://raw.githubusercontent.com/dfir-scripts/installers/main/install-forensic-tools.sh
    sudo chmod 755 install-forensic-tools.sh
    sudo ./install-forensic-tools.sh
    
To access the siftgrab menu simply type:
    
    sudo siftgrab

There are lots of forensic tools including siftgrab, so it is great way to quickly add a lot of forensic
tools to kali,Windows WSL or Ubuntu.
    
Downloaded tools are located in /usr/local/src/.
Some are copied to /usr/local/bin.

    
<li>Installers:  
 forensic-tools-install.sh
 RegRipper30-apt-git-Install.sh
 install-autospy-gui.sh
 get-yara-rules.sh

<li>Forensic tool/Triage
 Sleuthkit/Autopsy
 siftgrab

<li>Disk Mounting, Imaging and Carving
 ftkimager,ermount,ewf-tools,afflib-tools,qemu-utils,libbde-utils,exfat-utils,libvshadow-utils
 xmount,ddrescue,photorec/testdisk,ifuse,afro,apfs-fuse

<li>Parsers  
AnalyzeMFT,MFT_Dump,usnparser.py,Yarp,dfir_ntfs, Regripper 3.0,Tools from WFA 4/e, timeline tools, etc. (Harlan Carvey),
esedbexport,prefetchruncounts.py,lnkinfo,evtx_dump,PyWMIPersistenceFinder.py,CCM_RUA_Finder.py,pff-tools,
jobparser.py,bits_parser.py,Hindsight, Unfurl,Kacos2000/Queries,INDXParse.py,Volatility3,KStrike.py

<li>File Analysis Tools
Didier Stevens Tools,Floss,DEXRAY,iocextract,oletools,pefile,Density Scout

<li>Python Modules (installs python2, python3)
python-registry,python3-libesedb,python-evtx,libscca-python,liblnk-python,libfwsi-python

<li>Misc:
gift/stable repository,clamav,lf,attr,libesedb-utils,liblnk-utils,libevtx-utils,pff-tools,jq,yara,rar,unrar,p7zip-full,p7zip-rar

<li>Yara Rules (fetch using get-yara-rules.sh)
Nextron, ReversingLabs, yararules.com

<li>Directories created
  /mnt/raw 
  /mnt/image_mount
  /mnt/vss
  /mnt/shadow
  /mnt/bde
  /mnt/smb
  /cases
