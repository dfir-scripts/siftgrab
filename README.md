# siftgrab
<li><b>Siftgrab.sh</b> is a Triage Tool for Windows Forensic Images using SANS Sift</li>
A single script (siftgrab.sh) to mount images, collect and extract image artifacts.<br>  
Process single or multiple computer excerpts into a single csv and TLN timeline<br>
Copy Siftgrab.sh copy the files to usr/local/bin and make the following updates to SANS Sift:<br><br>
Tested on SANS Sift 3.0 v2018.28.0 (Ubuntu 16.04) and SANS Sift 3.0 (Ubuntu 14.04)<br> 
<li><b>INSTALLATION:</b><br>
<b>Download Siftgrab and copy to /usr/local/bin</b><br>
    "git clone https://github.com/siftgrab/siftgrab.git"<br>
    "chmod +x siftgrab/*.sh <br>
    "cp siftgrab/* /usr/local/bin/" <br><br>
<b>Install Sqlite (required for chrome, firefox and skype history)</b><br>
    "sudo apt-get install sqlite3"<br><br>
<b>Update Regripper: (Regripper has lots of new plugins and capabilities)</b><br>
    "git clone https://github.com/keydet89/RegRipper2.8.git"<br>
    "sudo cp RegRipper2.8/shellitems.pl /usr/local/bin/shellitems.pl"<br>
    "sudo cp RegRipper2.8/plugins/* /usr/local/src/regripper/plugins"<br><br>
<b>Patch the latest version of rip.pl so it will work in Sift:  </b><br>
    "siftgrab/rip.pl2linux.sh" (creates an updated rip.pl called rip.new)<br> 
    "sudo cp rip.new /usr/local/bin/rip.pl"<br>
    "sudo cp rip.new /usr/share/regripper/rip.pl"<br><br>
<b>Download https://gitub.com/HarmJ0y/pylnker/pylnker.py and copy to /usr/local/bin:  (lnk file extraction)</b><br>
    "wget https://github.com/HarmJ0y/pylnker/blob/master/pylnker.py"<br>
    "chmod +x pylnker.py"<br>
    "sudo cp pylnker.py /usr/local/bin/pylnker.py"<br><br>
<b>Download http://github.com/bromiley/tools/tree/master/win10_prefetch/w10pf_parse.py and copy to /usr/local/bin:  (Windows 8+ prefetch parser)</b><br>
    "wget http://github.com/bromiley/tools/tree/master/win10_prefetch/w10pf_parse.py"<br>
    "chmod +x w10pf_parse.py"<br>
    "sudo cp w10pf_parse.py /usr/local/bin/w10pf_parse.py"<br><br>
<b>Recommended: Install Sushi to use space bar preview</b><br>
    "sudo apt-get install gnome-sushi"<br><br><br>
<li><b>MOUNTING:</li></b>
    Selection 1 from siftrgrab menu or use ermount.sh from the command line<br>
<li><b>ACQUISITION:</li></b>
After mounting image, choose menu item 2, 3, 4 and or 5 as needed<br>
Or use filegrab.sh from Sift or a Live Boot USB/DVD to acquire files<br> 
<li><b>PROCESSING:</li></b>
Single or multiple cases procesessing produces timelines and other extracted registry information<br>
Location of data to process does not have to folllow Windows heirarchy<br>
To maintain identity when processing multiple cases, place evidence items in separate <br>
directories with parent folder named "cases"<br><br> 

<li><b>Sample directory structure needed to process multiple Windows computers:</li><br></b>
                 
             /mnt/hgfs/F/cases/Server1
             /mnt/hgfs/F/cases/CONTROLLER
             /mnt/hgfs/F/cases/myLabtop
             /mnt/hgfs/F/cases/DESKTOP-Q4652
