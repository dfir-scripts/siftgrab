#!/bin/bash
# Makes changes to Regripper's rip.pl so it will run on SANS Sift and possibly non-windows platforms.  Sets a static plugin path, so it can be changed as needed.

# https://github.com/keydet89/RegRipper2.8
# https://linuxconfig.org/how-to-install-regripper-registry-data-extraction-tool-on-linux  
#
# usage: rip.pl2linux.sh (Make sure original rip.pl in current path)


# Get a cof opy rip.pl from the RegRipper distro
echo "rip.pl-2linux.sh"
[ -e rip.pl ] && echo "rip.pl in current path:" && md5sum rip.pl|| echo "rip.pl not in current path:"  
[ -e rip.pl ] && cp rip.pl rip.pl.linux || exit
# Replace Windows hash bang and set perl lib
sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' rip.pl.linux
sed -i "1i #!`which perl`" rip.pl.linux
sed -i '2i use lib qw(/usr/lib/perl5/);' rip.pl.linux
sed -i 's/\#push/push/' rip.pl.linux
sed -i 's/\#my\ \$plugindir/\my\ \$plugindir/g' rip.pl.linux
sed -i 's/\"plugins\/\"\;/\"\/usr\/share\/regripper\/plugins\/\"\;/' rip.pl.linux
sed -i 's/(\"plugins\")\;/(\"\/usr\/share\/regripper\/plugins\")\;/' rip.pl.linux

[ -e rip.pl.linux ] && echo "rip.pl.linux file created!" && md5sum rip.pl.linux
echo -e "replace original rip.pl with new file rip.pl.linux

Back up and make sure the following files are updated:
/usr/local/bin/shellitems.pl
/usr/local/bin/time.pl
/usr/share/perl5/Parse/Win32Registry/WinNT/File.pm
/usr/share/perl5/Parse/Win32Registry/WinNT/Key.pm
/usr/share/perl5/Parse/Win32Registry/Base.pm"
