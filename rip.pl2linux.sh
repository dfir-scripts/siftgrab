#!/bin/bash
# Changes rip.pl 20180406, so it can run on SANS Sift
# and non-windows platforms
# https://github.com/keydet89/RegRipper2.8  
#   
# md5,file,version,desc
# de43148d13dc8591424e6c29bdb9b3ba,rip.pl,20180406 source
# 94cc02fd32a9b1810d397a7560c8cca7,rip.pl,20130801 Current Sift Linux Version
#
#sift version v2018.028.0
#md5,                               path  
#94cc02fd32a9b1810d397a7560c8cca7  /usr/local/bin/rip.pl
#de43148d13dc8591424e6c29bdb9b3ba  /usr/local/src/regripper/rip.pl
#94cc02fd32a9b1810d397a7560c8cca7  /usr/share/regripper/rip.pl
#94cc02fd32a9b1810d397a7560c8cca7  /var/cache/sift/cli/v2018.28.0/sift-saltstack-2018.28
#
#make a copy from source (edit path as needed)
md5sum /usr/local/src/regripper/rip.pl 2>/dev/null| grep de43148d13dc8591424e6c29bdb9b3ba || echo "Edit this file to manually set source file and plugin path"

# copy new version of rip.pl (20180406) from src to a temp file
cp /usr/local/src/regripper/rip.pl rip.new

# Replash hash bang
sed -i '/^#! c:[\]perl[\]bin[\]perl.exe/d' rip.new
 
sed -i "1i #!`which perl`" rip.new
# set plugin path 
# (edit manually or change section "'/usr/share/regripper/plugins/'" as needed)
sed -i "s|^my\ \$plugindir.*|my\ \$plugindir \= '/usr/share/regripper/plugins/';|" rip.new
[ -e rip.new ] && echo "rip.new created!" && md5sum rip.new
