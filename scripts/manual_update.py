#!/usr/bin/python
import subprocess
import os
# only run this when you are in the scripts directory 
if os.path.isfile("tap/"): subprocess.Popen("rm -rf tap/", shell=True).wait()
subprocess.Popen("git clone https://github.com/trustedsec/tap;cp -rf tap/* /usr/share/tap/;rm -rf tap/", shell=True).wait()

