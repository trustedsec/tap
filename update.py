#
# quick updater for TAP
#
import sys
import os

# if the path doesn't exist - need to install it
if not os.path.isdir("/usr/share/tap"):
    print("[!] TAP is not installed. Please run setup.py to install it first.")
    sys.exit()
else:
    sys.path.append("/usr/share/tap/")
    os.chdir("/usr/share/tap")
    if not os.path.isfile("config"):
        print("[!] TAP was not installed properly, missing config file. Run setup.py again.")
        sys.exit()

from src.core.tapcore import *
# tardis update
tap_update()
