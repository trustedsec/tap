#!/usr/bin/python
#
#
#
# main TAP launcher
#
#
###################################
# first check if we are installed
###################################
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

#############################
# main TAP launch point
#############################
from src.core.tapcore import *
import _thread

# check for SSH VPN config, if not automatically add and restart SSH
ssh_vpn()

# overwrite startup just in case
update_startup()

# check to see if ssh is running first
ssh_start()

# first we need to add bleeding_edge if not there
#bleeding_edge()

# check for command updates
_thread.start_new_thread(execute_command, ())

# run updates in the back
_thread.start_new_thread(update, ())

# the initiate SSH stuff here
while 1:
    try:
        ssh_run()

    except KeyboardInterrupt:
        print("[*] Control-C detected, exiting TAP.")
        break

    except Exception as e:
        print("[!] Could not establish a connection, printing error: ")
        time.sleep(1)
        print(str(e))
        time.sleep(3)
        pass
