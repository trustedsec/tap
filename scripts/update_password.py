import os,sys
if not os.path.isfile("tap.py"):
    sys.path.append("../")
from src.core.tapcore import *
print """
This will update the encrypted password inside the TARDIS config.

Creates a new cipher key and storage.
"""

password = raw_input("Enter password to update and encrypt: ")
encryptAES(password)
print "[*] Done! Check config to ensure its changed."
