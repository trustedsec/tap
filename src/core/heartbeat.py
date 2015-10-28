#!/usr/bin/python
#######################################################
# heartbeat actively attempts to ensure TAP 
# continues to run
#######################################################
import subprocess
import time

while 1:

    # check if TAP is running first
    print "[*] Checking to see if TAP is operational..."
    proc = subprocess.Popen("ps -ax | grep tap", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout_value = proc.stdout.read()

    # it's not up!
    if not "/usr/share/tap/tap.py" in stdout_value:
        # first trigger an update
        print "[*] TAP is not operational, attempting to kick it off.."
        subprocess.Popen("cd /usr/share/tap;python update.py", shell=True).wait()

        # kick off tap
        subprocess.Popen("python /usr/share/tap/tap.py &", shell=True).wait()

        print "[*] Checking to ensure it is operational..."
        proc = subprocess.Popen("ps -ax | grep tap", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
        stdout_value = proc.stdout.read()
        if "/usr/share/tap/tap.py" in stdout_value:
            print "[*] TAP is up and running!"

    else:
        print "TAP is operational. Not kicking off a new process."

    # check SSH
    proc = subprocess.Popen("ps -ax | grep ssh", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout_value = proc.stdout.read()
    if not "/sshd" in stdout_value:
        print "[!] SSH service is not started.. Kicking it off."
        # kick off SSH
        subprocess.Popen("service ssh start", shell=True)
        print "[*] SSH should now be operational.."
    
    print "Sleeping for 20 seconds..."
    time.sleep(20)
