#!/usr/bin/python
###############################
#
# main functions for TAP
#
##############################
import re
import sys
import subprocess
import time
import os
import pexpect
from Crypto.Cipher import AES
import base64
import urllib2
import hashlib
import platform
import urllib2

# here we encrypt via aes, will return encrypted string based on secret key which is random
def encryptAES(data):

    # the character used for padding--with a block cipher such as AES, the value
    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    # used to ensure that your value is always a multiple of BLOCK_SIZE
    PADDING = '{'

    BLOCK_SIZE = 32

    # one-liner to sufficiently pad the text to be encrypted
    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING

    # random value here to randomize builds
    a = 50 * 5

    # one-liners to encrypt/encode and decrypt/decode a string
    # encrypt with AES, encode with base64
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))

    secret = os.urandom(BLOCK_SIZE)
    cipher = AES.new(secret)

    aes = EncodeAES(cipher, data)
    fileopen = file("/usr/share/tap/config", "r")
    config = ""
    for line in fileopen:
        line = line.rstrip()
        if "PASSWORD" in line:
            line = "PASSWORD=" + str(aes)

        config = config + line + "\n"
    secret = base64.b64encode(secret)
    filewrite = file("/root/.tap/store", "w")
    filewrite.write(secret)
    filewrite.close()
    filewrite = file("/usr/share/tap/config", "w")
    filewrite.write(config)
    filewrite.close()    
    subprocess.Popen("/etc/init.d/ssh restart", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

# here we encrypt via aes, will return encrypted string based on secret key which is random
def decryptAES(data):
    
    if os.path.isfile("/root/.tap/store"):

    	    # the character used for padding--with a block cipher such as AES, the value
    	    # you encrypt must be a multiple of BLOCK_SIZE in length.  This character is
    	    # used to ensure that your value is always a multiple of BLOCK_SIZE
            PADDING = '{'
	
	    BLOCK_SIZE = 32
	
	    # one-liner to sufficiently pad the text to be encrypted
	    pad = lambda s: s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * PADDING
	
	    # random value here to randomize builds
	    a = 50 * 5
	
	    # one-liners to encrypt/encode and decrypt/decode a string
	    # encrypt with AES, encode with base64
	    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)
	    fileopen = file("/root/.tap/store", "r")
	    key = fileopen.read()
	    secret = base64.b64decode(key)
	    cipher = AES.new(secret)
	    aes = DecodeAES(cipher, data)
	    return str(aes)

    else: return ""

# quick check to see if we are running ubuntu-linux
def check_debian():
    if os.path.isfile("/etc/apt/sources.list"):
	return "Debian"
    else:
        print "[!] Not running a Debian variant.."
        return "Non-Debian"

# check keepalive
def check_keepalive():
    if os.path.isfile("/etc/ssh/ssh_config"):
        fileopen = file("/etc/ssh/ssh_config", "r")
        data = fileopen.read()
        match = re.search("ServerAliveInterval", data)
        if not match:
            print "[*] Adding Keepalive info to /etc/ssh/ssh_config..."
            filewrite = file("/etc/ssh/ssh_config", "a")
            filewrite.write("ServerAliveInterval 15\n")
            filewrite.write("ServerAliveCountMax 4\n")
            filewrite.close()

# def start ssh
def ssh_start():
    # just in case it didn't start
    subprocess.Popen("apt-get install -y openssh-server;update-rc.d -f ssh defaults", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
    subprocess.Popen("/etc/init.d/ssh start", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

# update every 2 hours
def update():

    # check for proxy chains
    socks = check_config("SOCKS_PROXY_PORT=")
    if socks != "":
        while 1:
            proc = subprocess.Popen('netstat -an | egrep "tcp.*:%s.*LISTEN"' % (socks), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout_value = proc.stdout.read()
            if not "127.0.0.1:" in stdout_value:
                # we wait a few seconds, check again.
                time.sleep(20)
            else: break

    # if socks is up, we'll now update and go through this routine
    while 1:
        print "[*] Pulling the latest packages and updating for you automatically."
        # main updates here
        subprocess.Popen("proxychains4 apt-get update;proxychains4 apt-get upgrade -f -y --force-yes;proxychains4 apt-get autoremove -f -y --force-yes", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
        print "[*] Grabbing distribution upgrade..."
        # distribution upgrades
        subprocess.Popen("proxychains4 apt-get update;proxychains4 apt-get dist-upgrade -f -y --force-yes;proxychains4 apt-get autoremove -f -y --force-yes", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
        print "[*] Update complete, checking again in two hours."
        # sleep two hours and try again
        time.sleep(7200)

# check proxychains config
def proxychain():
    socks = check_config("SOCKS_PROXY_PORT=")
    if socks != "":
            if os.path.isfile("/etc/proxychains.conf"):
                os.remove("/etc/proxychains.conf")
            filewrite = file("/etc/proxychains.conf", "w")
            filewrite.write("strict_chain\nproxy_dns\ntcp_read_time_out 15000\ntcp_connect_time_out 8000\n[ProxyList]\n\nsocks5 127.0.0.1 %s" % (socks))
            filewrite.close()

# update tap source code
def tap_update():
    auto_update = check_config("AUTO_UPDATE=")
    if auto_update == "ON":
        print "[*] Updating TAP now with the latest TAP codebase"
        updates = check_config("UPDATE_SERVER=")
        if not os.path.isdir("/usr/share/tap"):
	    subprocess.Popen("git clone https://github.com/trustedsec/tap", shell=True).wait()
	os.chdir("/usr/share/tap")
        subprocess.Popen(updates, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    else:
        print "[*] AUTO_UPDATE is turned to off - not updating. Manually update by downloading: git clone https://github.com/trustedsec/tap"

# grab the normal path for config
def check_config_path():
        path = ""
        # check operating system
        if os.path.isfile("/usr/share/tap/config"):
            path = "/usr/share/tap/config"
        if os.path.isfile("config"):
            path = "config"
        return path

# check config
def check_config(param):
        # grab the default path
        path = check_config_path()
        fileopen = file(path, "r")
        # iterate through lines in file
        counter = 0
        for line in fileopen:
            if not line.startswith("#"):
                match = re.search(param, line)
                if match:
                    line = line.rstrip()
                    line = line.replace('"', "")
                    line = line.split("=", 1)
                    return line[1]
                    counter = 1
        if counter == 0:
            return ""

# ssh run and auto check
def ssh_run():

    # fix permissions just in case
    subprocess.Popen("chmod 400 ~/.ssh/id_rsa;chmod 400 ~/.ssh/id_rsa.pub", shell=True).wait()
    # username for the remote system
    username = check_config("USERNAME=")
    # password for the remote system
    password = check_config("PASSWORD=")
    # decrypt the AES password
    password = decryptAES(password).rstrip()
    # port we connect back to for reverse SSH
    port = check_config("PORT=")
    # host we connect back to for reverse SSH
    host = check_config("IPADDR=")
    # local port on the remote server, one you SSH into
    localport = check_config("LOCAL_PORT=")
    # check if SSH is up and running interval
    interval = check_config("SSH_CHECK_INTERVAL=")
    interval = int(interval)

    # pull config for proxychains and modify
    proxychain()
    ssh_gen = check_config("SSH_KEYS=")
    ssh_commands = ""
    if ssh_gen.lower() == "on":
        ssh_commands = "-i /root/.ssh/id_rsa"
    try:
	    child = pexpect.spawn("ssh-add")
	    i = child.expect(['pass'])

	    # if prompting for password
	    if i == 0:
	        child.sendline(password)
   	        child.close()

    except: pass

    # if we need to generate our keys
    print "[*] Checking for stale SSH tunnels on the same port..."
    proc = subprocess.Popen("netstat -antp | grep ESTABLISHED | grep %s" % (port), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True) 
    stdout_value = proc.communicate()[0]
    stdout_value = stdout_value.split(" ")
    for line in stdout_value:
        if "/ssh" in line:
            print "[!] Stale process identified, killing it before we establish a new tunnel.."
            line = line.replace("/ssh", "")
            subprocess.Popen("kill " + line, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            print "[*] Process has been killed. Moving on to establishing a tunnel.."

    print "[*] Initializing SSH tunnel back to: " + host + " on port: " + port 
    subprocess.Popen("rm /root/.ssh/known_hosts", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()

    # empty placeholder if we are using \passwords or ssh keys
    child = pexpect.spawn("ssh -R 127.0.0.1:%s:127.0.0.1:22 %s@%s -p %s %s" % (localport,username,host,port, ssh_commands))
    i = child.expect(['pass', 'want to continue connecting', 'Could not resolve hostname'])

    # if prompting for password
    if i == 0:
        child.sendline(password)

    # if wanting to accept certificate for new ssh
    if i == 1:
        child.sendline("yes")
        #if ssh_gen.lower() == "off":
	if password != "":
            # added an except here to wait for it so the password doesn't trigger prompting invalid password
            child.expect(['pass'])
            # send the password
            child.sendline(password)

    if i == 2:
        print "[!] Warning, cannot resolve hostname or connect to host."

    # sleep and wait for check, make sure SSH is established
    time.sleep(40)
    while 1:

       # this is for SSH only
        print "[*] Fail-safe SSH is active.. Monitoring SSH connections. - All is well."
        time.sleep(1)
	try:
	        portcheck = pexpect.spawn('ssh -p %s %s %s@%s netstat -an | egrep "tcp.*:%s.*LISTEN"' % (port, ssh_commands, username, host, localport))
	        i = portcheck.expect(['pass', 'want to continue connecting', localport])
	        # if prompting for password
	        if i == 0:
	            portcheck.sendline(password)
	
	        # if wanting to accept certificate for new ssh
	        if i == 1:
	            portcheck.sendline("yes")
	            #if ssh_gen.lower() == "off":
	
	        #if ssh_gen.lower() == "off":
		    if password != "":
	                portcheck.expect("password")
	                portcheck.sendline(password)
	
	        # if we logged in already for some reason - shouldnt hit this
	        if i == 2:
	            # need to re-intiate to pass through   
	            portcheck.sendline("echo alive")
	
	        i = portcheck.expect([localport, "alive"])
	
		if i == 0:
       	        	# keep alive
       	        	portcheck.sendline("echo alive")	

            	# if we already hit here
            	if i == 1:
			pass

        except:
	
            print "\n[*] Reinitializing SSH tunnel - it went down apparently\n"
            subprocess.Popen("rm /root/.ssh/known_hosts", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            child = pexpect.spawn("ssh -R %s:127.0.0.1:22 %s@%s -p %s %s" % (localport,username,host,port, ssh_commands))
            i = child.expect(['pass', 'want to continue connecting', localport])
            if i == 0:
                child.sendline(password)

            if i == 1:
                child.sendline("yes")
                if password != "":
                    child.expect("pass")
                    child.sendline(password)

	    if i == 2:
		child.sendline("echo alive")

            print "[*] Back up and running. Waiting and checking....."

        # initiate socks proxy
        socks = check_config("SOCKS_PROXY_PORT=").rstrip()
        if socks != "":
            proc = subprocess.Popen('netstat -an | egrep "tcp.*:%s.*LISTEN"' % (socks), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            stdout_value = proc.stdout.read()
            if not "127.0.0.1:" in stdout_value:
                print "[*] Establishing socks proxy and tunneling 80/443 traffic"
		try:
                	child1 = pexpect.spawn("ssh -D %s %s@%s -p %s %s" % (socks,username,host,port, ssh_commands))
                	i = child1.expect(['pass', 'want to continue connecting', 'Last login:'])
                	if i == 0:
                    		child1.sendline(password)
                	if i == 1:
                    		child1.sendline("yes")
		    	if password != "":
	                        child1.expect("pass")
	                        child1.sendline(password)

			if i == 2: pass

		except Exception, e:
			print e
			print ("[!] Unable to establish a socks proxy - moving on.")
			pass

        # wait and sleep
        time.sleep(interval)

# This will poll through and look for command updates
# 
# Need to make sure top of line starts with - EXECUTE COMMANDS
def execute_command():
    commands = 0
    while 1:
        try:
            print "[*] Checking for new command updates..."
            url = check_config("COMMAND_UPDATES=")
            if url != "":
                try:
                    req = urllib2.Request(url)
                    html = urllib2.urlopen(req).read()
                    # if we have execute commands in URL
                    if "EXECUTE COMMANDS" in html or "EXECUTE COMMAND":
                        # here we check first to see if we need to execute or we have already
                        commands = 0
                        if os.path.isfile("/tmp/tap.txt"):
                            filewrite = file("/tmp/tap_comp.txt", "w")
                            filewrite.write(html)
                            filewrite.close()
                            # here we do hash comparisons
                            fileopen1 = file("/tmp/tap.txt", "r")
                            # our compare file
                            fileopen2 = file("/tmp/tap_comp.txt", "r")
                            data1 = fileopen1.read()
                            data2 = fileopen2.read()
                            hash = hashlib.sha512()
                            # create hash for first file
                            hash.update(data1)
                            hash1 = hash.hexdigest()
                            hash = hashlib.sha512()
                            # create hash for second file
                            hash.update(data2)
                            hash2 =  hash.hexdigest()
                            # compare if not the same then assign new value
                            if hash1 != hash2: commands = 1

                        # if we have no commands yet or
                        if not os.path.isfile("/tmp/tap.txt") or commands == 1:
                            print "[*] New commands identified, sending instructions to TAP."
                            # write out the new commands
                            filewrite = file("/tmp/tap.txt", "w")
                            filewrite.write(html)
                            filewrite.close()
                            time.sleep(1)
                            fileopen = file("/tmp/tap.txt", "r")
                            for line in fileopen:
                                line = line.rstrip()
                                # don't pull the execute commands line
                                if line != "EXECUTE COMMANDS":
				    if line != "EXECUTE COMMAND":
	                                    subprocess.Popen(line, shell=True).wait()
    
                # passing to keep it from erroring if Internet was down
                except: pass
            
                if commands == 1:
                    print "[*] TAP instruction updates complete. Sleeping for two mintues until next check."
                else:
                    print "[*] No updates needed. Sleeping two minutes before checking again..."
                time.sleep(120)

            if url == "":
                time.sleep(120)

        # except and loop through just in case
        except: pass

# create ssh-keygen stuff for authentication
def ssh_keygen(passphrase):
  
    print "[*] We will first generate our keys to upload to the remote server - also removing any old ones."
    # remove old
    if os.path.isfile("/root/.ssh/id_rsa.pub"):
        print "[*] Removing old SSH keys..."
        os.remove("/root/.ssh/id_rsa.pub")
        os.remove("/root/.ssh/id_rsa")

    # Enter file in which to save the key (/root/.ssh/id_rsa): 
    print "[*] Generating the keypair.."
    passphrase = passphrase.rstrip()
    child = pexpect.spawn("ssh-keygen -t rsa -b 4096")
    child.expect("save the")
    child.sendline("")
    print "[*] Saving the keys in the default location.."
    child.sendline(passphrase)
    child.expect("passphrase")
    child.sendline(passphrase)
    print "[*] Created public/private pair in /root/.ssh/ - will use certificates now."
    child.sendline("ssh-add")
    print "[*] Added SSH keypairs into main system.. Ready to rock."

# quick progress bar downloader
def download_file(url):
    file_name = url.split('/')[-1]
    u = urllib2.urlopen(url)
    f = open(file_name, 'wb')
    meta = u.info()
    file_size = int(meta.getheaders("Content-Length")[0])
    print "Downloading: %s Bytes: %s" % (file_name, file_size)

    file_size_dl = 0
    block_sz = 8192
    while True:
        buffer = u.read(block_sz)
        if not buffer:
            break
        file_size_dl += len(buffer)
        f.write(buffer)
        status = r"%10d  [%3.2f%%]" % (file_size_dl, file_size_dl * 100. / file_size)
        status = status + chr(8)*(len(status)+1)
        print status,
    f.close()

### check platform architecture
def check_os():
    osversion = platform.architecture()[0]
    if osversion == "64bit":
        return "64"
    else:
        return "32"

#
# update the motd
#
def motd(client):
    print ("Updating the MOTD for TAP...")
    data = file("/usr/share/tap/src/motd.txt", "rb").read()
    filewrite = file("/etc/motd", "w")
    filewrite.write(data)
    filewrite.write("\nTAP Customer Name: %s" % (client))
    filewrite.close()
    print ("Finished...")

#
# log everything on system
#
def log_everything():
    # first we check config to make sure its already added (backwards compability)
    log = check_config("LOG_EVERYTHING=")
    # if this wasn't added to our config, we will now add it
    if log == None:
        if os.path.isfile("/usr/share/tap/config"):
            filewrite = file("/usr/share/tap/config", "a")
            # we default to YES
            filewrite.write("# LOG EVERY COMMAND VIA SSH? YES OR NO - ALL LOGS GO TO /var/log/messages\nLOG_EVERYTHING=YES")
            filewrite.close()
        else:
            print "[!] TAP configuration file not found. TAP will not log any commands." 

    # check log again and if we are yes then we'll log everything    
    log = check_config("LOG_EVERYTHING=")
    if log.lower() == "yes":
        # check to see if its already added here
        data = file("/etc/bash.bashrc", "r").read()
        if """PROMPT_COMMAND='history -a >(logger -t "$USER[$PWD] $SSH_CONNECTION")'""" in data:
            # already added
            print "[*] Logger already added and working.. All SSH commands are logging."
        else:
            print "[*] Adding logging capabilities, all results will be logged in /var/log/messages"
            filewrite = file("/etc/bash.bashrc", "a")
            filewrite.write("""PROMPT_COMMAND='history -a >(logger -t "$USER[$PWD] $SSH_CONNECTION")'""")
            filewrite.close()
            print "[*] Now log off this current SSH connection and re-login and you will be all set."        

    # if we are set to no, make sure its been removed properly
    if log.lower() == "no":
        # we need to check if its there first
        fileopen = file("/etc/bash.bashrc", "r")
        data = fileopen.read()
        if """PROMPT_COMMAND='history -a >(logger -t "$USER[$PWD] $SSH_CONNECTION")'""" in data:
            print "[*] Removing logger and turning it off..."
            filewrite = file("/etc/bash.bashrc.bak", "w")
            data = ""
            for line in fileopen:
                line = line.rstrip()
                if not ("""PROMPT_COMMAND='history -a >(logger -t "$USER[$PWD] $SSH_CONNECTION")'""") in line:
                    data = data + line
            filewrite.write(data)
            filewrite.close()
            subprocess.Popen("mv /etc/bash.bashrc.bak /etc/bash.bashrc", shell=True).wait()
            print "[*] Finished removing logging, please exit the SSH connection and log back in to stop logging."

        # if it was already removed
        else:
            print "[*] Logger is turned off, will not log any commands other than normal bash history"


# update the init.d
def update_startup():
    # startup script here
    fileopen = file("/usr/share/tap/src/core/startup_tap", "r")
    config = fileopen.read()
    filewrite = file("/etc/init.d/tap", "w")
    filewrite.write(config)
    filewrite.close()
    print "[*] Triggering update-rc.d on TAP to automatic start..."
    subprocess.Popen("chmod +x /etc/init.d/tap", shell=True).wait()
    subprocess.Popen("update-rc.d tap defaults", shell=True).wait()

# ensure SSH supports VPN tunneling
def ssh_vpn():
    if os.path.isfile("/etc/ssh/sshd_config"):
        print "[*] Checking if SSH point-to-point is enabled in SSH config"
        # first we check to see if point-to-point is enabled, if not we will add it
        data = file("/etc/ssh/sshd_config", "r").read()
        # if it isn't lets add
        if not "PermitTunnel point-to-point" in data:
            print "[-] Adding PermitTunnel point-to-point to the SSH config."
            filewrite = file("/etc/ssh/sshd_config", "a")
            filewrite.write("\nPermitTunnel point-to-point\n")
            filewrite.close()
            print "[*] Done! Use the SSH vpn script under scripts in TAP source to VPN into host."
            print "[!] Restarting SSH real quick, you should still maintain your connection."
            subprocess.Popen("/etc/init.d/ssh restart", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
            print "[*] We are all set and done! Boom shakalaka."


# set the background to tap
def set_background():
	subprocess.Popen("gconftool -t string -s /desktop/gnome/background/picture_filename src/tap.jpg", shell=True).wait()
