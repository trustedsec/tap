#!/usr/bin/python
#
# quick script for installing tap
#
##
import subprocess,re,os,shutil,sys
import base64
from src.core.tapcore import ssh_keygen
from src.core.tapcore import motd
from src.core.tapcore import set_background
import pexpect
import getpass

def kill_tap():
    proc = subprocess.Popen("ps -au | grep tap", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    for line in proc.stdout:
        try:
            match = re.search("tap.py", line)
            if match:
                print "[*] Killing running version of TAP.."
                line = line.split(" ")
                pid = line[6]
                subprocess.Popen("kill %s" % (pid), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                print "[*] Killed the TAP process: " + pid

        except: pass

        try:
            # kill the heartbeat health check
            match = re.search("heartbeat.py", line)
            if match:
                print "[*] Killing running version of TAP HEARTBEAT.."
                line = line.split(" ")
                pid = line[6]
                subprocess.Popen("kill %s" % (pid), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True).wait()
                print "[*] Killed the Heartbeat TAP process: " + pid
        except: pass

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
    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    secret = os.urandom(BLOCK_SIZE)
    cipher = AES.new(secret)
    secret = base64.b64encode(secret)
    aes = EncodeAES(cipher, data)
    return str(aes) + "::::" + secret

print (r"""
                                                                      
TTTTTTTTTTTTTTTTTTTTTTT         AAA               PPPPPPPPPPPPPPPPP   
T:::::::::::::::::::::T        A:::A              P::::::::::::::::P  
T:::::::::::::::::::::T       A:::::A             P::::::PPPPPP:::::P 
T:::::TT:::::::TT:::::T      A:::::::A            PP:::::P     P:::::P
TTTTTT  T:::::T  TTTTTT     A:::::::::A             P::::P     P:::::P
        T:::::T            A:::::A:::::A            P::::P     P:::::P
        T:::::T           A:::::A A:::::A           P::::PPPPPP:::::P 
        T:::::T          A:::::A   A:::::A          P:::::::::::::PP  
        T:::::T         A:::::A     A:::::A         P::::PPPPPPPPP    
        T:::::T        A:::::AAAAAAAAA:::::A        P::::P            
        T:::::T       A:::::::::::::::::::::A       P::::P            
        T:::::T      A:::::AAAAAAAAAAAAA:::::A      P::::P            
      TT:::::::TT   A:::::A             A:::::A   PP::::::PP          
      T:::::::::T  A:::::A               A:::::A  P::::::::P          
      T:::::::::T A:::::A                 A:::::A P::::::::P          
      TTTTTTTTTTTAAAAAAA                   AAAAAAAPPPPPPPPPP          
                                                                    
		The TrustedSec Attack Platform
	    Written by: Dave Kennedy (@HackingDave)

		https://github.com/trustedsec/tap

       The self contained-deployable penetration testing kit
""")

print """ 
Welcome to the TAP installer. TAP is a remote connection setup tool that will install a remote
pentest platform for you and automatically reverse SSH out back to home.
 """

if os.path.isfile("/etc/init.d/tap"):
	answer = raw_input("TAP detected. Do you want to uninstall [y/n:] ")
	if answer.lower() == "yes" or answer.lower() == "y":
		answer = "uninstall"

if not os.path.isfile("/etc/init.d/tap"):
	answer = raw_input("Do you want to start the installation of TAP: [y/n]: ")

# if they said yes
if answer.lower() == "y" or answer.lower() == "yes":
                print "[*] Checking to see if TAP is currently running..."

                # kill running processes
                kill_tap()

                print "[*] Beginning installation. This should only take a moment."
                # if directories aren't there then create them
                if not os.path.isdir("/usr/share/tap"):
                        os.makedirs("/usr/share/tap")

                
                # install to rc.local
                print "[*] Adding TAP into startup through init scripts.."
                if os.path.isdir("/etc/init.d"):
                                # remove old startup
                                if os.path.isfile("/etc/init.d/tap"): os.remove("/etc/init.d/tap")

                                # startup script here
                                fileopen = file("src/core/startup_tap", "r")
                                config = fileopen.read()
                                filewrite = file("/etc/init.d/tap", "w")
                                filewrite.write(config)
                                filewrite.close()
                                print "[*] Triggering update-rc.d on TAP to automatic start..."
                                subprocess.Popen("chmod +x /etc/init.d/tap", shell=True).wait()
                                subprocess.Popen("update-rc.d tap defaults", shell=True).wait()

		# setting background
		print "[*] Setting background.."
		set_background()
                
		# install git and update everything
		print "[*] Updating everything beforehand..."
		subprocess.Popen("apt-get update && apt-get --force-yes -y upgrade && apt-get --force-yes -y dist-upgrade", shell=True).wait()
		subprocess.Popen("apt-get --force-yes -y install git python-crypto", shell=True).wait()
                choice = raw_input("Do you want to keep TAP updated? (requires internet) [y/n]: ")
                if choice == "y" or choice == "yes":
                        print "[*] Checking out latest TAP to /usr/share/tap"
                        # if old files are there
                        if os.path.isdir("/usr/share/tap/"):
                                shutil.rmtree('/usr/share/tap')
                        if not os.path.isdir("/usr/share/tap"):
                            os.makedirs("/usr/share/tap")
			subprocess.Popen("cd /usr/share/;git clone https://github.com/trustedsec/tap tap/", shell=True).wait()
                        print "[*] Finished. If you want to update tap go to /usr/share/tap and type 'git pull'"
                        AUTO_UPDATE="ON"
                else:
                        print "[*] Copying setup files over..."
                        AUTO_UPDATE="OFF"
                        if os.path.isdir("/usr/share/tap/"):
                            shutil.rmtree('/usr/share/tap')
                        if not os.path.isdir("/usr/share/tap"):
                            os.makedirs("/usr/share/tap")
                        subprocess.Popen("cp -rf * /usr/share/tap/", shell=True).wait()
       
                hostname = raw_input("Do you want TAP to set this machines hostname for you - yes or no [y]: ")
                if hostname == "y" or hostname == "yes":
                    hostname = raw_input("Enter the name of the hostname for this machine: ")
                    # modify /etc/hostname to specify hostname
                    filewrite = file("/etc/hostname", "w")
                    filewrite.write(hostname)
                    filewrite.close()
                    # set the hostname
                    subprocess.Popen("hostname %s" % (hostname), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
                    print "[*] Done! Hostname is set.. Restarting network settings real quick to take effect.."
                    subprocess.Popen("service networking restart", shell=True).wait()


                print "[*] Next we need to configure the remote SSH server you will want to tunnel over."
                print "[*] This is the main remote SSH server you have running on the Internet that TAP will call back to."
                print "\nWe need to figure out which method you want to use. The first method will use SSH keys\nfor authentication (preferred). This will generate a pub/priv key pair on your machine\nand automatically upload the key to the remote server. When that happens, a password\nwill not be needed then. The second method will use an actual password for authentication\non the remote server. The password is encrypted with AES but not in a secure format at the\nmoment.\n\n"
                choice1 = raw_input("Choice 1: Use SSH keys, Choice 2: Use password (1,2)[1]: ")
                if choice1 == "1" or choice1 == "":
                    choice1 = "ssh_keys"
                else:
                    choice1 = "password"

                # if we are just using straight passwords
                print "[*] This will ask for a username on the REMOTE system (root not recommended)"
		print "The username and password being requested would be the username and password needed to log into the REMOTE system that you have exposed on the Internet for the reverse SSH connection. For example, the TAP box needs to connect OUTBOUND to a box on the Internet - this would be the username and password for that system. ROOT access is NOT needed. This is a simple SSH tunnel. Recommend restricted account in case this box gets taken and has creds on it. Better preference is to use SSH keys."
                username = raw_input("Enter username for ssh [root]: ")
                if username == "": username = "root"

                # generate ssh_key gen from setcore
                if choice1 == "ssh_keys":
                    print "[*] SSH Key generation was selected, we will begin the process now."
                    password = getpass.getpass("Enter the passphrase for the key: ")
                    ssh_keygen(password)

                else:                
                    password = getpass.getpass("Enter password for %s: " % (username))

                if password != "":
                    print "[*] Encrypting the password now.."
                    password = encryptAES(password) 
                    store = password.split("::::")
                    password = store[0]
                    key = store[1]

                    # if the key directory isnt created, do it real quick
                    if not os.path.isdir("/root/.tap"):
                        os.makedirs("/root/.tap")
                    filewrite = file("/root/.tap/store", "w")
                    filewrite.write(key)
                    filewrite.close()

		print "[!] Warning when specifying hostname - this implies that the remote TAP device will have DNS - otherwise this will fail."
                host = raw_input("Enter the remote IP or hostname for SSH connect (remote external server): ")
                port = raw_input("Enter the PORT to the reverse SSH connect (remote external SSH port)[22]: ")
                if port == "": port = "22"
                print "[*] This next option will be the LOCAL port on the EXTERNAL box you will need to SSH into when TAP calls back. For example, when the SSH connection is sent from the TAP device to the box on the Internet, a local port is created on the remote box, so if you wanted to get into the tap, you would first SSH into the remote box, then ssh username@localhost -p <port you specify below>."
                localport = raw_input("Enter the LOCAL port that will be on the remote SSH box [10003]: ")
                socks = raw_input("Enter the LOCAL port that will be used for the SOCKS HTTP proxy [10004]: ")
                if localport == "": localport = "10003"
                if socks == "": socks = "10004"
		if AUTO_UPDATE == "ON"
			print "[*] The update server is a path to pull NEW versions of the TAP device. Using git isn't recommended if you customize your builds for your TAP devices. By default this will pull from git pull https://github.com/trustedsec/tap - recommended you change this."
			print "[*] For this field - you want to put every command you would run if you aren't using git, for example - wget https://yourcompany.com/tap.tar.gz;tar -zxvf tap.tar.gz"
	                updates = raw_input("Enter the commands for your update server [trustedsec (default)]: ")
	                if updates == "": updates = "git pull"
		else:
			updates = ""
                print """The next option allows you to specify a URL to execute commands.\nThis is used if you mess up and don't have reverse SSH access. Place a file in this location and TAP will execute the commands."""
                commands = raw_input("Enter URL to text file of commands (ex. https://yourwebsite.com/commands.txt): ")
                if commands == "": print "[!] No update server detected, will leave this blank."
                print "[*] Creating the config file."

                # determine if SSH keys are in use 
                if choice1 == "ssh_keys":
                    ssh_keys = "ON"
                    print "[*] We need to upload the public key to the remote server, enter the password for the remote server (once) to upload when prompted."
                    # clearing known hosts
                    if os.path.isfile("/root/.ssh/known_hosts"):
                        print "[!] Removing old known_hosts files.."                    
                        os.remove("/root/.ssh/known_hosts")
                    # pull public key into memory
                    fileopen = file("/root/.ssh/id_rsa.pub", "r")
                    pub = fileopen.read()
                    # spawn pexpect to add key
                    print "[*] Spawning SSH connection and modifying authorized hosts."
                    child = pexpect.spawn("ssh %s@%s -p %s" % (username,host,port))
                    child.expect("Are you sure you want to continue connecting")
                    child.sendline("yes")
                    password_onetime = getpass.getpass("Enter your password for the remote SSH server: ")
                    child.sendline(password_onetime)
                    # here we need to verify that we actually log in with the right password
                    i = child.expect(['Permission denied, please try again.', 'Last login:'])
                    if i == 0:
                        print "[!] ERROR!!!! You typed in the wrong password."
                        password_onetime = getpass.getpass("Lets try this again. Enter your SSH password: ")
                        child.sendline(password_onetime)
                        # second time fat fingering, no dice bro
                        i = child.expect(['Permission denied, please try again.'])
                        if i == 0:
                            print "[!] Sorry boss, still denied. Figure out the password and run setup again."
                            print "[!] Exiting TAP setup..."
                            # exit TAP here
                            sys.exit()
                        # successfully logged in
                        else:
                            print "[*] Successfully logged into the system, good to go from here!"

                    if i == 1:
                        print "[*] Successfully logged into the system, good to go from here!"

                    # next we grab the hostname so we can enter it in the authorized keys for a description
                    fileopen = file("/etc/hostname", "r")
                    hostname = fileopen.read()
                    # add a space
                    child.sendline("echo '' >> ~/.ssh/authorized_keys")
                    # comment code for authorized list
                    child.sendline("echo '# TAP box for hostname: %s' >> ~/.ssh/authorized_keys" % (hostname))
                    # actual ssh key
                    child.sendline("echo '%s' >> ~/.ssh/authorized_keys" % (pub))
                    print "[*] Key for %s added to the external box: %s" % (hostname, host)
                   
                else:
                    ssh_keys ="OFF"

                # do you want to log everything
                print "TAP has the ability to log every command used via SSH. This is useful for customers who want log files of the pentest. All logs are saved in /var/log/messages"
                log_everything = raw_input("Do you want to log everything? yes or no [yes] ")
                if log_everything == "": log_everything = "yes"
                log_everything = log_everything.upper()

                # write out the config file
                filewrite = file("/usr/share/tap/config", "w")
                filewrite.write("# tap config options\n\n")
                filewrite.write("# The username for the ssh connection\nUSERNAME=%s\n# The password for the reverse ssh connection\nPASSWORD=%s\n# The reverse ssh ipaddr or hostname\nIPADDR=%s\n# The port for the reverse connect\nPORT=%s\n" % (username, password,host,port))
                filewrite.write("# SSH check is in seconds\nSSH_CHECK_INTERVAL=60\n")
                filewrite.write("# The local SSH port on the reverse SSH host\nLOCAL_PORT=%s\n" % (localport))
                filewrite.write("# Where to pull updates from\nUPDATE_SERVER=%s\n" % (updates))
                filewrite.write("# URL for command updates - ENSURE THAT THE FIRST LINE OF TEXT FILE HAS: 'EXECUTE COMMANDS' or it will not execute anything!\nCOMMAND_UPDATES=%s\n" % (commands))
                filewrite.write("# SPECIFY IF TAP WILL AUTOMATICALLY UPDATE OR NOT\nAUTO_UPDATE=%s\n" % (AUTO_UPDATE))
                filewrite.write("# SPECIFY IF SSH KEYS ARE IN USE OR NOT\nSSH_KEYS=%s\n" % (ssh_keys))
                filewrite.write("# LOG EVERY COMMAND VIA SSH? YES OR NO - ALL LOGS GO TO /var/log/messages\nLOG_EVERYTHING=%s\n" % (log_everything))
                filewrite.write("# THIS IS USED TO TUNNEL SOCKS HTTP TRAFFIC FOR LINUX UPDATES\nSOCKS_PROXY_PORT=%s\n" % (socks))
                filewrite.close()

                # set the background
                # background()
        
                # update motd
                client = raw_input("What customer are you deploying this to: ")
                motd(client)

                # configuring permissions  
                subprocess.Popen("chmod +x /usr/share/tap/tap.py;chmod +x /usr/share/tap/src/core/heartbeat.py", shell=True).wait()

                # ensure proxychains is installed
                print "[*] Installing proxychains-ng for SOCKS5 proxy support."
		subprocess.Popen("git clone https://github.com/rofl0r/proxychains-ng proxy;cd proxy;./configure && make && make install;cd ..;rm -rf proxy", shell=True).wait()

		# enable root login
		print "[*] Enabling SSH-Server and allow remote root login.. Please ensure and test this ahead of time."
		subprocess.Popen("apt-get --force-yes -y install openssh-server", shell=True).wait()
		data = file("/etc/ssh/sshd_config", "r").read()
		filewrite = file("/etc/ssh/sshd_config", "w")
		data = data.replace("PermitRootLogin without-password", "PermitRootLogin yes")
		filewrite.write(data)
		filewrite.close()
		print "[*] Restarting the SSH service after changes."
		subprocess.Popen("service ssh restart", shell=True).wait()
                print "[*] Installation complete. Edit /usr/share/tap/config in order to config tap to your liking.."
		print "[*] Pulling the PenTesters Framework - when installation finishes go to /pentest/ptf, ./ptf, and install all (use modules/install_update_all"
		if not os.path.isdir("/pentest/"): os.makedirs("/pentest")
		subprocess.Popen("cd /pentest;git clone https://github.com/trustedsec/ptf ptf", shell=True).wait()
        
                # start TAP, yes or no?
                choice = raw_input("Would you like to start TAP now? [y/n]: ")
                if choice == "yes" or choice == "y":
			subprocess.Popen("/etc/init.d/tap start", shell=True).wait()

		print "[*] All finished, now run the following command to install all of your tools: " 
		print "[*] cd /pentest/ptf, ./ptf, use modules/install_update_all"

# uninstall tap
if answer == "uninstall":
		os.remove("/etc/init.d/tap")
		subprocess.Popen("rm -rf /usr/share/tap", shell=True)
		subprocess.Popen("rm -rf /etc/init.d/tap", shell=True)
       		print "[*] Checking to see if tap is currently running..."
        	kill_tap()
		print "[*] TAP has been uninstalled. Manually kill the process if it is still running."

