# The TrustedSec Attack Platform (TAP)

TAP - Remote penetration testing platform builder.
Written by: David Kennedy @HackingDave - from TrustedSec (https://www.trustedsec.com)
Project page: https://github.com/trustedsec/tap
A TrustedSec Project - Copyright 2020
Supported operating systems: Linux (Ubuntu Linux preferred)

TAP is a remote penetration testing platform builder. For folks in the security industry, traveling often times becomes a burden and
adds a ton of cost to the customer. TAP was designed to make the deployment of these boxes super simple and create a self-healing and
stable platform to deploy remote penetration testing platforms. Essentially the concept is simple, you pre-configure a brand new box and
run the TAP setup file. This will install a service on Linux that will be configured the way you want. What it will do is establish
a reverse SSH tunnel back to a machine thats exposed on the Internet for you. From there you can access the box locally from the server
it connects back to. TAP automatically detects when an SSH connection has gone stale and will automatically rebuild it for you. 

It also has a number of other options, for example, in the event you lose SSH, it'll connect out to a text file and execute commands for
you. Also updates itself continiously as well as ensure that you are running the latest packages for Ubuntu Linux (if that is your OS).

#In order to install TAP:

python setup.py - This will install TAP.

In order to uninstall TAP:

python setup.py - This will uninstall TAP.

#Instructions:

When setting up TAP, the questions you may have is the REMOTE ssh server, this would be an external box you have with SSH exposed. This
would be your box you want the TAP machine to connect back to, the machine you have on the Internet waiting for connections. It is
not recommended to use root as this is a security oversight. Use a normal user to establish the SSH tunnel. Right now its password only 
although lateron we will be adding support for SSH keys. The password is stored using AES however the cipher key storage is insecure at
the moment. Someone with maintained access to the box could grab the cipher key and decrypt the password in the config with enough time
and persistence. Will fix this in a later release date.

The second is the LOCAL port that will be on the REMOTE box. When TAP connects back via reverse SSH, it connects to the REMOTE box and
establishes a local port on the machine. When you SSH to the remote box on the Internet, you will want to ssh user@localhost -p <LOCAL PORT>.
This will be the port TAP bindes to on the REMOTE system so you can access it. 

Once you configure that, TAP has a default path it pulls updates from, you can change this to your own update path. I intentionally kept
this off github so you can specify what you want for approved updates.

Next, you can send commands to the TAP, it checks every two minutes for new instructions. You need to specify a path, for example:

https://websiteurl/commands.txt

TAP will check that path every two minutes looking for new commands, note that this next part is IMPORTANT. The first line of the text file
MUST contain "EXECUTE COMMAND" (without the double quotes). Once TAP identifies this, it will check to see if the command was executed before
and if not it will execute the commands line by line. This is useful when you lose connection with TAP and need to call execute commands to
fix it.

Once you run setup, it will install the files in /usr/share/tap. It will automatically start if you specify, and will automatically
check for updates such as Debian updates, TAP updates, etc. 

You should also whitelist the update servers if you are using Debian as well as your REMOTE box you connect back to.

Thats it! 

In the event that you decide not to use SSH keys and use passwords, the config stores it in an AES format (requires python-pycrypto). If you need
to update the password, go to the scripts directory which has an update-password script to update the encrypted password and create a new dynamic
cipher key.

Also a neat trick once you are there is a small tool we wrote for basically a SSH VPN. This works out great if you aren't
doing large traffic volumes such as port scans, vulnerability scans, etc. The below is a simple tool that wraps sshuttle to create
the VPN. Just save the below file into a python file and run and use the commands. It'll VPN you in to the remote network where
TAP is deployed. You can do anything such as long as it isn't extremely large volume traffic (pretty stable).


There's two ways to handle a VPN, first is through the method below with SSHuttle. You can also use a transparent VPN that was
created by Geoff Walton at TrustedSec that is located in the under the scripts folder. This will create a TAP interface and
VPN you into the system through SSH. With SSHuttle, things like port scans do not work properly, would highly recommend the
ssh-tunnel script.

# Simple SSHUTTLE script written by Dave Kennedy @HackingDave
import os
import subprocess
import time

if not os.path.isfile("/usr/sbin/sshuttle"):
    print "[!] SSHUTTLE does not appear to be installed, installing now"
    subprocess.Popen("apt-get install sshuttle -f", shell=True).wait()

print "Welcome to the sshuttle wrapper for TAP."
print "Enter the address for the SSH server, i.e. box.sshserver.com"
reverse1 = raw_input("Enter SSH server (REMOTE server): ")
reverse2 = raw_input("Enter the remote SSH port for %s:: " % (reverse1))
reverse3 = raw_input("Enter the port to tunnel for the  local TAP machine (i.e. TAP box localhost port): ")
reverse4 = raw_input("Enter the username to connect to REMOTE system: ")
print "Triggering tunnel now..."
time.sleep(2)
subprocess.Popen("ssh -f %s@%s -L %s:localhost:%s -N" % (reverse4, reverse1, reverse3, reverse2), shell=True).wait()
subprocess.Popen("sshuttle --dns -vr %s@localhost:%s 0/0" % (reverse4,reverse3), shell=True).wait()

# Using Proxy Chains

TAP uses proxychains4 (proxychains-ng) to tunnel all of your http/https traffic through SSH to your remote box. This 
helps with content/egress filtering so you can ensure you always have everything up-to-date. In order to use proxychains, 
just type proxychains4 <command_you_want_to_use> - TAP updates automatically use this.

# Logging

TAP during the setup process will prompt you to see if you want to log all commands executed on the system. If you do, 
all commands that are entered on the system will be logged so that you can provide to the customer or keep records of 
what happened on the devices. All logs are saved under /var/log/messages.

# Supported Operating Systems

Ubuntu 18.04 LTS (should work fine on debian and other ubuntu versions)
