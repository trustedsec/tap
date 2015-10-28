#!/bin/bash
#
# TAP SSH VPN - this will allow you to VPN your machine into the remote TAP device through a reverse SSH tunnel.
#
# Written by: Geoff Walton from TrustedSec (https://www.trustedsec.com)
#
# Usage: ./ssh-tunnel.sh
#
next_remote_tap() {
TAP=$( ssh $SSH_OPTIONS "ifconfig -a | egrep 'tun[0-9]{1,2}' | sort -r | head -n1 | cut -d':' -f1 | cut -d' ' -f1" )
R=$?
if [ "" == "$TAP" ]; then 
  echo "tun0"
  return $R
fi
TAP=$[ $( echo $TAP | cut -c4- ) + 1 ]
echo "tun$TAP"
return $R
}

next_tap() {
TAP=$( ifconfig -a | egrep 'tun[0-9]{1,2}' | sort -r | head -n1 | cut -d':' -f1 | cut -d' ' -f1)
R=$?
if [ -z "$TAP" ]; then
  echo "tun0"
  return $R
fi
TAP=$[ $( echo $TAP | cut -c4- ) + 1 ]
echo "tun$TAP"
return $R
}

create_tun() {
#if
ip tuntap add mode tun $1
}

remove_tun() {
ip tuntap del mode tun $1
}

remove_remote_tun() {
ssh $SSH_OPTIONS "ip tuntap del mode tun $1"
}

create_remote_tun() {
ssh $SSH_OPTIONS "ip tuntap add mode tun $1"
}

set_ipfwd() {
#turn in ip forward
IP_FWD_STATE=$( cat /proc/sys/net/ipv4/ip_forward )
echo $1 > /proc/sys/net/ipv4/ip_forward  
echo $IP_FWD_STATE
}

set_remote_ipfwd() {
IP_FWD_STATE=$( ssh $SSH_OPTIONS 'cat /proc/sys/net/ipv4/ip_forward' )
ssh $SSH_OPTIONS "echo $1 > /proc/sys/net/ipv4/ip_forward"
echo $IP_FWD_STATE
}

set_remote_ip() {
#if ip remote_ip
ssh $SSH_OPTIONS "ifconfig $1 $2 dstaddr $3"
}

set_ip(){
ifconfig $1 $2 dstaddr $3
}

check_remote_net() {
ssh $SSH_OPTIONS 'iptables -t nat -S POSTROUTING' | grep "\-s $1" > /dev/null
if [ 0 -eq $? ]; then
  echo "[***] Connection aborted: Address already in use: $1"
  exit 2 
fi
} 

check_remote_ip(){
ssh $SSH_OPTIONS "ifconfig | grep 'inet ' | tr -s ' ' | cut -f3 -d' '" | grep "$1" > /dev/null
if [ 0 -eq $? ]; then
  echo "[***] Connection aborted: Tunnel ip already in use: $1"
  exit 2
fi
}

set_remote_nat() {
#source net
GW_IF=$(ssh $SSH_OPTIONS "route | grep default | rev | cut -f1 -d' ' | rev" )
ssh $SSH_OPTIONS "iptables -t nat -I POSTROUTING 1 -s $1 -o $GW_IF -j MASQUERADE"
echo $GW_IF
}

unset_remote_nat() {
ssh $SSH_OPTIONS "iptables -t nat -D POSTROUTING -s $1 -o $2 -j MASQUERADE"
}

set_remote_route() {
#net, dev
ssh $SSH_OPTIONS "ip route add $1 dev $2"
}

set_route() {
ip route add $1 dev $2
}

kill_ssh() {
#lif rif
SSH_PID=$(ps aux | grep "ssh -w$( echo $1 | cut -c4- ):$( echo $2 | cut -c4- )" | tr -s ' ' | head -n1 | cut -f2 -d' ')
if [ -z $SSH_PID ]; then
echo "[***] ssh process not found" >&2
return 1
fi
kill $SSH_PID
}

read_ip() {
#Accept an IP or blank
VALID=1
P=$1
until [ $VALID -eq 0 ]; do
 read -p "$P" IP
 if [ -z "$IP" ]; then 
   return
 fi
 CNT=$( echo $IP | egrep -c '([0-9]{1,3}\.){3}[0-9]{1,3}' )
 if [ $CNT -ne 1 ]; then 
   echo "[**] Entry format incorrect please use the form XXX.XXX.XXX.XXX" >&2
 else
   VALID=4
   for I in $( echo $IP | tr '.' ' ' ); do
     if [ 255 -ge $I ]; then 
       VALID=$[ $VALID - 1 ]
     else
       echo "[**] $I is not valid for an IP octet" >&2
     fi
   done
 fi
done
 echo $IP
}

read_ipmask() {
#Accept an IP or blank
VALID=1
P=$1
until [ $VALID -eq 0 ]; do
 read -p "$P" IPMASK
 if [ -z "$IPMASK" ]; then 
   return
 fi
 CNT=$( echo $IPMASK | egrep -c '([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}' )
 if [ $CNT -ne 1 ]; then 
   echo "[**] Entry format incorrect please use the form XXX.XXX.XXX.XXX/XX" >&2 
 else
   IP=$( echo $IPMASK | cut -d'/' -f1 )
   MASK=$( echo $IPMASK | cut -d'/' -f2)
   VALID=5
   for I in $( echo $IP | tr '.' ' ' ); do
     if [ 255 -ge $I ]; then 
       VALID=$[ $VALID - 1 ]
     else
       echo "[**] $I is not valid for an IP octet" >&2
     fi
   done
   if [ 32 -ge $MASK ]; then
     VALID=$[ $VALID -1 ];
   else
     echo "[**] $MASK should be an integer number of mask bits (0-32)" >&2
   fi
 fi
done
 echo $IPMASK
}

interactive_setup() {
echo "SSH VPN interactive setup, please answer the following questions:"
echo "IP for local side of point-to-point tunnel?"
REPLY=$( read_ip "[192.168.200.1]:" )
if [ -z "$REPLY" ]; then LOCAL_IP="192.168.200.1"; else LOCAL_IP=$REPLY; fi
echo "IP for remote side of point-to-point tunnel?"
REPLY=$( read_ip "[192.168.200.2]:" )
if [ -z "$REPLY" ]; then REMOTE_IP="192.168.200.2"; else REMOTE_IP=$REPLY; fi
echo "Should ip forwarding be enabled on the local host,"
echo "you'll need this to use the VPN from other VMs?"
read -p "[y/N]:"
if [ "$REPLY" == "y" ]; then LOCAL_FWD=0; fi
echo "Should ip forwarding be enabled on the remote host,"
echo "you'll need this to reach host behind that system?"
read -p "[y/N]:"
if [ "$REPLY" == "y" ]; then REMOTE_FWD=0; fi
echo "Should NAT be enabled, most likely needed unless you"
echo "can manipulate routing on the remote network?"
read -p "[y/N]:"
if [ "$REPLY" == "y" ]; then 
USE_NAT=0
  echo "Begin entering networks for reverse route injection on the remote host"
  echo "these should be in CIDR format, usually you just need your local subnet"
  echo "you may not need any if you will only be accessing the VPN network from"
  echo "this host."
  echo "Enter a blank line when done."
  I=0
  IP=$(read_ipmask ':')
  until [ -z "$IP" ]; do
    LOCAL_NET[$I]="$IP"
    I=$[ $I + 1 ]
    IP=$(read_ipmask ':')
  done
fi 
echo "Begin entering remote networks in CIDR format that should route via the"
echo "tunnel. You may need to route these networks to this host on other"
echo "machines."
echo "Enter a blank line when done."
I=0
IP=$(read_ipmask ':')
until [ -z "$IP" ]; do
  REMOTE_NET[$I]="$IP"
  I=$[ $I + 1 ]
  IP=$(read_ipmask ':')
done
echo "The script can wait and then attempt to clean up routes, NATs, interfaces."
echo "If you chose no the script will exit after establishing the tunnel,"
echo "you may need to manually remove one or more interfaces and iptables rules."
echo "Should the script wait and automatically clean up?"
read -p "[Y/n]:"
if [ "$REPLY" == "n" ]; then CLEAN=1; else CLEAN=0; fi
read -p "Options to pass to ssh, ex '-p4444 host.example.com' :"
SSH_OPTIONS="$REPLY"
echo "[*] Interactive configuration completed!"
}

helptext() {
echo 'help text:'
echo '-lip local ppp ip, ex -lip 192.168.16.1'
echo '-rip remote ppp ip, ex -rip 192.168.16.2'
echo '-n nat for net, ex -n 172.16.235.0/24'
echo '-r route net at, ex -r 10.0.0.0/8'
echo '-lf local forward, enable ip forwarding to remote host'
echo '-rf remote forward, enable ip forwarding from remote host'
echo '-c do not exit wait and clean up'
echo "-o ssh quoted host and options options, ex -o 'localhost -p 10003'" 
echo "$SCRIPT_NAME <-lip <xxx.xxx.xxx.xxx>> <-rip <xxx.xxx.xxx.xxx>> <-o <localhost -p 10003>> [-n [xxx.xxx.xxx.xxx/xx[, ...]]] [-r <xxx.xxx.xxx.xxx/xx[, ...]>] [-lf] [-rf] [-c]"
echo " --- OR --- "
echo "$SCRIPT_NAME"
}

if [ "$(id -u)" != "0" ]; then
  echo "You must run this script as root"
  exit 1
fi

#Options parse
SCRIPT_NAME=$0
USE_NAT=1
LOCAL_FWD=1
REMOTE_FWD=1
CLEAN=1
declare -a LOCAL_NET
declare -a REMOTE_NET
declare LOCAL_IP
declare REMOTE_IP
declare SSH_OPTIONS

if [ -n "$1" ]; then
until [ -z "$1" ]; do
  case "$1" in
  '-lip')
  LOCAL_IP=$2
  shift 2
  ;;
  '-rip')
  REMOTE_IP=$2
  shift 2
  ;;
  '-n')
  USE_NAT=0
      if [ -n "$2" ]; then
      IFS=', ' read -a LOCAL_NET <<< $2
    fi
  shift 2
  ;;
  '-r')
  IFS=', ' read -a REMOTE_NET <<< $2
  shift 2
  ;;
  '-lf')
  LOCAL_FWD=0
  shift
  ;;
  '-rf')
  REMOTE_FWD=0
  shift
  ;;
  '-c')
  CLEAN=0
  shift
  ;;
  '-o')
  SSH_OPTIONS=$2
  shift 2
  ;;
  '-h')
  helptext
  exit 0
  ;;
  '--help')
  helptext
  exit 0
  ;;
  *)
    echo "Incorrect option $1 options are"
    helptext
    exit 1
  esac
done
else
#no args so interactive
  interactive_setup
fi

if [ -z "$LOCAL_IP" ]; then
  helptext
  exit 1
fi

if [ -z "$REMOTE_IP" ]; then
 helptext
 exit 1
fi

if [ -z "$SSH_OPTIONS" ]; then
 helptext
 exit 1
fi
#End options parse

#weak (really weak) check to make sure key address are ok to use
check_remote_ip $LOCAL_IP
check_remote_ip $REMOTE_IP
if [ $USE_NAT -eq 0 ]; then
  for I in ${LOCAL_NET[@]}; do
    check_remote_net $I
  done
fi

if [ $LOCAL_FWD -eq 0 ]; then
   echo "[*] Enabling local ip forwarding" 
   LOCAL_FWD_STATE=$( set_ipfwd 1 )
fi
 
if [ $REMOTE_FWD -eq 0 ]; then
   echo "[*] Enabling remote ip forwarding"
   REMOTE_FWD_STATE=$( set_remote_ipfwd 1 )
fi
 
LOCAL_IF=$( next_tap )
echo "[*] Creating tunnel interface $LOCAL_IF"
create_tun $LOCAL_IF

REMOTE_IF=$( next_remote_tap )
echo "[*] Creating tunnel interface on remote $REMOTE_IF"
create_remote_tun $REMOTE_IF

echo "[*] Applying local ip address $LOCAL_IP to $LOCAL_IF"
set_ip $LOCAL_IF $LOCAL_IP $REMOTE_IP

echo "[*] Applying remote ip address $REMOTE_IP to $REMOTE_IF"
set_remote_ip $REMOTE_IF $REMOTE_IP $LOCAL_IP

if [ $USE_NAT -eq 0 ]; then
  echo "[*] Applying NAT'ing rules for $LOCAL_IP"
  REMOTE_GW=$( set_remote_nat $LOCAL_IP )
  for I in ${LOCAL_NET[@]}; do
    echo "[*] Applying NAT'ing and routing rules for $I"
    set_remote_route $I $REMOTE_IF
    set_remote_nat $I > /dev/null
  done			
  echo "[*] remote gateway interface is $REMOTE_GW" 
else
  echo "[**] No NAT requested, hosts on remote network may not have a route back, the adjacent host will have a connected route" >&2
fi 

if [ 0 -eq ${#REMOTE_NET[@]} ]; then
  echo "[**] No remote networks specified only the adjacent host will be reachable" >&2
else
  for I in ${REMOTE_NET[@]}; do
    echo "[*] Adding route for $I on $LOCAL_IF"
    set_route $I $LOCAL_IF
    done
fi

#create the tunnel
ssh -w$( echo $LOCAL_IF | cut -c4- ):$( echo $REMOTE_IF | cut -c4- ) $SSH_OPTIONS -f 'echo .' &

if [ 0 -eq $CLEAN ]; then
  read -p "Press enter to clean up ssh VPN"
  if [ $LOCAL_FWD -eq 0 ]; then
    echo "[*] Restoring ip forward state $LOCAL_FWD_STATE"
    set_ipfwd $LOCAL_FWD_STATE > /dev/null
  fi
  
  if [ $REMOTE_FWD -eq 0 ]; then
     echo "[*] Restoring remote ip forwarding state $REMOTE_FWD_STATE"
     set_remote_ipfwd $REMOTE_FWD_STATE >/dev/null
  fi
  
  if [ $USE_NAT -eq 0 ]; then
    #deleting the interfaces will remove any routes
    echo "[*] Cleaning up remote iptables NAT rule for $LCOAL_IP"
    unset_remote_nat $LOCAL_IP $REMOTE_GW
    for I in ${LOCAL_NET[@]}; do
      echo "[*] Cleaning up remote iptables NAT rule for $I"
      unset_remote_nat $I $REMOTE_GW
    done
  fi
  
  echo "[*] shutting down ssh tunnel"
  kill_ssh $LOCAL_IF $REMOTE_IF
  
  echo "[*] removing remote tunnel if"
  remove_remote_tun $REMOTE_IF
  
  echo "[*] removing local tunnel if"
  remove_tun $LOCAL_IF
fi

echo "[*] All operations complete"   
    
