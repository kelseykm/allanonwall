#!/bin/bash

###Written by kelseykm

##ALLANONWALL##
# This script creates a flexible iptables firewall for different situations


##To enable the transparent proxy add the following to your torrc:
#	VirtualAddrNetworkIPv4 10.192.0.0/10
#	AutomapHostsOnResolve 1
#	TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
#	DNSPort 5353


#Useful Variables
_interface=(`nmcli device status|grep -w connected|awk '{print $1}'`)
_local_ip=(`for iface in ${interface[@]};do nmcli device show $iface|grep IP4.ADDRESS|awk '{print $2;}'|cut -d\/ -f 1;done`)
_local_host="127.0.0.1/8"
_home="/root/.allanonwall"
_depends=(NetworkManager iptables ip6tables figlet tor python3)
_tor_uid=`id -u debian-tor` #change to `id -u tor` if not using debian-based distro
_trans_port="9040" # Tor's TransPort
_dns_port="5353" # Tor's DNSPort
_ssh_port="22"
_fport="19999" #fakerport's port
_fkr_port="fakerport.py" #fakerport
#_po_port #port_opener port
#_pc_port #port_closer port
#_protocol #port_opener/closer port protocol
_virt_addr="10.192.0.0/10" # Tor's VirtualAddrNetworkIPv4
_non_tor=(127.0.0.0/8 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16) # LAN destinations that shouldn't be routed through Tor
_icmp6_types=(1 128)
_icmp4_types=(3 8)


# Functions

##function coming_soon(){
#	if [[ ${#_interface[@]} -gt 1 ]];then
#		for interface in ${_interface[@]};do
#			case $_interface in
#				pattern ) command ;;
#			esac
#		done
#	else
#		#do stuff
#	fi
#}

function check_uid(){
	id=`id -u`
	if [ $id -ne 0 ];then
		printf "YOU MUST BE ROOT TO RUN THIS SCRIPT\n"
		exit 20
	else
		return
	fi
}

function home_dir(){
	if [[ ! -d $_home ]];then
		mkdir $_home
	fi
}

function check_depends(){
	for app in ${_depends[@]};do
		if ! which $app &>/dev/null;then
			printf "ALLANONWALL REQUIRES $app TO BE ABLE TO RUN EFFECTIVELY. PLEASE INSTALL IT FIRST\n\n"
			exit 21
		fi
	done
}

function activate_firewall(){
	#Check if allanonwall is already running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy DROP)" &>/dev/null;then
		printf "ALLANONWALL IS ALREADY RUNNING\n\n"
		follow_up
	fi

	# Drop ICMP echo-request messages sent to broadcast or multicast addresses
	echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

	# Drop source routed packets
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_source_route

	# Enable TCP SYN cookie protection from SYN floods
	echo 1 > /proc/sys/net/ipv4/tcp_syncookies

	# Don't accept ICMP redirect messages
	echo 0 > /proc/sys/net/ipv4/conf/all/accept_redirects

	# Don't send ICMP redirect messages
	echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects

	# Enable source address spoofing protection
	echo 1 > /proc/sys/net/ipv4/conf/all/rp_filter

	# Log packets with impossible source addresses
	echo 1 > /proc/sys/net/ipv4/conf/all/log_martians

	# Reset filter policies to ACCEPT
	for table in filter nat mangle;do
		if [ $table == nat ];then
			for chain in PREROUTING INPUT OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == filter ];then
			for chain in INPUT FORWARD OUTPUT;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == mangle ];then
			for chain in PREROUTING INPUT FORWARD OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		fi
	done

	#flush rules from all tables
	for table in nat filter mangle;do
		iptables -t $table -F
		ip6tables -t $table -F
	done

	# Allow unlimited traffic on the loopback interface
	iptables -A INPUT -s $_local_host -d $_local_host -i lo -j ACCEPT
	iptables -A OUTPUT -s $_local_host -d $_local_host -o lo -j ACCEPT

	# Set default policies
	for chain in INPUT FORWARD OUTPUT;do
		iptables -t filter --policy $chain DROP
	done

	# Previously initiated and accepted exchanges bypass rule checking
	iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

	#Allow icmp for trouble shooting
	for icmp in ${_icmp4_types[@]};do
		iptables -A INPUT -p icmp -m icmp --icmp-type $icmp -j ACCEPT
	done

	#Drop incoming packets that are not associated with a known connection and are not starting a new connection
	iptables -A INPUT -m state --state INVALID -j LOG --log-level 7 --log-prefix "Dropped INVALID incoming: "
	iptables -A INPUT -m state --state INVALID -j DROP

	#Allow outward traffic
	iptables -A OUTPUT -m state --state NEW,ESTABLISHED -j ACCEPT

	# Log and Drop all other traffic
	iptables -A INPUT -j LOG --log-level 7 --log-prefix "Input packet dropped: "
	iptables -A INPUT -j DROP

	####ipv6 rules

	#Allow unlimited loopback
	ip6tables -A INPUT -s ::1 -d ::1 -i lo -j ACCEPT
	ip6tables -A OUTPUT -s ::1 -d ::1 -o lo -j ACCEPT

	### Set default policies to DROP for IPv6
	for chain in INPUT FORWARD OUTPUT;do
			ip6tables -t filter -P $chain DROP
	done


	#*filter INPUT
	#Allow only established connections to come in
	ip6tables -A INPUT -m state --state ESTABLISHED -j ACCEPT

	#Allow icmp for trouble shooting
	for icmp in ${_icmp6_types[@]};do
		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type $icmp -j ACCEPT
	done

	#Drop outgoing packets that are not associated with a known connection and are not starting a new connection
	ip6tables -A INPUT -m state --state INVALID -j LOG --log-level 7 --log-prefix "Dropped INVALID incoming: "
	ip6tables -A INPUT -m state --state INVALID -j DROP

	# Log and Drop all other traffic
	ip6tables -A INPUT -j LOG --log-level 7 --log-prefix "Input packet dropped: "
	ip6tables -A INPUT -j DROP

	#*filter OUTPUT
	#Allow outward traffic
	ip6tables -A OUTPUT -m state --state NEW,ESTABLISHED -j ACCEPT

	#Make the rules survive reboots
	#for debian users
	netfilter-persistent save &>/dev/null
	#If using arch, Uncomment the lines below and make sure to enable iptables service
	# iptables-save > /etc/iptables/iptables.rules
	# ip6tables-save > /etc/iptables/ip6tables.rule
	#If using rhel, Uncomment the lines below
	# iptables-save > /etc/sysconfig/iptables
	# ip6tables-save > /etc/sysconfig/ip6tables

	# print to the console when script is completed
	printf "ALLANONWALL STARTED\n\n"
	follow_up
}

function deactivate_firewall(){
	#Check if allanonwall is already stopped
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "ALLANONWALL ALREADY DEACTIVATED\n\n"
		follow_up
	fi

	#Kill fakerport if running
	local pid=`lsof -i TCP:$_fport|tail -n1|awk '{print $2}'`
	if ! [ -z $pid ];then
		kill -9 $pid
	fi

	# Reset filter policies to ACCEPT
	for table in filter nat mangle;do
		if [ $table == nat ];then
			for chain in PREROUTING INPUT OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == filter ];then
			for chain in INPUT FORWARD OUTPUT;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == mangle ];then
			for chain in PREROUTING INPUT FORWARD OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		fi
	done

	#flush rules from all tables
	for table in nat filter mangle;do
		iptables -t $table -F
		ip6tables -t $table -F
	done

	#Flush permanent rules
	#netfilter-persistent flush &>/dev/null

	# print to the console after running
	printf "ALLANONWALL DEACTIVATED\n"
	follow_up
}

function port_opener(){
	#Check if allanonwall is running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "PLEASE ACTIVATE ALLANONWALL FIRST\n\n"
		follow_up
	fi

	read -p "PLEASE ENTER PORT YOU WISH TO ALLOW TRAFFIC THROUGH [1-65535] (q to cancel) --> " _po_port

	while true; do
		if  [[ $_po_port == q ]];then
			follow_up
		elif [ -z $_po_port ] || ! [[ $_po_port =~ ^[0-9]{1,5}$ ]] || ! (( $_po_port >= 1 && $_po_port <= 65535 )); then
			printf "\nINVALID ENTRY\n"
			read -p "PLEASE ENTER PORT YOU WISH TO ALLOW TRAFFIC THROUGH [1-65535] (q to cancel) --> " _po_port
		else
			break
		fi
	done

	if [[ $_po_port -eq $_ssh_port ]];then
		printf "PLEASE OPEN PORT 22 THROUGH THE SPECIAL OPTION ON THE MAIN MENU\n"
		follow_up
	elif [[ $_po_port -eq $_fport ]]; then
		printf "PORT $_po_port IS RESERVED FOR FAKERPORT; PLEASE PICK ANOTHER PORT\n"
		follow_up
	fi

	read -p "PLEASE ENTER THE PROTOCOL OF THE PORT (TCP OR UDP) [t/u] (q to cancel) --> " _prot

	while true; do
		if [[ $_prot == q ]];then
			follow_up
		elif [[ -z $_prot ]] || ! [[ $_prot == 't' || $_prot == 'u' ]]; then
			printf "\nINVALID ENTRY\n"
			read -p "PLEASE ENTER THE PROTOCOL OF THE PORT (TCP OR UDP) [t/u] (q to cancel) --> " _prot
		else
			break
		fi
	done

	if [[ $_prot == t ]];then
		_protocol=tcp
	else
		_protocol=udp
	fi

	if ! iptables -C INPUT -p $_protocol -m $_protocol --dport $_po_port -m state --state NEW -j ACCEPT &>/dev/null;then
		iptables -I INPUT 2 -p $_protocol -m $_protocol --dport $_po_port -m state --state NEW -j ACCEPT
	else
		printf "PORT $_po_port IS ALREADY ALLOWED\n"
		follow_up
	fi

	#Check if fakerport is running
	if iptables -C INPUT -p $_protocol -m $_protocol --dport $_fport -m state --state NEW -j ACCEPT &>/dev/null;then
		iptables -t nat -I PREROUTING -p $_protocol -m $_protocol --dport $_po_port -j RETURN
	fi

	printf "${_protocol^^} PORT $_po_port NOW ALLOWED\n"
	follow_up
}

function port_closer(){
	#Check if allanonwall is running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "PLEASE ACTIVATE ALLANONWALL FIRST\n\n"
		follow_up
	fi

	local IFS=$'\n'

	read -p "PLEASE ENTER PORT YOU WISH TO BLOCK [1-65535] (q to cancel) --> " _pc_port

	while true; do
		if [[ $_pc_port == q ]];then
			follow_up
		elif [ -z $_pc_port ] || ! (( $_pc_port >= 1 && $_pc_port <= 65535 )) || ! [[ $_pc_port =~ ^[0-9]+$ ]]; then
			printf "\nINVALID ENTRY\n"
			read -p "PLEASE ENTER PORT YOU WISH TO BLOCK [1-65535] (q to cancel) --> " port
		else
			break
		fi
	done

	if [[ $_pc_port -eq $_ssh_port ]];then
		printf "PLEASE BLOCK PORT 22 THROUGH THE SPECIAL OPTION ON THE MAIN MENU\n"
		follow_up
	fi

	read -p "PLEASE ENTER THE PROTOCOL OF THE PORT (TCP OR UDP) [t/u] (q to cancel) --> " _prot

	while true; do
		if [[ $_prot == q ]];then
			follow_up
		elif [[ -z $_prot ]] || ! [[ $_prot == 't' || $_prot == 'u' ]]; then
			printf "\nINVALID ENTRY\n"
			read -p "PLEASE ENTER THE PROTOCOL OF THE PORT (TCP OR UDP) [t/u] (q to cancel) --> " _prot
		else
			break
		fi
	done

	if [[ $_prot == t ]]; then
		_protocol=tcp
	else
		_protocol=udp
	fi

	if ! iptables -C INPUT -p $_protocol -m $_protocol --dport $_pc_port -m state --state NEW -j ACCEPT &>/dev/null;then
		printf "PORT IS NOT OPEN\n"
		follow_up
	fi

	iptables -nL --line-numbers | grep "dpt:$_pc_port" > $_home/rules

	for line in `cat $_home/rules`;do
		iptables -D INPUT `awk '{ print $1 }' <<< $line`
	done

	#Check if fakerport is running
	if iptables -C INPUT -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT &>/dev/null;then
		iptables -t nat -D PREROUTING -p $_protocol -m $_protocol --dport $_po_port -j RETURN
	fi

	rm $_home/rules
	printf "PORT $_pc_port IS NOW BLOCKED\n"
	follow_up
}

function allow_ssh(){
	#Check if allanonwall is running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "PLEASE ACTIVATE ALLANONWALL FIRST\n\n"
		follow_up
	fi

	#Check if ssh is already allowed
	if ! iptables -C INPUT -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT &>/dev/null;then
		#Check if fakerport is running
		if iptables -C INPUT -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT &>/dev/null;then
			iptables -t nat -I PREROUTING -p tcp -m tcp --dport $_ssh_port -j RETURN
		fi

		#Rate-limit SSH
		iptables -I INPUT 2 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --set
		iptables -I INPUT 3 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --update --seconds 60 --hitcount 4 -j LOG --log-prefix "Dropped incoming SSH: " --log-level 7
		iptables -I INPUT 4 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --update --seconds 60 --hitcount 4 -j DROP
		iptables -I INPUT 5 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j LOG --log-prefix "New SSH connections: " --log-level 7
		iptables -I INPUT 6 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT
	else
		printf "SSH IS ALREADY ALLOWED\n"
		follow_up
	fi

	#Check if transproxy is already running
	if [[ `iptables -t nat -n -L OUTPUT|wc -l` -gt 2 ]];then
		iptables -t nat -I OUTPUT -p tcp -m tcp --sport $_ssh_port -m recent --name SSH --rcheck -j RETURN
	fi

	#Print message when done
	printf "SSH NOW ALLOWED\n"
	follow_up
}

function block_ssh(){
	#Check if allanonwall is running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "PLEASE ACTIVATE ALLANONWALL FIRST\n\n"
		follow_up
	fi

	local IFS=$'\n'

	if ! iptables -C INPUT -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT &>/dev/null;then
		printf "SSH IS ALREADY BLOCKED\n"
		follow_up
	fi

	#Check if fakerport is running
	if iptables -C INPUT -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT &>/dev/null;then
		iptables -t nat -D PREROUTING -p tcp -m tcp --dport $_ssh_port -j RETURN
	fi

	#Check if transproxy is still running
	if [[ `iptables -t nat -n -L OUTPUT|wc -l` -gt 2 ]];then
		iptables -t nat -D OUTPUT -p tcp -m tcp --sport $_ssh_port -m recent --name SSH --rcheck -j RETURN
	fi

	iptables -nL --line-numbers | grep "dpt:$_ssh_port" |sort -r > $_home/rules

	for line in `cat $_home/rules`;do
		iptables -D INPUT `awk '{ print $1 }' <<< $line`
	done

	rm $_home/rules
	printf "SSH NOW BLOCKED\n"
	follow_up
}

function tor_transproxy(){
	#Check if transproxy is already running
	if [[ `iptables -t nat -n -L OUTPUT|wc -l` -gt 2 ]];then
		printf "TOR TRANSPARENT PROXY IS ALREADY RUNNING\n\n"
		follow_up
	fi

	#Check if ssh is already allowed
	if iptables -C INPUT -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT &>/dev/null;then
		local _ssh_allowed=true
	else
		local _ssh_allowed=false
	fi

	#Check for allowed ports
	iptables -nL --line-numbers | grep "dpt" > $_home/rules
	while read rule; do
	  if grep -E 'dpt:[0-9]{1,5}' <<< $rule &>/dev/null; then
	    port=`grep -oE 'dpt:[0-9]{1,5}' <<< $rule | awk -F 'dpt:' '{print $2}'`
	    if ! (( $port == $_ssh_port || $port == $_fport || $port == $_trans_port )); then
	      prot=$(grep -o tcp <<< $rule | head -n 1)
	      if [[ $prot == tcp ]]; then _protocol=tcp; else _protocol=udp; fi
	      echo "$_protocol:$port" >> $_home/allowed_ports
	    fi
	  fi
	done < $_home/rules

	# Reset policies to ACCEPT
	for table in filter nat mangle;do
		if [ $table == nat ];then
			for chain in PREROUTING INPUT OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == filter ];then
			for chain in INPUT FORWARD OUTPUT;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == mangle ];then
			for chain in PREROUTING INPUT FORWARD OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		fi
	done

	#flush rules from all tables
	for table in nat filter mangle;do
		iptables -t $table -F
		ip6tables -t $table -F
	done

	####NAT####
	### *nat OUTPUT (For local redirection)
	# nat .onion addresses
	iptables -t nat -A OUTPUT -d $_virt_addr -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -j REDIRECT --to-ports $_trans_port

	# nat dns requests to Tor
	iptables -t nat -A OUTPUT -p udp -m udp --dport 53 -j REDIRECT --to-ports $_dns_port

	# Don't nat the Tor process, the loopback, or the local network
	iptables -t nat -A OUTPUT -m owner --uid-owner $_tor_uid -j RETURN
	iptables -t nat -A OUTPUT -o lo -j RETURN

	# Allow lan access for hosts in $_non_tor
	for _lan in ${_non_tor[@]}; do
	  iptables -t nat -A OUTPUT -d $_lan -j RETURN
	done

	# Redirect all other output to Tor's TransPort
	iptables -t nat -A OUTPUT -p tcp -m tcp -j REDIRECT --to-ports $_trans_port

	####FILTER####
	### *filter INPUT
	iptables -A INPUT -i lo -j ACCEPT
	iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

	# Allow INPUT from lan hosts in $_non_tor
	for _lan in ${_non_tor[@]}; do
	 iptables -A INPUT -s $_lan -m state --state ESTABLISHED -j ACCEPT
		 #Allow icmp for trouble shooting
	 	for icmp in ${_icmp4_types[@]};do
	 		iptables -A INPUT -s $_lan -p icmp -m icmp --icmp-type $icmp -j ACCEPT
	 	done
	done

	# Log & Drop everything else. Uncomment to enable logging
	iptables -A INPUT -j LOG --log-prefix "Dropped INPUT packet: " --log-level 7
	iptables -A INPUT -j DROP

	### *filter FORWARD
	iptables -A FORWARD -j DROP

	### *filter OUTPUT
	# Allow loopback output
	iptables -A OUTPUT -d 127.0.0.1/32 -o lo -j ACCEPT

	iptables -A OUTPUT -m state --state INVALID -j DROP
	iptables -A OUTPUT -m state --state ESTABLISHED -j ACCEPT

	# Allow Tor process output
	iptables -A OUTPUT -m owner --uid-owner $_tor_uid -p tcp -m tcp --tcp-flags FIN,SYN,RST,ACK SYN -m state --state NEW -j ACCEPT

	# Tor transproxy magic
	iptables -A OUTPUT -d 127.0.0.1/32 -p tcp -m tcp --dport $_trans_port --tcp-flags FIN,SYN,RST,ACK SYN -j ACCEPT

	# Allow OUTPUT to lan hosts in $_non_tor
	for _lan in ${_non_tor[@]}; do
	 iptables -A OUTPUT -d $_lan -m state --state NEW,ESTABLISHED -j ACCEPT
	done

	# Log & Drop everything else. Uncomment to enable logging
	iptables -A OUTPUT -j LOG --log-prefix "Dropped OUTPUT packet: " --log-level 7 --log-uid
	iptables -A OUTPUT -j DROP

	#Check if ssh was allowed
	if $_ssh_allowed;then
		#Rate-limit SSH
		iptables -I INPUT 2 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --set
		iptables -I INPUT 3 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --update --seconds 60 --hitcount 4 -j LOG --log-prefix "Dropped incoming SSH: " --log-level 7
		iptables -I INPUT 4 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --update --seconds 60 --hitcount 4 -j DROP
		iptables -I INPUT 5 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j LOG --log-prefix "New SSH connections: " --log-level 7
		iptables -I INPUT 6 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT
		iptables -t nat -I OUTPUT -p tcp -m tcp --sport $_ssh_port -m recent --name SSH --rcheck -j RETURN
	fi

	#Restore allowed ports
	while read line; do
		_protocol=`cut -d':' -f 1 <<< $line`
		port=`cut -d':' -f 2 <<< $line`
		iptables -I INPUT -p $_protocol -m $_protocol --dport $port -m state --state NEW -j ACCEPT
	done < $_home/allowed_ports
	rm $_home/allowed_ports

	#Restore fakerport if it had been running
	local pid=`lsof -i TCP:$_fport|tail -n1|awk '{print $2}'`
	if ! [ -z $pid ];then
		#Redirect all incoming connections to FAKERPORT
		iptables -t nat -I PREROUTING -p tcp -m tcp --tcp-flags ALL SYN -j REDIRECT --to-ports $_fport
		iptables -I INPUT 2 -p tcp -m tcp --dport $_fport -j LOG --log-level 7 --log-prefix "Redirected to FAKERPORT: "
		iptables -I INPUT 3 -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT

		#Check if ssh is allowed
		if $_ssh_allowed;then
			iptables -t nat -I PREROUTING -p tcp -m tcp --dport $_ssh_port -j RETURN
		fi

		#check if a port is allowed
		iptables -nL --line-numbers | grep "dpt" > $_home/rules

		while read rule; do
		  if grep -E 'dpt:[0-9]{1,5}' <<< $rule &>/dev/null; then
		    port=`grep -oE 'dpt:[0-9]{1,5}' <<< $rule | awk -F 'dpt:' '{print $2}'`
		    if ! (( $port == $_ssh_port || $port == $_fport || $port == $_trans_port )); then
		      prot=`grep -o tcp <<< $rule | head -n 1`
		      if [[ $prot == tcp ]]; then _protocol=tcp; else _protocol=udp; fi
		      iptables -t nat -I PREROUTING -p $_protocol -m $_protocol --dport $port -j RETURN
		    fi
		  fi
		done < $_home/rules
		rm $_home/rules
	fi

	### Set default filter policies to DROP
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT DROP

	### Set default policies to DROP for IPv6
	ip6tables -P INPUT DROP
	ip6tables -P FORWARD DROP
	ip6tables -P OUTPUT DROP

	#Print message when done
	printf "TOR TRANSPARENT PROXY NOW ACTIVE\n"
	follow_up
}

function stop_tor_transproxy(){
	#Check if transproxy is running
	if [[ `iptables -t nat -n -L OUTPUT|wc -l` -eq 2 ]];then
		printf "TOR TRANSPARENT PROXY IS NOT RUNNING\n\n"
		follow_up
	fi

	#Check if ssh is already allowed
	if iptables -C INPUT -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT &>/dev/null;then
		local _ssh_allowed=true
	else
		local _ssh_allowed=false
	fi

	#Check for allowed ports
	iptables -nL --line-numbers | grep "dpt" > $_home/rules
	while read rule; do
	  if grep -E 'dpt:[0-9]{1,5}' <<< $rule &>/dev/null; then
	    port=`grep -oE 'dpt:[0-9]{1,5}' <<< $rule | awk -F 'dpt:' '{print $2}'`
	    if ! (( $port == $_ssh_port || $port == $_fport || $port == $_trans_port )); then
	      prot=$(grep -o tcp <<< $rule | head -n 1)
	      if [[ $prot == tcp ]]; then _protocol=tcp; else _protocol=udp; fi
	      echo "$_protocol:$port" >> $_home/allowed_ports
	    fi
	  fi
	done < $_home/rules

	# Reset filter policies to ACCEPT
	for table in filter nat mangle;do
		if [ $table == nat ];then
			for chain in PREROUTING INPUT OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == filter ];then
			for chain in INPUT FORWARD OUTPUT;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		elif [ $table == mangle ];then
			for chain in PREROUTING INPUT FORWARD OUTPUT POSTROUTING;do
				iptables -t $table -P $chain ACCEPT
				ip6tables -t $table -P $chain ACCEPT
			done
		fi
	done

	#flush rules from all tables
	for table in nat filter mangle;do
		iptables -t $table -F
		ip6tables -t $table -F
	done

	# Allow unlimited traffic on the loopback interface
	iptables -A INPUT -s $_local_host -d $_local_host -i lo -j ACCEPT
	iptables -A OUTPUT -s $_local_host -d $_local_host -o lo -j ACCEPT

	# Set default policies
	for chain in INPUT FORWARD OUTPUT;do
		iptables -t filter --policy $chain DROP
	done

	# Previously initiated and accepted exchanges bypass rule checking
	iptables -A INPUT -m state --state ESTABLISHED -j ACCEPT

	#Allow icmp for trouble shooting
	for icmp in ${_icmp4_types[@]};do
		iptables -A INPUT -p icmp -m icmp --icmp-type $icmp -j ACCEPT
	done

	#Drop incoming packets that are not associated with a known connection and are not starting a new connection
	iptables -A INPUT -m state --state INVALID -j LOG --log-level 7 --log-prefix "Dropped INVALID incoming: "
	iptables -A INPUT -m state --state INVALID -j DROP

	#Allow outward traffic
	iptables -A OUTPUT -m state --state NEW,ESTABLISHED -j ACCEPT

	# Log and Drop all other traffic
	iptables -A INPUT -j LOG --log-level 7 --log-prefix "Input packet dropped: "
	iptables -A INPUT -j DROP

	####ipv6 rules

	#Allow unlimited loopback
	ip6tables -A INPUT -s ::1 -d ::1 -i lo -j ACCEPT
	ip6tables -A OUTPUT -s ::1 -d ::1 -o lo -j ACCEPT

	### Set default policies to DROP for IPv6
	for chain in INPUT FORWARD OUTPUT;do
			ip6tables -t filter -P $chain DROP
	done


	#*filter INPUT
	#Allow only established connections to come in
	ip6tables -A INPUT -m state --state ESTABLISHED -j ACCEPT

	#Allow icmp for trouble shooting
	types=(1 128)
	for icmp in ${types[@]};do
		ip6tables -A INPUT -p ipv6-icmp -m icmp6 --icmpv6-type $icmp -j ACCEPT
	done

	#Drop outgoing packets that are not associated with a known connection and are not starting a new connection
	ip6tables -A INPUT -m state --state INVALID -j LOG --log-level 7 --log-prefix "Dropped INVALID incoming: "
	ip6tables -A INPUT -m state --state INVALID -j DROP

	# Log and Drop all other traffic
	ip6tables -A INPUT -j LOG --log-level 7 --log-prefix "Input packet dropped: "
	ip6tables -A INPUT -j DROP

	#*filter OUTPUT
	#Allow outward traffic
	ip6tables -A OUTPUT -m state --state NEW,ESTABLISHED -j ACCEPT

	#Check if ssh was allowed
	if $_ssh_allowed;then
		#Rate-limit SSH
		iptables -I INPUT 2 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --set
		iptables -I INPUT 3 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --update --seconds 60 --hitcount 4 -j LOG --log-prefix "Dropped incoming SSH: " --log-level 7
		iptables -I INPUT 4 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -m recent --name SSH --update --seconds 60 --hitcount 4 -j DROP
		iptables -I INPUT 5 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j LOG --log-prefix "New SSH connections: " --log-level 7
		iptables -I INPUT 6 -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT
	fi

	#Restore allowed ports
	while read line; do
		_protocol=`cut -d':' -f 1 <<< $line`
		port=`cut -d':' -f 2 <<< $line`
		iptables -I INPUT -p $_protocol -m $_protocol --dport $port -m state --state NEW -j ACCEPT
	done < $_home/allowed_ports
	rm $_home/allowed_ports

	#Restore fakerport if it had been running
	local pid=`lsof -i TCP:$_fport|tail -n1|awk '{print $2}'`
	if ! [ -z $pid ];then
		#Redirect all incoming connections to FAKERPORT
		iptables -t nat -I PREROUTING -p tcp -m tcp --tcp-flags ALL SYN -j REDIRECT --to-ports $_fport
		iptables -I INPUT 2 -p tcp -m tcp --dport $_fport -j LOG --log-level 7 --log-prefix "Redirected to FAKERPORT: "
		iptables -I INPUT 3 -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT

		#Check if ssh is allowed
		if $_ssh_allowed;then
			iptables -t nat -I PREROUTING -p tcp -m tcp --dport $_ssh_port -j RETURN
		fi
		#check if a port is allowed
		iptables -nL --line-numbers | grep "dpt" > $_home/rules

		while read rule; do
		  if grep -E 'dpt:[0-9]{1,5}' <<< $rule &>/dev/null; then
		    port=`grep -oE 'dpt:[0-9]{1,5}' <<< $rule | awk -F 'dpt:' '{print $2}'`
		    if ! (( $port == $_ssh_port || $port == $_fport || $port == $_trans_port )); then
		      prot=`grep -o tcp <<< $rule | head -n 1`
		      if [[ $prot == tcp ]]; then _protocol=tcp; else _protocol=udp; fi
		      iptables -t nat -I PREROUTING -p $_protocol -m $_protocol --dport $port -j RETURN
		    fi
		  fi
		done < $_home/rules
		rm $_home/rules
	fi

	#Print message when done
	printf "TOR TRANSPARENT PROXY DEACTIVATED\n"
	follow_up
}

function start_fakerport(){
	#Check if allanonwall is running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "PLEASE ACTIVATE ALLANONWALL FIRST\n\n"
		follow_up
	fi

	#Check if fakerport is running
	if iptables -C INPUT -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT &>/dev/null;then
		printf "FAKERPORT IS ALREADY RUNNING\n\n"
		follow_up
	fi

	#Check depends
	if ! which $_fkr_port &>/dev/null;then
		printf "ALLANONWALL REQUIRES $_fkr_port TO BE ABLE TO RUN THIS FEATURE EFFECTIVELY. PLEASE ADD IT TO \$PATH.\n\n"
		follow_up
	fi

	#Start fakerport server in the background
	$_fkr_port &>/dev/null &
	if [[ `echo $?` -ne 0 ]];then
		printf "AN ERROR OCCURED WHILE STARTING FAKERPORT\n\n"
		follow_up
	fi

	#Redirect all incoming connections to FAKERPORT
	iptables -t nat -I PREROUTING -p tcp -m tcp --tcp-flags ALL SYN -j REDIRECT --to-ports $_fport
	iptables -I INPUT 2 -p tcp -m tcp --dport $_fport -j LOG --log-level 7 --log-prefix "Redirected to FAKERPORT: "
	iptables -I INPUT 3 -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT

	#Check if ssh is allowed
	if iptables -C INPUT -p tcp -m tcp --dport $_ssh_port -m state --state NEW -j ACCEPT &>/dev/null;then
		iptables -t nat -I PREROUTING -p tcp -m tcp --dport $_ssh_port -j RETURN
	fi

	#check if a port is allowed
	iptables -nL --line-numbers | grep "dpt" > $_home/rules

	while read rule; do
	  if grep -E 'dpt:[0-9]{1,5}' <<< $rule &>/dev/null; then
	    port=`grep -oE 'dpt:[0-9]{1,5}' <<< $rule | awk -F 'dpt:' '{print $2}'`
	    if ! (( $port == $_ssh_port || $port == $_fport || $port == $_trans_port )); then
	      prot=`grep -o tcp <<< $rule | head -n 1`
	      if [[ $prot == tcp ]]; then _protocol=tcp; else _protocol=udp; fi
	      iptables -t nat -I PREROUTING -p $_protocol -m $_protocol --dport $port -j RETURN
	    fi
	  fi
	done < $_home/rules
	rm $_home/rules

	#print message when done
	printf "FAKERPORT ACTIVATED\n"
	follow_up
}

function stop_fakerport(){
	#Check if allanonwall is running
	if iptables -t filter -n -L INPUT|grep -w "Chain INPUT (policy ACCEPT)" &>/dev/null;then
		printf "PLEASE ACTIVATE ALLANONWALL FIRST\n\n"
		follow_up
	fi

	#Check if fakerport is running
	if ! iptables -C INPUT -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT &>/dev/null;then
		printf "FAKERPORT IS NOT RUNNING\n\n"
		follow_up
	fi

	local pid=`lsof -i TCP:$_fport|tail -n1|awk '{print $2}'`

	#Kill fakerport if running
	if ! [ -z $pid ];then
		kill -9 $pid
	fi

	#Remove iptables rules redirecing traffic to FAKERPORT
	iptables -t nat -F PREROUTING
	iptables -D INPUT -p tcp -m tcp --dport $_fport -m state --state NEW -j ACCEPT
	iptables -D INPUT -p tcp -m tcp --dport $_fport -j LOG --log-level 7 --log-prefix "Redirected to FAKERPORT: "

	#print message when done
	printf "FAKERPORT DEACTIVATED\n"
	follow_up
}

function get_status(){
	clear
	figlet -f big allanonwall
	cat <<<"
WHICH TABLE WOULD YOU LIKE TO SEE?
	1)Filter table
	2)Nat table
	3)Mangle table
	4)All tables
	5)Cancel
	6)Go Back
"
	read -n 1 -p "Please select [1-6] --> " response && printf $'\n'$'\n'

	while true;do
	echo $response|grep -E [1-6] 1>/dev/null
	if [ `echo $?` -eq 0 ];then
		break
	else
		read -n 1 -p "Please select [1-6] -->" response && printf $'\n'$'\n'
	fi
	done
	case $response in
	1 )	printf "\t\t\tFILTER TABLE\n"
			printf "\t\t\tIPV4\n"
			iptables -t filter -nL --line-numbers
			printf "\n\t\t\tIPV6\n"
			ip6tables -t filter -nL --line-numbers
		;;
	2 )	printf "\t\t\tNAT TABLE\n"
			printf "\t\t\tIPV4\n"
			iptables -t nat -nL --line-numbers
			printf "\n\t\t\tIPV6\n"
			ip6tables -t nat -nL --line-numbers
		;;
	3 )	printf "\t\t\tMANGLE TABLE\n"
			printf "\t\t\tIPV4\n"
			iptables -t mangle -nL --line-numbers
			printf "\n\t\t\tIPV6\n"
			ip6tables -t mangle -nL --line-numbers
		;;
	4 )	printf "\t\t\tFILTER TABLE\n"
			printf "\t\t\tIPV4\n"
			iptables -t filter -nL --line-numbers
			printf "\n\t\t\tIPV6\n"
			ip6tables -t filter -nL --line-numbers

			printf "\n\t\t\tNAT TABLE\n"
			printf "\t\t\tIPV4\n"
			iptables -t nat -nL --line-numbers
			printf "\n\t\t\tIPV6\n"
			ip6tables -t nat -nL --line-numbers

			printf "\n\t\t\tMANGLE TABLE\n"
			printf "\t\t\tIPV4\n"
			iptables -t mangle -nL --line-numbers
			printf "\n\t\t\tIPV6\n"
			ip6tables -t mangle -nL --line-numbers
		;;
	5 )	exit 0 ;;
	6 )	get_intentions ;;
	esac

	follow_up
}

function follow_up(){
	printf $'\n'
	cat <<<"
WHAT WOULD YOU LIKE TO DO NOW?
	1)Go Back
	2)Quit
"
	read -n 1 -p "Please select [1-2] --> " response && printf $'\n'$'\n'
	while true;do
	echo $response|grep -E [1-2] 1>/dev/null
	if [ `echo $?` -eq 0 ];then
		break
	else
		read -n 1 -p "Please select [1-2] --> " response && printf $'\n'$'\n'
	fi
	done
	if [ $response -eq 1 ];then
		get_intentions
	elif [ $response -eq 2 ];then
		exit 0
	fi
}

function get_intentions(){
	clear
	figlet -f big allanonwall
	cat <<< "
What would you like to do?
	0)Check status
	1)Start firewall
	2)Stop  firewall
	3)Allow traffic through port
	4)Block traffic on port
	5)Allow incoming SSH
	6)Block incoming SSH
	7)Activate TOR transparent proxy
	8)Stop TOR transparent proxy
	9)Start FAKERPORT
	10)Stop FAKERPORT
	11)Cancel
"
	read -n 2 -p "Please reply with [0-11]--> " intention && printf $'\n'$'\n'

	while true;do
		if ! [[ $intention =~ ^[0-9]{1,2}$ ]] || ! [[ $intention -ge 0 && $intention -le 11 ]];then
			read -n 2 -p "Please reply with [0-11] --> " intention && printf $'\n'$'\n'
		else
			break
		fi
	done
	case $intention in
		0 ) get_status ;;
		1 ) activate_firewall ;;
		2 ) deactivate_firewall ;;
		3 ) port_opener ;;
		4 ) port_closer ;;
		5 ) allow_ssh ;;
		6 ) block_ssh ;;
		7 ) tor_transproxy ;;
		8 ) stop_tor_transproxy ;;
		9 ) start_fakerport ;;
		10 ) stop_fakerport ;;
		11 ) exit 0 ;;
	esac
}

### MAIN ###
check_uid
home_dir
check_depends
get_intentions

### END ###
