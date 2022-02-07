# Allanonwall
![alt text](./allanonwall.png)
**An advanced bash script that creates an iptables and ip6tables firewall with many features to serve different situations**

## **Features**
1. Allow incoming traffic to specific ports of your choosing
2. Allow/deny devices to connect to hotspot
3. Rate-limit SSH to slow SSH brute-force attacks
4. Route all traffic through the tor network via a transparent proxy
5. Deceive inexperienced attackers by sending fake banners to port scanners to make it appear as though all your ports are open

## **Requires**
* iptables
* ip6tables
* iptables-persistent (if using Debian-based distribution)
* NetworkManager
* figlet
* tor
* python 3
* iw

## **Installation**
* Install all the packages listed above if you haven't already
* Make sure to add **both** *allanonwall.sh* and *fakerport.py* to your PATH.
* Add the following lines to your torrc file *(located at /etc/tor/)*:
```
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040 IsolateClientAddr IsolateClientProtocol IsolateDestAddr IsolateDestPort
DNSPort 5353
```

**NB: allanonwall.sh needs to be run as root in order for it to be able to make changes to your iptables rules**
