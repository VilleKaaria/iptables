#!/bin/bash

IPT="/sbin/iptables"
IP6T="/sbin/ip6tables"
INTERF="eth0"

# Delete all rules
$IPT -F
$IP6T -F

# Delete all chains
$IPT -X
$IP6T -X

# Zero packet and byte counters in all chains
$IPT -Z
$IP6T -Z

# Set default policy to drop
$IPT -P INPUT DROP
$IPT -P OUTPUT DROP
$IPT -P FORWARD DROP
$IP6T -P INPUT DROP
$IP6T -P OUTPUT DROP
$IP6T -P FORWARD DROP

# Allow loopback
$IPT -A INPUT -i lo -j ACCEPT
$IPT -A OUTPUT -o lo -j ACCEPT
$IP6T -A INPUT -i lo -j ACCEPT
$IP6T -A OUTPUT -o lo -j ACCEPT

# Log blocked Output packets
$IPT -N BLOCKEDOUTPUT
$IPT -A BLOCKEDOUTPUT -m limit --limit 10/min -j LOG --log-prefix "iptables[OUTPUT-blocked]: "
$IPT -A BLOCKEDOUTPUT -j DROP
$IP6T -N BLOCKEDOUTPUT
$IP6T -A BLOCKEDOUTPUT -m limit --limit 10/min -j LOG --log-prefix "ip6tables[OUTPUT-blocked]: "
$IP6T -A BLOCKEDOUTPUT -j DROP

# Log ICMP flood
$IPT -N ICMPFLOOD
$IPT -A ICMPFLOOD -m recent --name ICMP --set --rsource
$IPT -A ICMPFLOOD -m recent --name ICMP --update --rsource --seconds 1 --hitcount 6 --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "iptables[ICMPFLOOD-blocked]: "
$IPT -A ICMPFLOOD -m recent --name ICMP --update --rsource --seconds 1 --hitcount 6 --rttl -j DROP
$IPT -A ICMPFLOOD -j ACCEPT
$IP6T -N ICMPFLOOD
$IP6T -A ICMPFLOOD -m recent --name ICMP --set --rsource
$IP6T -A ICMPFLOOD -m recent --name ICMP --update --rsource --seconds 1 --hitcount 6 --rttl -m limit --limit 1/sec --limit-burst 1 -j LOG --log-prefix "ip6tables[ICMPFLOOD-blocked]: "
$IP6T -A ICMPFLOOD -m recent --name ICMP --update --rsource --seconds 1 --hitcount 6 --rttl -j DROP
$IP6T -A ICMPFLOOD -j ACCEPT

# Log and drop invalid packets
$IPT -N BADPACKET
$IPT -A BADPACKET -m limit --limit 10/min -j LOG --log-prefix "iptables[BADPACKET-blocked]: "
$IPT -A BADPACKET -j DROP
$IP6T -N BADPACKET
$IP6T -A BADPACKET -m limit --limit 10/min -j LOG --log-prefix "ip6tables[BADPACKET-blocked]: "
$IP6T -A BADPACKET -j DROP

# Limit new inbound SSH connections to 5 per 5 minutes per IP with "recent" module
$IPT -N NEWSSH
# Add new connection IP to list --set
$IPT -A NEWSSH -m recent --name SSH --set
# Update IPs last seen timestamp --update 
# Matching IPs with timestamp in within last 300 seconds --seconds 300
# Dropping packets from IPs with 6 or more packets received --hitcount 6 -j DROP
$IPT -A NEWSSH -m recent --name SSH --update --seconds 300 --hitcount 6 -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "iptables[SSH-blocked]: "
$IPT -A NEWSSH -m recent --name SSH --update --seconds 300 --hitcount 6 -j DROP
# If packet not dropped then allow new connection
$IPT -A NEWSSH -j ACCEPT
$IP6T -N NEWSSH
$IP6T -A NEWSSH -m recent --name SSH --set
$IP6T -A NEWSSH -m recent --name SSH --update --seconds 300 --hitcount 6 -m limit --limit 1/sec --limit-burst 100 -j LOG --log-prefix "ip6tables[SSH-blocked]: "
$IP6T -A NEWSSH -m recent --name SSH --update --seconds 300 --hitcount 6 -j DROP
$IP6T -A NEWSSH -j ACCEPT

# Drop invalid packets
$IPT -A INPUT -m conntrack --ctstate INVALID -j BADPACKET
$IPT -A OUTPUT -m conntrack --ctstate INVALID -j BADPACKET
$IPT -A FORWARD -m conntrack --ctstate INVALID -j BADPACKET
$IP6T -A INPUT -m conntrack --ctstate INVALID -j BADPACKET
$IP6T -A OUTPUT -m conntrack --ctstate INVALID -j BADPACKET
$IP6T -A FORWARD -m conntrack --ctstate INVALID -j BADPACKET

# Block remote packets claiming to be from a loopback address.
$IPT -A INPUT -s 127.0.0.0/8 ! -i lo -j BADPACKET
$IP6T -A INPUT -s ::1/128 ! -i lo -j BADPACKET

# Check that syn packets are at the start of the connection
$IPT -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j BADPACKET
$IP6T -A INPUT -p tcp ! --syn -m conntrack --ctstate NEW -j BADPACKET

# Drop XMAS packets
$IPT -A INPUT -p tcp --tcp-flags ALL ALL -j BADPACKET
$IP6T -A INPUT -p tcp --tcp-flags ALL ALL -j BADPACKET

# Drop NULL packets
$IPT -A INPUT -p tcp --tcp-flags ALL NONE -j BADPACKET
$IP6T -A INPUT -p tcp --tcp-flags ALL NONE -j BADPACKET

# Drop inbound packets that are Broadcast, Multicast or Anycast
$IPT -A INPUT -m addrtype --dst-type BROADCAST -j BADPACKET
$IPT -A INPUT -m addrtype --dst-type MULTICAST -j BADPACKET
$IPT -A INPUT -m addrtype --dst-type ANYCAST -j BADPACKET
$IPT -A INPUT -d 224.0.0.0/4 -j BADPACKET

# Allow established tcp, udp and icmp connections
$IPT -A INPUT -i $INTERF -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INTERF -p udp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IPT -A INPUT -i $INTERF -p icmp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INTERF -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INTERF -p udp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IPT -A OUTPUT -o $INTERF -p icmp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IP6T -A INPUT -i $INTERF -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IP6T -A INPUT -i $INTERF -p udp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p tcp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p udp -m conntrack --ctstate ESTABLISHED -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p ipv6-icmp -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow inbound ipv4 RFC 792 ICMP packets
$IPT -A INPUT -i $INTERF -p icmp --icmp-type 0 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT -i $INTERF -p icmp --icmp-type 3 -m conntrack --ctstate NEW -j ACCEPT
$IPT -A INPUT -i $INTERF -p icmp --icmp-type 11 -m conntrack --ctstate NEW -j ACCEPT

# Allow inbound ipv6 RFC 4890 ICMP packets
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 1 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 2 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 3 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 4 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 133 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 134 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 135 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 136 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 137 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 141 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 142 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 130 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 131 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 132 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 143 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 148 -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 149 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 151 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 152 -j ACCEPT
$IP6T -A INPUT -i $INTERF -s fe80::/10 -p ipv6-icmp --icmpv6-type 153 -j ACCEPT

# Allow outbound ipv6 ICMP
$IP6T -A OUTPUT -o $INTERF -p ipv6-icmp --icmpv6-type 133 -j ACCEPT

# Allow inbound and outbound ping
$IPT -A INPUT -i $INTERF -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ICMPFLOOD
$IPT -A OUTPUT -o $INTERF -p icmp --icmp-type 8 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A INPUT -i $INTERF -p ipv6-icmp --icmpv6-type 128 -j ICMPFLOOD
$IP6T -A OUTPUT -o $INTERF -p ipv6-icmp --icmpv6-type 128 -j ACCEPT

# Allow inbound HTTP
$IPT -A INPUT -i $INTERF -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
#$IP6T -A INPUT -i $INTERF -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow inbound HTTPS
$IPT -A INPUT -i $INTERF -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
#$IP6T -A INPUT -i $INTERF -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow outbound DNS
$IPT -A OUTPUT -o $INTERF -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# Check new inbound SSH connections with NEWSSH chain
$IPT -A INPUT -i $INTERF -p tcp --dport 22 -m conntrack --ctstate NEW -j NEWSSH
# add -s IP if only listed ips are allow to connect. example: $IPT -A INPUT -i $INTERF -p tcp --dport 22 -s 192.168.0.1 -m conntrack --ctstate NEW -j NEWSSH
# $IP6T -A INPUT -i $INTERF -p tcp --dport 22 -m conntrack --ctstate NEW -j NEWSSH

# Allow outbound NTP
$IPT -A OUTPUT -o $INTERF -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p udp --dport 123 -m conntrack --ctstate NEW -j ACCEPT

# Allow outbound HTTP
$IPT -A OUTPUT -o $INTERF -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# Allow outbound HTTPS
$IPT -A OUTPUT -o $INTERF -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p tcp --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# Allow outbound DHCP
$IPT -A OUTPUT -o $INTERF -p udp --sport 67:68 --dport 67:68 -m conntrack --ctstate NEW -j ACCEPT
$IP6T -A OUTPUT -o $INTERF -p udp --sport 67:68 --dport 67:68 -m conntrack --ctstate NEW -j ACCEPT

# Log blocked outbound packets with BLOCKEDOUTPUT chain
$IPT -A OUTPUT -j BLOCKEDOUTPUT
$IP6T -A OUTPUT -j BLOCKEDOUTPUT
