from scapy.all import *

s = conf.L3socket(iface="eth0")

# Iptables Rules
# iptables -I INPUT -p ICMP -j NFQUEUE
# iptables -I INPUT -p TCP -j NFQUEUE
# iptables -I INPUT -p UDP -j NFQUEUE

# Flags IP
DF = 0x02

# Flags ICMP
request = 8

# Flags TCP
NUL = 0
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80

# Port a ouvrir
portCisco =[22,23,80,443]

def send_echo_reply(pkt):
        if(pkt[ICMP].type == 8):
        	print "ICMP detect"
        	ip = IP()
        	icmp = ICMP()
        	ip.src = pkt[IP].dst
        	ip.dst = pkt[IP].src
        	ip.ttl = 254
        	ip.flags = pkt[IP].flags
        	icmp.type = 0
        	icmp.code = pkt[ICMP].code
        	icmp.ttl = 255
        	icmp.id = pkt[ICMP].id
        	icmp.seq = pkt[ICMP].seq
        	data = pkt[ICMP].payload
        	s.send(ip/icmp/data)

def send_tcp_rst_ack(pkt):
	if pkt['IP'].src != "192.168.10.16":
		ip_dst = pkt['IP'].src
		dst_port = pkt['TCP'].dport
		src_port = pkt['TCP'].sport
		perso_seq = pkt['TCP'].ack + 1
		perso_ack = pkt['TCP'].seq + 1
		my_paquet = IP(dst=ip_dst)/TCP(sport=dst_port, flags=0x14, dport=src_port, seq = perso_seq,  ack=perso_ack)
		s.send(my_paquet)


def send_syn_ack(pkt):
	# Recup Value
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 1
	perso_ack = pkt['TCP'].seq + 1
	# Forge TCP
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags='SA', dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128)
	s.send(my_paquet)

######################################
#          PROBES P1-P6				 #
######################################



def send_rep_p1(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 56
	perso_ack = pkt['TCP'].seq + 1
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags='SA', dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128, options=[('MSS',1460)])
	s.send(my_paquet)

def send_rep_p2(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 1
	perso_ack = pkt['TCP'].seq + 1
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags='SA', dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128, options=[('MSS',1400)])
	s.send(my_paquet)

def send_rep_p3(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 1
	perso_ack = pkt['TCP'].seq + 1
	# Forge TCP
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags='SA', dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128, options=[('MSS',640)])
	s.send(my_paquet)

def send_rep_p4(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 1
	perso_ack = pkt['TCP'].seq + 1
	# Forge TCP
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags='SA', dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128, options=[('MSS',536)])
	s.send(my_paquet)


def send_rep_p5(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 1
	perso_seq = 0
	perso_ack = pkt['TCP'].seq + 1
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags=0x14, dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128, options=[('MSS',536)])
	s.send(my_paquet)


def send_rep_p6(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack + 1
	perso_ack = pkt['TCP'].seq + 1
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags='SA', dport=src_port, seq = perso_seq,  ack=perso_ack, window = 4128, options=[('MSS',265)])
	s.send(my_paquet)


######################################
#          T2 - T7					 #
######################################


def send_rep_t5(pkt):
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	perso_seq = pkt['TCP'].ack 
	perso_ack = pkt['TCP'].seq
	my_paquet = IP(dst=ip_dst, ttl=254, flags=0x1)/TCP(sport=dst_port, flags=0x14, dport=src_port, seq = perso_seq,  ack=perso_ack, window = 0)
	s.send(my_paquet)



def get_tcp_options(pkt,Option):
	ret = ""
	list_options = pkt['TCP'].options
	for element in list_options:
		if Option == element[0]:
			ret = element[1]
	return ret



######################################
#          PARSING REQUEST			 #
######################################

def pkt_callback(pkt):
	if TCP in pkt:
		F = pkt['TCP'].flags
		F_IP = pkt['IP'].flags
		WScale = pkt['TCP'].window
		TCP_dport = pkt['TCP'].dport
		RealWScale = get_tcp_options(pkt,'WScale')

		# P1 = Window Scale (10), NOP, MSS (1460), timestamp 0xFFFFFF, TSecr : 0, Window field 1
		if(WScale == 1):
			send_rep_p1(pkt)

		# P2 = Window Field(63)
		if(WScale == 63):
		 	send_rep_p2(pkt)

		# P3 = Windows_Filed(5)
		if(WScale == 4 and RealWScale == 5):
			send_rep_p3(pkt)

		# P4 = Windows Field = 4 && WScale = 10
		if(WScale == 4 and RealWScale == 10):
			send_rep_p4(pkt)

		# P5 = Windows Field = 16 && WScale = 10
		if(WScale == 16 and RealWScale == 10):
			send_rep_p5(pkt)

		# P6 = Windows Field = 512
		if(WScale == 512):
			send_rep_p6(pkt)

		## T2 - T7 ###
		# T2 = Flag TCP None + TCP WScale = 128 + Flag IP Dont Fragment set
		if(F == NUL and WScale == 128 and chr(F_IP) == chr(DF)):
			print "T2"

		# T3 = Flag TCP SYN/FIN/URG/PSH + TCP WScale + Flag IP Dont Fragment is not set
		elif(F & SYN and F & FIN and F & URG and F & PSH and WScale == 256 and chr(F_IP) != chr(DF)):
			print "T3"
					
		# T4 = Flag TCP ACK + IP DF set + TCP WScale 1024
		elif(F & ACK and chr(F_IP) == chr(DF) and WScale == 1024):
			print "T4"

		#T5 = Flag TCP SYN + IP DF not set + WScale 31337
		elif(F & SYN and chr(F_IP) != chr(DF) and WScale == 31337):
			print "T5"
			send_rep_t5(pkt)

		# T6 = Flag TCP Ack + IP DF set + WScale 32768
		elif(F & ACK and chr(F_IP) == chr(DF) and WScale == 32768):
			print "T6"

		#T7 = Flag TCP FIN/PSH/URG + WScale 65535 + IP DF not set
		elif(F & FIN and F & PSH and F & URG and WScale == 65535 and chr(F_IP) != chr(DF)):
			print "T7"
		
		elif TCP_dport in portCisco:
			send_syn_ack(pkt)
		
		else:
			send_tcp_rst_ack(pkt)



	if ICMP in pkt:
		send_echo_reply(pkt)
		

# Sniff
sniff(iface="eth0", prn=pkt_callback, store=0)

