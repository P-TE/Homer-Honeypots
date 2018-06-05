from ConfigParser import ConfigParser, NoOptionError, NoSectionError
from scapy.all import *

CONF = './example/cisco.conf'
IFACE = 'enp0s3'
NO_RSTACK = 'None'

s = conf.L3socket(iface=IFACE)

# Iptables Rules
# iptables -I INPUT -p ICMP -j NFQUEUE
# iptables -I INPUT -p TCP -j NFQUEUE
# iptables -I INPUT -p UDP -j NFQUEUE

# How to generate a .conf file :
# (example)
# ./gen_profil.sh ./example/cisco.profil ./example/cisco.conf
#
# The nmap db is there :
# https://github.com/nmap/nmap/blob/master/nmap-os-db
# check any example .profil file to do another one

# Flags IP
#NUL = 0
MF = 0x01
DF = 0x02

# Flags ICMP
request = 8

# Flags TCP
NUL = 0
FIN = 0x01 # flag F
SYN = 0x02 # flag S
RST = 0x04 # flag R
PSH = 0x08 # flag P
ACK = 0x10 #  flag A
URG = 0x20 # flag U
ECE = 0x40 # flag E
CWR = 0x80


######################################
#			   CONF				 #
######################################

conf = {'ports':[22,23,80,443], # default values 
	'SEQ':{'SP':'', 'GCD':'', 'ISR':'', 'TI':'', 'CI':'', 'IT':'', 'TS':''},
	'OPS':{'O1':'', 'O2':'', 'O3':'', 'O4':'', 'O5':'', 'O6':''},
	'WIN':{'W1':'', 'W2':'', 'W3':'', 'W4':'', 'W5':'', 'W6':''},
	'ECN':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'O':'', 'CC':'', 'Q':''},
	'T1':{'R':'', 'DF':'', 'T':'', 'TG':'', 'S':'', 'A':'', 'F':'', 'RD':'', 'Q':''},
	'T2':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'S':'', 'A':'', 'F':'', 'O':'', 'RD':'', 'Q':''},
	'T3':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'S':'', 'A':'', 'F':'', 'O':'', 'RD':'', 'Q':''},
	'T4':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'S':'', 'A':'', 'F':'', 'O':'', 'RD':'', 'Q':''},
	'T5':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'S':'', 'A':'', 'F':'', 'O':'', 'RD':'', 'Q':''},
	'T6':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'S':'', 'A':'', 'F':'', 'O':'', 'RD':'', 'Q':''},
	'T7':{'R':'', 'DF':'', 'T':'', 'TG':'', 'W':'', 'S':'', 'A':'', 'F':'', 'O':'', 'RD':'', 'Q':''},
	'U1':{'DF':'', 'T':'', 'TG':'', 'IPL':'', 'UN':'', 'RIPL':'', 'RID':'', 'RIPCK':'', 'RUCK':'', 'RUD':''},
	'IE':{'DFI':'', 'T':'', 'TG':'', 'CD':''}}


def get_conf(FILE):
	# Check if FILE exists
	if os.path.isfile(FILE):
		config_file = FILE
	else:
		print("Conf not found")
		return False

	config = ConfigParser()
	config.read(config_file)
	try:
		conf['SEQ']['SP'] = config.get('SEQ','SP')
	except NoOptionError:
		pass

	try:
		conf['SEQ']['GCD'] = config.get('SEQ','GCD')
	except NoOptionError:
		pass

	try:
		conf['SEQ']['ISR'] = config.get('SEQ','ISR')
	except NoOptionError:
		pass

	try:
		conf['SEQ']['TI'] = config.get('SEQ','TI')
	except NoOptionError:
		pass

	try:
		conf['SEQ']['II'] = config.get('SEQ','II')
	except NoOptionError:
		pass

	try:
		conf['SEQ']['TS'] = config.get('SEQ','TS')
	except NoOptionError:
		pass

	try:
		conf['OPS']['O1'] = config.get('OPS','O1')
	except NoOptionError:
		pass

	try:
		conf['OPS']['O2'] = config.get('OPS','O2')
	except NoOptionError:
		pass

	try:
		conf['OPS']['O3'] = config.get('OPS','O3')
	except NoOptionError:
		pass

	try:
		conf['OPS']['O4'] = config.get('OPS','O4')
	except NoOptionError:
		pass

	try:
		conf['OPS']['O5'] = config.get('OPS','O5')
	except NoOptionError:
		pass

	try:
		conf['OPS']['O6'] = config.get('OPS','O6')
	except NoOptionError:
		pass

	try:
		conf['WIN']['W1'] = config.get('WIN','W1')
	except NoOptionError:
		pass

	try:
		conf['WIN']['W2'] = config.get('WIN','W2')
	except NoOptionError:
		pass

	try:
		conf['WIN']['W3'] = config.get('WIN','W3')
	except NoOptionError:
		pass

	try:
		conf['WIN']['W4'] = config.get('WIN','W4')
	except NoOptionError:
		pass

	try:
		conf['WIN']['W5'] = config.get('WIN','W5')
	except NoOptionError:
		pass

	try:
		conf['WIN']['W6'] = config.get('WIN','W6')
	except NoOptionError:
		pass

	try:
		conf['ECN']['R'] = config.get('ECN','R')
	except NoOptionError:
		pass

	try:
		conf['ECN']['DF'] = config.get('ECN','DF')
	except NoOptionError:
		pass

	try:
		conf['ECN']['T'] = config.get('ECN','T')
	except NoOptionError:
		pass

	try:
		conf['ECN']['TG'] = config.get('ECN','TG')
	except NoOptionError:
		pass

	try:
		conf['ECN']['W'] = config.get('ECN','W')
	except NoOptionError:
		pass

	try:
		conf['ECN']['O'] = config.get('ECN','O')
	except NoOptionError:
		pass

	try:
		conf['ECN']['CC'] = config.get('ECN','CC')
	except NoOptionError:
		pass

	try:
		conf['ECN']['Q'] = config.get('ECN','Q')
	except NoOptionError:
		pass

	try:
		conf['T1']['R'] = config.get('T1','R')
	except NoOptionError:
		pass

	try:
		conf['T1']['DF'] = config.get('T1','DF')
	except NoOptionError:
		pass

	try:
		conf['T1']['T'] = config.get('T1','T')
	except NoOptionError:
		pass

	try:
		conf['T1']['TG'] = config.get('T1','TG')
	except NoOptionError:
		pass

	try:
		conf['T1']['W'] = config.get('T1','W')
	except NoOptionError:
		pass

	try:
		conf['T1']['S'] = config.get('T1','S')
	except NoOptionError:
		pass

	try:
		conf['T1']['A'] = config.get('T1','A')
	except NoOptionError:
		pass

	try:
		conf['T1']['F'] = config.get('T1','F')
	except NoOptionError:
		pass

	try:
		conf['T1']['O'] = config.get('T1','O')
	except NoOptionError:
		pass

	try:
		conf['T1']['RD'] = config.get('T1','RD')
	except NoOptionError:
		pass

	try:
		conf['T1']['Q'] = config.get('T1','Q')
	except NoOptionError:
		pass

	try:
		conf['T2']['R'] = config.get('T2','R')
	except NoOptionError:
		pass

	try:
		conf['T2']['DF'] = config.get('T2','DF')
	except NoOptionError:
		pass

	try:
		conf['T2']['T'] = config.get('T2','T')
	except NoOptionError:
		pass

	try:
		conf['T2']['TG'] = config.get('T2','TG')
	except NoOptionError:
		pass

	try:
		conf['T2']['W'] = config.get('T2','W')
	except NoOptionError:
		pass

	try:
		conf['T2']['S'] = config.get('T2','S')
	except NoOptionError:
		pass

	try:
		conf['T2']['A'] = config.get('T2','A')
	except NoOptionError:
		pass

	try:
		conf['T2']['F'] = config.get('T2','F')
	except NoOptionError:
		pass

	try:
		conf['T2']['O'] = config.get('T2','O')
	except NoOptionError:
		pass

	try:
		conf['T2']['RD'] = config.get('T2','RD')
	except NoOptionError:
		pass

	try:
		conf['T2']['Q'] = config.get('T2','Q')
	except NoOptionError:
		pass

	try:
		conf['T3']['R'] = config.get('T3','R')
	except NoOptionError:
		pass

	try:
		conf['T3']['DF'] = config.get('T3','DF')
	except NoOptionError:
		pass

	try:
		conf['T3']['T'] = config.get('T3','T')
	except NoOptionError:
		pass

	try:
		conf['T3']['TG'] = config.get('T3','TG')
	except NoOptionError:
		pass

	try:
		conf['T3']['W'] = config.get('T3','W')
	except NoOptionError:
		pass

	try:
		conf['T3']['S'] = config.get('T3','S')
	except NoOptionError:
		pass

	try:
		conf['T3']['A'] = config.get('T3','A')
	except NoOptionError:
		pass

	try:
		conf['T3']['F'] = config.get('T3','F')
	except NoOptionError:
		pass

	try:
		conf['T3']['O'] = config.get('T3','O')
	except NoOptionError:
		pass

	try:
		conf['T3']['RD'] = config.get('T3','RD')
	except NoOptionError:
		pass

	try:
		conf['T3']['Q'] = config.get('T3','Q')
	except NoOptionError:
		pass

	try:
		conf['T4']['R'] = config.get('T4','R')
	except NoOptionError:
		pass

	try:
		conf['T4']['DF'] = config.get('T4','DF')
	except NoOptionError:
		pass

	try:
		conf['T4']['T'] = config.get('T4','T')
	except NoOptionError:
		pass

	try:
		conf['T4']['TG'] = config.get('T4','TG')
	except NoOptionError:
		pass

	try:
		conf['T4']['W'] = config.get('T4','W')
	except NoOptionError:
		pass

	try:
		conf['T4']['S'] = config.get('T4','S')
	except NoOptionError:
		pass

	try:
		conf['T4']['A'] = config.get('T4','A')
	except NoOptionError:
		pass

	try:
		conf['T4']['F'] = config.get('T4','F')
	except NoOptionError:
		pass

	try:
		conf['T4']['O'] = config.get('T4','O')
	except NoOptionError:
		pass

	try:
		conf['T4']['RD'] = config.get('T4','RD')
	except NoOptionError:
		pass

	try:
		conf['T4']['Q'] = config.get('T4','Q')
	except NoOptionError:
		pass

	try:
		conf['T5']['R'] = config.get('T5','R')
	except NoOptionError:
		pass

	try:
		conf['T5']['DF'] = config.get('T5','DF')
	except NoOptionError:
		pass

	try:
		conf['T5']['T'] = config.get('T5','T')
	except NoOptionError:
		pass

	try:
		conf['T5']['TG'] = config.get('T5','TG')
	except NoOptionError:
		pass

	try:
		conf['T5']['W'] = config.get('T5','W')
	except NoOptionError:
		pass

	try:
		conf['T5']['S'] = config.get('T5','S')
	except NoOptionError:
		pass

	try:
		conf['T5']['A'] = config.get('T5','A')
	except NoOptionError:
		pass

	try:
		conf['T5']['F'] = config.get('T5','F')
	except NoOptionError:
		pass

	try:
		conf['T5']['O'] = config.get('T5','O')
	except NoOptionError:
		pass

	try:
		conf['T5']['RD'] = config.get('T5','RD')
	except NoOptionError:
		pass

	try:
		conf['T5']['Q'] = config.get('T5','Q')
	except NoOptionError:
		pass

	try:
		conf['T6']['R'] = config.get('T6','R')
	except NoOptionError:
		pass

	try:
		conf['T6']['DF'] = config.get('T6','DF')
	except NoOptionError:
		pass

	try:
		conf['T6']['T'] = config.get('T6','T')
	except NoOptionError:
		pass

	try:
		conf['T6']['TG'] = config.get('T6','TG')
	except NoOptionError:
		pass

	try:
		conf['T6']['W'] = config.get('T6','W')
	except NoOptionError:
		pass

	try:
		conf['T6']['S'] = config.get('T6','S')
	except NoOptionError:
		pass

	try:
		conf['T6']['A'] = config.get('T6','A')
	except NoOptionError:
		pass

	try:
		conf['T6']['F'] = config.get('T6','F')
	except NoOptionError:
		pass

	try:
		conf['T6']['O'] = config.get('T6','O')
	except NoOptionError:
		pass

	try:
		conf['T6']['RD'] = config.get('T6','RD')
	except NoOptionError:
		pass

	try:
		conf['T6']['Q'] = config.get('T6','Q')
	except NoOptionError:
		pass

	try:
		conf['T7']['R'] = config.get('T7','R')
	except NoOptionError:
		pass

	try:
		conf['T7']['DF'] = config.get('T7','DF')
	except NoOptionError:
		pass

	try:
		conf['T7']['T'] = config.get('T7','T')
	except NoOptionError:
		pass

	try:
		conf['T7']['TG'] = config.get('T7','TG')
	except NoOptionError:
		pass

	try:
		conf['T7']['W'] = config.get('T7','W')
	except NoOptionError:
		pass

	try:
		conf['T7']['S'] = config.get('T7','S')
	except NoOptionError:
		pass

	try:
		conf['T7']['A'] = config.get('T7','A')
	except NoOptionError:
		pass

	try:
		conf['T7']['F'] = config.get('T7','F')
	except NoOptionError:
		pass

	try:
		conf['T7']['O'] = config.get('T7','O')
	except NoOptionError:
		pass

	try:
		conf['T7']['RD'] = config.get('T7','RD')
	except NoOptionError:
		pass

	try:
		conf['T7']['Q'] = config.get('T7','Q')
	except NoOptionError:
		pass

	try:
		conf['U1']['DF'] = config.get('U1','DF')
	except NoOptionError:
		pass

	try:
		conf['U1']['T'] = config.get('U1','T')
	except NoOptionError:
		pass

	try:
		conf['U1']['TG'] = config.get('U1','TG')
	except NoOptionError:
		pass

	try:
		conf['U1']['IPL'] = config.get('U1','IPL')
	except NoOptionError:
		pass

	try:
		conf['U1']['UN'] = config.get('U1','UN')
	except NoOptionError:
		pass

	try:
		conf['U1']['RIPL'] = config.get('U1','RIPL')
	except NoOptionError:
		pass

	try:
		conf['U1']['RID'] = config.get('U1','RID')
	except NoOptionError:
		pass

	try:
		conf['U1']['RIPCK'] = config.get('U1','RIPCK')
	except NoOptionError:
		pass

	try:
		conf['U1']['RUCK'] = config.get('U1','RUCK')
	except NoOptionError:
		pass

	try:
		conf['U1']['RUD'] = config.get('U1','RUD')
	except NoOptionError:
		pass

	try:
		conf['IE']['DFI'] = config.get('IE','DFI')
	except NoOptionError:
		pass

	try:
		conf['IE']['T'] = config.get('IE','T')
	except NoOptionError:
		pass

	try:
		conf['IE']['TG'] = config.get('IE','TG')
	except NoOptionError:
		pass

	try:
		conf['IE']['CD'] = config.get('IE','CD')
	except NoOptionError:
		pass

	try:
		conf['ports'] = config.get('Other','ports')
	except NoOptionError:
		pass
	except NoSectionError:
		pass

	translate_conf()


def translate_conf_O(key1, key2):
	O = conf[key1][key2]

	M_flag = False
	T_flag = 0
	W_flag = False
	t1 = 0
	t2 = 0
	option = []
	tmp_string = ''
	#print O+'\n'
	for c in O:
		if M_flag:
			if c in 'LNWTS':
				option.append(('MSS',int(tmp_string, 16)))
				tmp_string=''
				M_flag = False
			else:
				tmp_string += c

		if W_flag:
			if c in 'LNMTS':
				option.append(('WScale',int(tmp_string, 16)))
				tmp_string=''
				W_flag = False
			else:
				tmp_string += c

		# Il semble que pour t1 et t2,
		# 0 => pas de timestamp
		# 1 => il y en a un, mais lequel??
		# On peut : definir des valeurs toujours utiliees
		# modifiables dans le fichier .conf
		if T_flag == 2:
			t2 = int(c)
			T_flag = 0
			option.append(('Timestamp',(t1,t2)))
		if T_flag == 1: 
			t1 = int(c)
			T_flag = 2
			
		if c == 'M':
			M_flag = True

		if c == 'S':
			option.append(('SAckOK',''))

		if c == 'N':
			option.append(('NOP',0))

		if c == 'W':
			W_flag = True

		if c == 'L':
			option.append(('EOL',''))

		if c == 'T':
			T_flag = 1
	if M_flag:
		option.append(('MSS',int(tmp_string, 16)))
	if W_flag:
		option.append(('WScale',int(tmp_string, 16)))

	conf[key1][key2] = option


def translate_conf_W(i):
	W = conf['WIN']['W'+str(i)]
	conf['WIN']['W'+str(i)] = int(W,16)


def translate_conf_ports():
	#if default value
	if type(conf['ports']) != type('string'):
		return 0

	ports = conf['ports']
	tmp_str = ''
	port_list = []
	for c in ports:
		if c == ',':
			port_list.append(int(tmp_str))
			tmp_str = ''
		else:
			tmp_str += c
	port_list.append(int(tmp_str))
	conf['ports'] = port_list


def translate_conf_IE():
	if conf['IE']['DFI'] == 'N':
		# Neither of the ping have DF
		conf['IE']['DFI'] = 0 
	elif conf['IE']['DFI'] == 'S':
		# Both echo the DF value of the probe
		conf['IE']['DFI'] = 'p' 
	elif conf['IE']['DFI'] == 'Y':
		# Both response have the DF
		conf['IE']['DFI'] = 1
	else: # Should be 'O'
		# Both have the DF toggled
		conf['IE']['DFI'] = 't'

	# TG : ttl guess
	try:
		conf['IE']['TG'] = int(conf['IE']['TG'],16)
	except Exception:
		print "Error IE : TG"
		pass

	if conf['IE']['CD'] == 'Z':
		# Both code value are 0
		conf['IE']['CD'] = 0
	elif conf['IE']['CD'] == 'S':
		# Both are the same as the corresponding probe
		conf['IE']['CD'] = 'p'
	elif conf['IE']['CD'] == 'O':
		# Other combination
		conf['IE']['CD'] = 't'
	else: # Should be <NN>
		# Both have the DF toggled
		try:
			conf['IE']['CD'] = int(conf['IE']['CD'],16)
		except Exception:
			conf['IE']['CD'] = int('11',16) # au pif


def translate_conf_T(i):
	# ex : T5(R=Y%DF=N%T=FA-104%TG=FF%W=0%S=A%A=S+%F=AR%O=%RD=0%Q=)
	if conf['T'+str(i)]['R'] == 'N':
		conf['T'+str(i)]['R'] = False
	else:
		conf['T'+str(i)]['R'] = True
	
	# if Don't Fragment
	if conf['T'+str(i)]['DF'] == 'Y':
		conf['T'+str(i)]['DF'] = DF
	# if More Fragment
	elif conf['T'+str(i)]['DF'] == 'N':
		conf['T'+str(i)]['DF'] = MF
	# if not set 
	else :
		conf['T'+str(i)]['DF'] = NUL
		
	# T isn't used
	# T=7B-85 => ttl should be between 7B and 85
	# (we use TG, ttl guess)
	tmp_str = ''
	if conf['T'+str(i)]['T']:
		for c in conf['T'+str(i)]['T']:
			if c == '-':
				break
			else:
				tmp_str += c
		conf['T'+str(i)]['T'] = int(tmp_str,16)
		tmp_str = ''
		
	# TG : ttl guess
	try:
		conf['T'+str(i)]['TG'] = int(conf['T'+str(i)]['TG'],16)
	except Exception:
		pass
	
	# Window
	try:
		conf['T'+str(i)]['W'] = int(conf['T'+str(i)]['W'],16)
	except Exception:
		pass

	# Sequence number
	if conf['T'+str(i)]['S'] == 'Z':
		conf['T'+str(i)]['S'] = -1
	elif conf['T'+str(i)]['S'] == 'A':
		conf['T'+str(i)]['S'] = 0
	elif conf['T'+str(i)]['S'] == 'A+':
		conf['T'+str(i)]['S'] = 1
	else: # Should be 'O'
		conf['T'+str(i)]['S'] = 56 # this is a random value

	# Acknowledgment number
	if conf['T'+str(i)]['A'] == 'Z':
		conf['T'+str(i)]['A'] = -1
	elif conf['T'+str(i)]['A'] == 'S':
		conf['T'+str(i)]['A'] = 0
	elif conf['T'+str(i)]['A'] == 'S+':
		conf['T'+str(i)]['A'] = 1
	else: # Should be 'O'
		conf['T'+str(i)]['A'] = 56 # this is a random value
	
	# Flags
	flag = 0
	if 'F' in conf['T'+str(i)]['F']:
		flag += FIN
	if 'S' in conf['T'+str(i)]['F']:
		flag += SYN 
	if 'R' in conf['T'+str(i)]['F']:
		flag += RST
	if 'P' in conf['T'+str(i)]['F']:
		flag += PSH
	if 'A' in conf['T'+str(i)]['F']:
		flag += ACK
	if 'U' in conf['T'+str(i)]['F']:
		flag += URG
	if 'E' in conf['T'+str(i)]['F']:
		flag += ECE
	conf['T'+str(i)]['F'] = flag
	
	if i != 1:
		translate_conf_O('T'+str(i), 'O')
	
	#TODO : RD and Q


def translate_conf():
	for k in range(1,7):
		#print "translate_conf O&W: "+str(k)
		translate_conf_O('OPS', 'O'+str(k))
		translate_conf_W(k)
	for k in range(1,8):
		#print "translate_conf T: "+str(k)
		translate_conf_T(k)
	translate_conf_ports()
	translate_conf_IE()


######################################
#		  ICMP, & other				 #
######################################

def send_echo_reply(pkt):#, num):
	if(pkt[ICMP].type == 8):
		print "ICMP"
		ip = IP()
		icmp = ICMP()
		ip.src = pkt[IP].dst
		ip.dst = pkt[IP].src
		ip.ttl = conf['IE']['TG']	# TG

		# Don't Fragment ICMP
		if conf['IE']['DFI'] == 't': # Toggled
			if pkt[IP].flags == 1:
				ip.flags = 0 
			else:
				ip.flags = 1
		if conf['IE']['DFI'] == 'p': # Same as probe
			ip.flags = pkt[IP].flags
		else:
			try:
				ip.flags = int(conf['IE']['DFI'])
			except Exception:
				ip.flags = 0

		icmp.type = 0
		icmp.code = pkt[ICMP].code # CD
		# CD
		if conf['IE']['CD'] == 't': # Toggled
			if pkt[ICMP].code:
				icmp.code = 0 
			else:
				icmp.code = 1
		if conf['IE']['CD'] == 'p': # Same as probe
			icmp.code = pkt[ICMP].code
		else:
			try:
				icmp.code = int(conf['IE']['CD'])
			except Exception:
				icmp.code = 0

		icmp.id = pkt[ICMP].id
		icmp.seq = pkt[ICMP].seq
		data = pkt[ICMP].payload
		s.send(ip/icmp/data)


def send_tcp_rst_ack(pkt):
	if pkt['IP'].src != NO_RSTACK:
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
#		  PROBES P1-P6				 #
######################################

def send_rep_px(pkt, num):
	if not num in range(1,7):
		return 1
	# if T1: R=N, abort
	if not conf['T1']['R']:
		#print ("T1: R=N, do not reply")
		return 0

	# getting window size
	WIN_SIZE = conf['WIN']['W'+str(num)]
	OPTIONS = conf['OPS']['O'+str(num)]
	
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	
	if conf['T1']['S'] == -1:
		perso_seq = 0
	else:
		perso_seq = pkt['TCP'].ack  + conf['T1']['S']
	
	if conf['T1']['A'] == -1:
		perso_ack = 0
	else:
		perso_ack = pkt['TCP'].seq  + conf['T1']['A']
	
	my_paquet = IP(dst=ip_dst, ttl=conf['T1']['TG'], flags=conf['T1']['DF'])/TCP(sport=dst_port, flags=conf['T1']['F'], dport=src_port, seq = perso_seq,  ack=perso_ack, window = WIN_SIZE, options=OPTIONS)
	s.send(my_paquet)


######################################
#		  T2 - T7					 #
######################################

def send_rep_tx(pkt, num):
	if not num in range(1,8):
		return 1
	
	# If Reply = No
	if not conf['T'+str(num)]['R']:
		return 0
	
	ip_dst = pkt['IP'].src
	dst_port = pkt['TCP'].dport
	src_port = pkt['TCP'].sport
	
	if conf['T'+str(num)]['S'] == -1:
		perso_seq = 0
	else:
		perso_seq = pkt['TCP'].ack  + conf['T'+str(num)]['S']
	
	if conf['T'+str(num)]['A'] == -1:
		perso_ack = 0
	else:
		perso_ack = pkt['TCP'].seq  + conf['T'+str(num)]['A']
	
	my_paquet = IP(dst=ip_dst, ttl=conf['T'+str(num)]['TG'], flags=conf['T'+str(num)]['DF'])/TCP(sport=dst_port, flags=conf['T'+str(num)]['F'], dport=src_port, seq = perso_seq,  ack=perso_ack, window = conf['T'+str(num)]['W'], options=conf['T'+str(num)]['O'])
	s.send(my_paquet)


def get_tcp_options(pkt,Option):
	ret = ""
	list_options = pkt['TCP'].options
	for element in list_options:
		if Option == element[0]:
			ret = element[1]
	return ret


######################################
#		  PARSING REQUEST			 #
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
			send_rep_px(pkt, 1)

		# P2 = Window Field(63)
		if(WScale == 63):
		 	send_rep_px(pkt, 2)

		# P3 = Windows_Filed(5)
		if(WScale == 4 and RealWScale == 5):
			send_rep_px(pkt, 3)

		# P4 = Windows Field = 4 && WScale = 10
		if(WScale == 4 and RealWScale == 10):
			send_rep_px(pkt, 4)

		# P5 = Windows Field = 16 && WScale = 10
		if(WScale == 16 and RealWScale == 10):
			send_rep_px(pkt, 5)

		# P6 = Windows Field = 512
		if(WScale == 512):
			send_rep_px(pkt, 6)

		## T2 - T7 ###
		# T2 = Flag TCP None + TCP WScale = 128 + Flag IP Dont Fragment set
		if(F == NUL and WScale == 128 and chr(F_IP) == chr(DF)):
			print "T2"
			send_rep_tx(pkt, 2)

		# T3 = Flag TCP SYN/FIN/URG/PSH + TCP WScale + Flag IP Dont Fragment is not set
		elif(F & SYN and F & FIN and F & URG and F & PSH and WScale == 256 and chr(F_IP) != chr(DF)):
			print "T3"
			send_rep_tx(pkt, 3)
					
		# T4 = Flag TCP ACK + IP DF set + TCP WScale 1024
		elif(F & ACK and chr(F_IP) == chr(DF) and WScale == 1024):
			print "T4"
			send_rep_tx(pkt, 4)

		#T5 = Flag TCP SYN + IP DF not set + WScale 31337
		elif(F & SYN and chr(F_IP) != chr(DF) and WScale == 31337):
			print "T5"
			send_rep_tx(pkt, 5)

		# T6 = Flag TCP Ack + IP DF set + WScale 32768
		elif(F & ACK and chr(F_IP) == chr(DF) and WScale == 32768):
			print "T6"
			send_rep_tx(pkt, 6)

		#T7 = Flag TCP FIN/PSH/URG + WScale 65535 + IP DF not set
		elif(F & FIN and F & PSH and F & URG and WScale == 65535 and chr(F_IP) != chr(DF)):
			print "T7"
			send_rep_tx(pkt, 7)
		
		elif TCP_dport in conf['ports']:
			send_syn_ack(pkt)
		
		else:
			send_tcp_rst_ack(pkt)



	if ICMP in pkt:
		send_echo_reply(pkt)
		

get_conf(CONF)
# Sniff
print "Ready"
sniff(iface=IFACE, prn=pkt_callback, store=0)


