#! /usr/bin/python
# -*- coding: utf-8 -*-

# author : J.C
# creation date : 06/09/2017 
# modification date : 20/11/2017 

# ------------  IMPORT ---------------

import sys, os
from logging import getLogger, ERROR
import pyclamd
getLogger('scapy.runtime').setLevel(ERROR)

import logging, hashlib
from logging.handlers import RotatingFileHandler
from datetime import datetime

try:
	from scapy.all import *
except ImportError:
	print '[!] ERROR : Scapy not found '
	sys.exit(1)

# ----------  VARIABLES --------------

array_ftp_commands = {'USER' : 5,
					  'PASS' : 5,
					  'TYPE' : 1, 
					  'CWD' : 2,
					  'LIST' : 3,
					  'PWD' : 2, 
					  'DELE' : 5,
					  'RETR' : 5, #GET Important  srcport = 20
					  'STOR' : 5,  #PUT Important  dstport = 20
					  'MKD' : 4,
					  'RMD' : 5,
					  'QUIT' : 1
					  }


# ----------  FUNCTIONS --------------
class honeyFTP:
	def __init__(self):
		self.logger = self.initLoggerFormat()
		self.currentcommand = ""
		self.clamav = pyclamd.ClamdAgnostic()
		self.portpassif = -1

		self.file_filename = None
		self.file_data = ""
		self.file_command = ""
		self.file_ip = ""

	def initLoggerFormat(self):
		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)
		formatter = logging.Formatter("%(date)s %(ip_source)s %(service)s %(ratio)s %(message)s")
		file_handler = RotatingFileHandler('/var/log/homer/honeyftp.log','a',1000000,1 )
		file_handler.setFormatter(formatter)
		logger.addHandler(file_handler)
		return logger


	def isFTPRequest(self, pkt):
		if pkt.haslayer(TCP) and pkt.haslayer(Raw):
			if pkt[TCP].dport == 21:
				return True
			else:
				return False
		else:
			return False

	def isFTPResponse(self, pkt):
		if pkt.haslayer(TCP) and pkt.haslayer(Raw):
			if pkt[TCP].sport == 21:
				return True
			else:
				return False
		else:
			return False

	def isFTPPutData(self, pkt):
		if pkt.haslayer(TCP) and pkt.haslayer(Raw):
			if pkt[TCP].dport == 20 :
				return True
			if pkt[TCP].dport == int(self.portpassif):
				#self.passive = ?? 
				return True
			else:
				return False
		else:
			return False

	def isFTPGetData(self, pkt):
		#print pkt.show()
		port = 20
		if pkt.haslayer(TCP) and pkt.haslayer(Raw):
			if pkt[TCP].sport == 20:
				return True			
			if pkt[TCP].sport == int(self.portpassif):
				#self.passive = ?? 
				return True
			else:
				return False
		else:
			return False



	def getIP(self):
		command = "ip a | grep eth0 | grep inet | awk '{print $2}'"
		f = os.popen(command)
		ip = f.read()
		return ip.replace('/24','')


	def create_syslog(self, key, args, ip_src, indice):
		ip = self.getIP()
		now = datetime.now().strftime("%b %d %H:%M:%S")
		element = {'date' : now, 'ip_source': str(ip.replace('\n','')), 'service': 'honeyFTP', 'ratio':str(indice)}
		self.logger.info("["+str(ip_src.replace('\n',''))+"]"+str(key)+" "+str(args), extra=element)


	def check_command(self, command, ip_src):
		for key in array_ftp_commands.keys():
			if (key in command):
				self.create_syslog(key, command.replace(key, '').strip(), ip_src, array_ftp_commands[key])
				return command
		#Commande non référencée		
		self.create_syslog(command, "", ip_src, -1)
		return ""

	def saveFile(self, data, ip, command):

		if self.file_filename == None: 
			now = datetime.now().strftime("%b%d-%H:%M:%S")
			tmp = command.split(' ')
			filename = "["+str(now)+"]["+str(ip)+"]["+tmp[0]+"]"+tmp[1]
			filename = filename.replace('\r\n', '')
			self.file_filename = filename
			self.file_data = data
			self.file_command = command
			self.file_ip = ip
		else:
			self.file_data += data



	
	def analyseFile(self, filepath, command, ip_src):
		tmp = command.split(' ')
		key = tmp[0]
		filename = tmp[1]

		result = self.clamav.scan_file(filepath)
		f = open(filepath, 'rb')
		tmp = f.read()
		hashfile = hashlib.sha1(tmp).hexdigest()
		f.close()
		if result == None:
			data_log = filename.strip() + " sha1:"+str(hashfile) + " result:NEGATIVE"
			self.create_syslog(key+"-ANALYSE", data_log, ip_src, 0)

		else:
			data_log = filename.strip() + " sha1:"+str(hashfile) + " result:POSITIVE"
			self.create_syslog(key+"-ANALYSE", data_log, ip_src, 5)
		return None		

	def check_pkt(self, pkt):

		if "RETR" in self.currentcommand and self.isFTPGetData(pkt):
			ip = pkt[IP].dst
			data = pkt[Raw].load
			self.saveFile(data, ip, self.currentcommand)
		elif "STOR" in self.currentcommand and self.isFTPPutData(pkt):
			ip = pkt[IP].src
			data = pkt[Raw].load
			self.saveFile(data, ip, self.currentcommand)
		elif self.isFTPRequest(pkt):
			ip_src = pkt[IP].src
			data=pkt[Raw].load 
			self.currentcommand = self.check_command(data, ip_src)
		elif self.isFTPResponse(pkt):
			data=pkt[Raw].load 
			if "Passive Mode" in data.strip():
				#Cas "Extended"
				if "Extended" in data.strip():
					self.portpassif = data.split('(')[1].split(')')[0].replace('|','')
				#Cas normal
				else:
					all_input = data.split('(')[1].split(')')[0]
					tmp_port = all_input.split(',')[-2:]
					passive_port = int(tmp_port[0]) * 256 + int(tmp_port[1])
					self.portpassif = str(passive_port)
			if "Transfer complete" in data.strip():
				if self.file_filename != None:
					f = open('/var/log/homerfile/'+str(self.file_filename), 'wb')
					f.write(self.file_data)
					f.close()
					self.analyseFile('/var/log/homerfile/'+str(self.file_filename), self.file_command, self.file_ip)

					self.file_filename = None
					self.file_data = ""
					self.file_command = ""
					self.file_ip = ""
				else:
					print "[ERREUR] Save File after transfer completed >> filename is null"


# -------------  MAIN ----------------

if __name__ == '__main__':
	honey_instance = honeyFTP()
	print "[+] Sniffing started"
	try:
		sniff(iface="eth0", prn=honey_instance.check_pkt)
	except Exception as e:
		print '[!] ERROR : Failed to initialize sniff()'
		print e
