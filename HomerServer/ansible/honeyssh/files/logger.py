#!/usr/bin/python
#coding: utf-8
import time
import json
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from os import popen



array_commands = {'ls' : 0,
		  'pwd' : 0,
		  'touch' : 3,
		  'rm' : 4,
		  'shutdown': 5
		 }

class Watcher:
	def __init__(self):
		self.l = Logger()
		self.cursor = 0
		self.logfile = "/home/cowrie/cowrie-git/log/cowrie.json"

	def run(self):
		while True:
			time.sleep(30)
			with open(self.logfile, 'r') as f:
				f.seek(self.cursor)
				lines = f.readlines()
				self.cursor = f.tell()
			if len(lines) != 0:
				for line in lines:
					self.l.create_syslog(line)

class Logger():
	def __init__(self):
		self.logger = self.initLoggerFormat()

	def initLoggerFormat(self):
		logger = logging.getLogger()
		logger.setLevel(logging.DEBUG)
		formatter = logging.Formatter("%(date)s %(ip_source)s %(service)s %(ratio)s %(message)s")
		file_handler = RotatingFileHandler('/var/log/homer/honeyssh.log','a',1000000,1 )
		file_handler.setFormatter(formatter)
		logger.addHandler(file_handler)
		return logger

	def getIP(self):
		command = "hostname -i"
		f = popen(command)
		ip = f.read()
		return ip.strip()

	def create_syslog(self, line):
		log = json.loads(line)
		timestamp = datetime.strptime(log['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ").strftime("%b %d %H:%M:%S")	
		eventid = log['eventid']
		indice = -1
		if eventid == "cowrie.command.input":
			cmd = log['message'].split(': ')[1]
			for keys in array_commands.keys():
				if keys == cmd:
					indice = array_commands[cmd]
					break
		element = {'date': timestamp, 'ip_source': self.getIP(), 'service': 'honeySSH', 'ratio': str(indice)}
		self.logger.info(line, extra=element)


if __name__ == "__main__":
	watcher = Watcher()
	watcher.run()
