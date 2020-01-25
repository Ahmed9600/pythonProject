import re
import subprocess
import socket
import contextlib
import sys
from datetime import datetime
import os
import platform
from bs4 import BeautifulSoup
from bs4 import Comment
import requests
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler
import time
import threading
import iptc
host = "127.0.0.1"


def menu():
	print("If you want the parsing tool press 1")
	print("\nIf you want the monotoring tool press 2")
	print("\nIf you want the scanning tool press 3")
	print("\nIf you want the attack detection tool press 4")
	print("\nIf you want to parse a link and extract all the information of it press 5")
	print("\nType any other key in order to close")
	theInput = input("\nPress the number for the tool you want")
	if(theInput=='1'):
		parseInfo()
		menu()
	elif(theInput=='2'):
		monitoring()
		menu()
	elif(theInput=='3'):
		IP_scan()
		menu()
	elif(theInput=='4'):
		__main__()
		menu()
	elif(theInput=='5'):
		parsingHTML()
		menu()
	else:
		sys.exit()


# ITI_Tool


def parseInfo():
	file = open('logs.txt','r')
	textf = file.readlines()
	logs = []
	for i in textf:
		logs.append(i.split())

	for ips in logs:
		print 

	for uAgent in logs:
		print("IP is: "+ uAgent[0] +  " using method: " + uAgent[5][1:] + " to access URI of: " + uAgent[6][1:-1]+" with user agent name of: " + (' '.join(uAgent[11:-1]))[1:-1]  )


def monitoring():
	logging.basicConfig(level=logging.INFO,
	format='%(asctime)s - %(message)s',
	datefmt='%Y-%m-%d %H:%M:%S')
	path = sys.argv[1] if len(sys.argv) > 1 else '.'
	event_handler = LoggingEventHandler()
	observer = Observer()
	observer.schedule(event_handler, 'pythonprojects', recursive=True)
	observer.start()
	try:
		while True:
			time.sleep(1)
	except KeyboardInterrupt:
		observer.stop()
	observer.join()



#def ReggWeb():
#	file_handle = open('test2.txt' , 'r')
#	www=file_handle.read()
#	firstHttp = re.findall("(http://|https://)(.+)(.org|.com|.net|.at)" , www)
#	print(list(map(' '.join, firstHttp)))




def IP_scan():

	fullAddress = input("Enter the Network Address")
	addressSplit = fullAddress.split(".")
	a = "."
	networkAddress = addressSplit[0]+a+addressSplit[1]+a+addressSplit[2]+a
	startAddress = int(input("Enter the start address"))
	endAddress = int(input("Enter the end address"))
	startPort = int(input("Enter the start port"))
	endPort = int(input("Enter the end port"))
	endAddress = endAddress + 1
	endPort = endPort + 1
	try: 
		for ip in range(startAddress,endAddress):
			addr = networkAddress+str(ip)
			for port in range(startPort,endPort):
				s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
			#socket.setdefaulttimeout(1)
				result = s.connect_ex((addr,port))


#	for ip in range(startAddress,endAddress)
#		addr = networkAddress+str(ip)
				if(result == 0):

					nmapCMD = "nmap -sC -sV -p " + str(port) + " " + str(addr)
					res = os.popen(nmapCMD).read()


					print(addr, "is up with port",port)
					print(res)

				else:
					print(addr,"is down with port" , port)
	except KeyboardInterrupt:
		print("Interrupted")
		sys.exit() 


#IP_scan()
#----------------------------------------------------------------

class MyThread(threading.Thread):

    def __init__(self, host, port):

        threading.Thread.__init__(self)
        self.port = port
        self.host = host
    def block(self, ip):
        chain = iptc.Chain(iptc.Table(iptc.Table.FILTER), "INPUT")
        rule = iptc.Rule()
        rule.in_interface = "lo"
        rule.src = ip
        target = iptc.Target(rule, "DROP")
        rule.target = target
        chain.insert_rule(rule)
        print(chain.rules)
    def listen(self):
        serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            serv.bind((host, self.port))
        except:
            print("Port " + str(self.port) + " is in use \n")
        serv.listen(5)
        while True:
            conn, addr = serv.accept()
            if (conn): print("client : " + str(addr[0]) + "  trying to connect on port " + str(self.port) + "\n")
            self.block(str(addr[0]))
            print("this address " + str(addr[0])+ " has been blocked \n")


    def run(self):
        self.listen()

def __main__():
    ports = [8888, 9999, 4444]
    threads = []
    for i in ports:
        thread = MyThread(host, i)
        thread.start()
        threads.append(thread)
    print("listenning on ports " + str(ports))

#---------------------------------
def parsingHTML():
	theURL = input("Enter the URL you want to parse")
	#urlTest = "https://old.reddit.com/r/datascience/"
	headers = {'User-Agent': 'Mozilla/5.0'}
	page = requests.get(theURL, headers=headers)
	soup = BeautifulSoup(page.text, 'html.parser')
	#print(soup)
	tags=[]
	for tag in soup.find_all(True):
		tags.append("<"+tag.name+">")
	tagUnique = set(tags)
	for i in tagUnique:
		print(i)

#------------------------

	for comments in soup.findAll(text=lambda text:isinstance(text,Comment)):
		print("<!--"+comments+" -->")		


#------------------------

	domainList=[]
	sSoup = str(soup)
	pattern=re.findall(r'(www\.)(.+\.[a-z]{2,3})',sSoup)
	for domain in pattern:
		domainList.append(domain[1])
	final_domain=set(domainList)


	for j in final_domain:
		print(j)

#-------------------------

	subDomainList=[]
	for subdomainn in newDomains:
		newPattern=re.compile('[a-z0-9]*\.'+subdomainn)
		resp=re.findall(newPattern,sSoup)
		subDomainList.append(list(set(resp)))


	for k in subDomainList:
		print(k)


#-----------------------------

	finalURL = re.findall(r"\w+://\w+\.\w+\.\w+/?[\w\.\?=#]*", sSoup)
	f_result = set(finalURL)
	for p in f_result:
		print("\n",p)


#parsingHTML()



#def run1():
#	for ip in range(startAddress,endAddress):
#		addr = net2 + str(ip)
#		if (scan(addr)):
#			print (addr , "is live")






#for i in range(0 , len(lines)):
#	res=pattern.findall(lines[i])
#	res=list(set(res))
#	print(res)
	
#ReggWeb()

menu()
