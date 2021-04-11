from scapy.all import *
import sys
import time


out = open('pk_sniffer.txt','w')

protocols = {1:'ICMP',6:'TCP',17:'UDP'}

pks=[]
num = 0
timer = 10000		
start = time.time()

def showPacket(packet):
	global num
	global start
	#set the timer with the timer variable 
	if time.time()-start<int(timer):
		
		val = time.time()-start
		left = int(timer)-val
		print("time left -> ",left)
		num = num + 1
		src_ip = packet[0][1].src
		dst_ip = packet[0][1].dst
		proto = packet[0][1].proto
		if proto in protocols:		#if proto is icmp, tcp or udp
			
			print("\n\n<",num,"> protocol : %s \n  %s ->  %s"%(protocols[proto],src_ip,dst_ip))
			
		if proto == 1:			#if proto is icmp we'll print this information
			print("  TYPE:[%d], CODE[%d]\n"%(packet[0][2].type,packet[0][2].code))

		
		print("  [Summary Info]\n  ",packet.summary())			#print packet summary
		print(packet.summary(),file=out)					#print packet summary in txt file
		print("\n================================================")
		packet.show()
		print("================================================\n")
		 #print the whole packet information

	else:
		print("timeout")
		start = time.time()
		sys.exit()
		
		
		
def sniffing(filter,count):
			sniff(filter = filter,prn = showPacket,count = int(count))


if __name__ =='__main__':

	while True:
		
		try :
				num = 0
				#set the filter,count,timer				
				print("\n\n\n===================SET THE FILTER & COUNT=======================")
				filter = input("set the filter of your sniffer : ")
				count = input("set your sniffer count ( '0'is for monitering ) : " )
				timer = input("set the timer : ")
					
				print("======================================================================\n")			
				
				
				#check if the count is integer or not
				if count.isdigit():
					start = time.time()
					sniffing(filter,count)
					out.close()

					stop = input("\n\ndo you want to stop?[y/n] : ")
					if stop == 'y':
						break
					else:
						start = time.time()
				else:
					print("ERROR : please answer the question properly")
		except :
			stop = input("do you want to stop?[y/n] : ")
			if stop == 'y':
				break
			else:
				start = time.time()
				
				
				
				
				
				
				
