# Detect portscans of host, automatically blacklist addresses that scan and runs connecting addresses to see if they were similar to blacklisted
from scapy.all import *
import os
import sys
from datetime import datetime
import socket
from collections import OrderedDict


#  Logic of program:
#  Sniff network for (TCP ONLY RIGHT NOW) connections
#  Log each connection in the dictionary
#       ->Only keep track of N number of connections
#       ->Only keep track of connections for T time period
#       ->
#
#



#This value is how many port connections an IP connects to on the host before it is considered hostile
SCANTHRESHOLD = 25

class Connection():
        def __init__(self, pkt):
                self.src = pkt[IP].src
                self.dst = pkt[IP].dst
                self.ports = set()
                self.timeStamp = datetime.fromtimestamp(pkt.time)
                self.pkt = pkt



def timeStamp(pkt):
        #print(datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f'))
        return datetime.fromtimestamp(pkt.time)

def getFlags(pkt):
        F = pkt[TCP].flags
        return F


connections = OrderedDict() #a dictionary of connections to the host, maintains insertion order
                #k,v = ip, pkt
maxConnections = 50

#_______FIGURE OUT A WAY TO HAVE A MAX SIZE DICT
def addConn(key,conn):
        
        connections[key] = conn
        if len(connections) > maxConnections:
                maxConnections.popitem(False); #pops the fist item
def checkConnection(pkt):
       pass 
#arbitrary 50 port limit


def process_packet(pkt):
        #TCP Connect scan
        # Connect 18
        # Syn 2
        # Fin 1
        # Ack 16
        if TCP in pkt:
                srcIP = pkt[IP].src
                dstIP = pkt[IP].dst
                srcPrt = pkt[IP].sport
                dstPrt = pkt[IP].dport
                flags = getFlags(pkt)

                key = srcIP

                if key in connections:
                        connection = connections[key]
                        connection.timeStamp = timeStamp(pkt)
                        connection.ports.add(dstPrt)
                if key not in connections:
                        connection = Connection(pkt)
                        addConn(key,connection)
                        print("----------------Adding Connection----------------")
                        print("[+] "+srcIP+":"+str(srcPrt) +" -> "+dstIP+":"+str(dstPrt))
                        print("Flag: "+ str(flags))
               
                        if flags ==0:
                                print("Null")
                        if flags == 1:
                                print("Fin")
                        if flags == 2:
                                print("Syn")
                        if flags == 16:
                                print("Ack")
                        if flags == 18:
                                print("Connect")
                        print("--------------------------------------------------")
                if len(connections[key].ports) >= SCANTHRESHOLD:

                        print("[!]============ Port scan detected============")
                        print(connections[key].src, [p for p in connections[key].ports])
                        print("--------------------------------------------------")

def log(iface=None):
        hostIP = str(socket.gethostbyname(socket.gethostname()))
        filterStr = "ip and dst host "+hostIP
        sniff(filter= filterStr, prn=process_packet, iface = iface)

def main():
        #check if user is root/sudo
        
        if os.geteuid() == 0:
                log()
        else:
                print("[-] Warning: Must run as root.")
                sys.exit()

if __name__ == '__main__':
        main()
 