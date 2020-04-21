# Detect portscans of host, automatically blacklist addresses that scan and runs connecting addresses to see if they were similar to blacklisted

from scapy.all import *
import os
import sys
from datetime import datetime
def timeStamp():
        return "{:%Y-%b-%d %H:%M:%S}".format(datetime.datetime.now())
class Packet:
        src = None
        dst = None
        sport = None
        dport = None
        timeStamp = None
        flags = None
        



def getFlags(pkt):
        F = pkt[TCP].flags
        return F

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
                print("[+] "+srcIP+":"+str(srcPrt) +" -> "+dstIP+":"+str(dstPrt))
                print("Flag: "+ str(flags))
                if flags == 18:
                        print("Connect")
                if flags == 2:
                        print("Syn")
                if flags == 1:
                        print("Fin")
                if flags == 16:
                        print("Ack")
        pass

def log(iface=None):
        sniff(filter="ip",prn=process_packet, iface = iface)

def main():
        #check if user is root/sudo
        if os.geteuid() == 0:
                log()
        else:
                print("[-] Warning: Must run as root.")
                sys.exit()

if __name__ == '__main__':
        main()
