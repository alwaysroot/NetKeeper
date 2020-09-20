#!/usr/bin/env python


from scapy.all import *
import logging
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

interface='YOUR_MON_INTERFACE' # Set your monitor interface.

print(" _   _      _   _  __")
print("| \ | | ___| |_| |/ /___  ___ _ __   ___ _ __")
print("|  \| |/ _ \ __| ' // _ \/ _ \ '_ \ / _ \ '__|")
print("| |\  |  __/ |_| . \  __/  __/ |_) |  __/ |")
print("|_| \_|\___|\__|_|\_\___|\___| .__/ \___|_|")
print("                             |_|           ")

logging.basicConfig(format='%(asctime)s - %(message)s',filename= 'main.log',filemode='a', datefmt='%d-%b-%y %H:%M:%S')



# set Packet Counter 
Packet_Counter = 1

# extract  packet 
def info(packet):
    if packet.haslayer(Dot11):
        # The packet.subtype==12  indicates  deauth frame
        if ((packet.type == 0) & (packet.subtype==12)):
            global Packet_Counter
            logging.warning('Deauth-attack detected.')
            print ("[!]Deauthentication Packet detected ", Packet_Counter)
            Packet_Counter = Packet_Counter + 1



sniff(iface=interface,prn=info)

