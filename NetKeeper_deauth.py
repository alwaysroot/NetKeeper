#!/usr/bin/env python


from scapy.all import *
import logging
from scapy.layers.dot11 import Dot11
from scapy.sendrecv import sniff

interface='wlan1mon' # Set your monitor interface.

print(" _   _      _   _  __")
print("| \ | | ___| |_| |/ /___  ___ _ __   ___ _ __")
print("|  \| |/ _ \ __| ' // _ \/ _ \ '_ \ / _ \ '__|")
print("| |\  |  __/ |_| . \  __/  __/ |_) |  __/ |")
print("|_| \_|\___|\__|_|\_\___|\___| .__/ \___|_|")
print("                             |_|           ")

logging.basicConfig(format='%(asctime)s - %(message)s',filename= 'main.log',filemode='a', datefmt='%d-%b-%y %H:%M:%S')



def process_packet(packet):
    if packet.haslayer(Dot11Deauth):
        print(' [ ' +  str(datetime.datetime.now())+ ' ] '+  ' Deauthentication Attack Detected Against Mac Address: ' +   str(packet.addr2).swapcase())
#Running scanner for packet
sniff(iface="wlan1mon", prn=process_packet, store=False, count=0)
