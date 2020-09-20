import scapy.all as scapy
import argparse

import RPi.GPIO as GPIO 
from time import sleep
from gpiozero import LED
from time import sleep

import logging

led = LED(YOUR_LED_PIN)#write here your led pin(Raspberry Pi)


print(" _   _      _   _  __")
print("| \ | | ___| |_| |/ /___  ___ _ __   ___ _ __")
print("|  \| |/ _ \ __| ' // _ \/ _ \ '_ \ / _ \ '__|")
print("| |\  |  __/ |_| . \  __/  __/ |_) |  __/ |")
print("|_| \_|\___|\__|_|\_\___|\___| .__/ \___|_|")
print("                             |_|           ")






def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", dest="interface", 
                        help="Your Interface ")
    options = parser.parse_args()
    return options


def get_mac(ip):
  
    return  "YOUR_ROUTER_MAC-ADDRESS" #Write here your router MAC-address

logging.basicConfig(format='%(asctime)s - %(message)s',filename= 'main.log',filemode='a', datefmt='%d-%b-%y %H:%M:%S')# Setting logging parameters


def sniff_packet(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packets)#sniffing network packets


def process_packets(packet):
    if packet.haslayer(scapy.ARP) and packet[scapy.ARP].op == 2:
        try:
            real_mac = get_mac
            responce_mac = packet[scapy.ARP].hwsrc

            if real_mac != responce_mac:              #If real mac isn't equal responce mac - Blink led and log this.
                print("You are under attack!")
                logging.warning('ARP-spoofing detected')
                led.on()
                sleep(0.5)
                led.off()
          
        except IndexError:

            pass


options = get_arguments()
sniff_packet(options.interface)
