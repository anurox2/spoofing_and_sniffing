#!/usr/bin/python

## This is a custom traceroute program which has been implemented using the scapy library

# Importing libraries 
from scapy.all import *	# Scapy works directly by looking at packets going through the Network Interface Card the of your computer
import os


# Getting input (URL or IP address) from the user to run the traceroute (No regex involved)
destination = raw_input('Enter a website name or an IP address: ')

# Setting TTL (Time To Live) at 1
ttl = 1

# Printing a simple message to indicate start of the program
print('Running a Traceroute to '+destination)

# Setting a flag
destination_reached = False 

# Master loop to run traceroute
while(destination_reached != True):
  packet_data = sr1(IP(dst=destination, ttl=ttl)/ICMP(id=os.getpid()), verbose=0)	# Pinging the destination
  if(packet_data[ICMP].type == 0):							# Checking the response
    print(str(packet_data.src)+' Reached '+ destination)
    destination_reached = True
  else:
    print("Hop " + str(ttl) +" "+str(packet_data.src))
  ttl += 1										# Increasing TTL for each iteration
