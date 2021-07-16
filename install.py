import os
import time

if os.getuid() != 0:
    print("Please run as root/administrator.")
    exit(1)

print("Installing packages..")
time.sleep(1)
os.system('pip3 install scapy')
os.system('pip3 install requests')
operating_system = input("What is your OS, Windows or Linux? (w/l):-> ")
if operating_system == 'l':
    print("Installing g++..")
    time.sleep(1)
    os.system('sudo apt install g++')
elif operating_system == 'w':
    print("Please follow these instructions to install g++\nhttp://www.sefidian.com/2020/05/09/installing-g-c-compiler-on-windows/")
