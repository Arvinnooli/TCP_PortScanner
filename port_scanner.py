import socket # for connecting
from colorama import init, Fore

# some colors
init()
GREEN = Fore.GREEN
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

def is_port_open(host, port):
    # creates a new socket
    s = socket.socket()
    try:
        # tries to connect to host using that port
        s.connect((host, port))
        s.close()  # close the socket after successful connection
        return True
    except:
        # cannot connect, port is closed
        # return false
        return False

# get the host and port from the user
host = input("Enter the host:")
port = int(input("Enter the port:"))

if is_port_open(host, port):
    print(f"{GREEN}[+] {host}:{port} is open      {RESET}")
else:
    print(f"{GRAY}[!] {host}:{port} is closed    {RESET}")

