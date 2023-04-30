import socket
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scapy.all import *
from colorama import init, Fore

init(autoreset=True)

GREEN = Fore.GREEN
RED = Fore.RED
RESET = Fore.RESET
GRAY = Fore.LIGHTBLACK_EX

def tcp_scan(host, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        s.connect((host, port))
        s.shutdown(socket.SHUT_RDWR)
        return True
    except:
        return False

def udp_scan(host, port):
    try:
        pkt = IP(dst=host)/UDP(dport=port)
        response = sr1(pkt, timeout=2, verbose=0)
        if response:
            return True
        else:
            return False
    except:
        return False

def syn_scan(host, port):
    try:
        pkt = IP(dst=host)/TCP(dport=port, flags="S")
        response = sr1(pkt, timeout=2, verbose=0)
        if response:
            flags = response.getlayer(TCP).flags
            if flags == 0x12:
                return True
            else:
                return False
        else:
            return False
    except:
        return False

def fin_scan(host, port):
    try:
        pkt = IP(dst=host)/TCP(dport=port, flags="F")
        response = sr1(pkt, timeout=2, verbose=0)
        if response:
            flags = response.getlayer(TCP).flags
            if flags == 0x14:
                return False
            else:
                return True
        else:
            return True
    except:
        return True

def port_scan(host, ports, scan_type):
    open_ports = []
    start_time = time.time()
    if scan_type == "TCP":
        for port in ports:
            if tcp_scan(host, port):
                open_ports.append(port)
    elif scan_type == "UDP":
        for port in ports:
            if udp_scan(host, port):
                open_ports.append(port)
    elif scan_type == "SYN":
        for port in ports:
            if syn_scan(host, port):
                open_ports.append(port)
    elif scan_type == "FIN":
        for port in ports:
            if fin_scan(host, port):
                open_ports.append(port)
    end_time = time.time()
    return (open_ports, end_time - start_time)

def export_results(data):
    df = pd.DataFrame(data)
    df.to_csv("scan_results.csv", index=False)



def main():
    host = input("Enter the host:")
    start_port = int(input("Enter the start port:"))
    end_port = int(input("Enter the end port:"))
    ports = range(start_port, end_port + 1)
    scan_types = ["TCP", "UDP", "SYN", "FIN"]
    results = []
    for scan_type in scan_types:
        open_ports, time_taken = port_scan(host, ports, scan_type)
        results.append({"Scan Type": scan_type, "Open Ports": len(open_ports), "Time Taken (s)": time_taken})

    # Display results
    print(f"\nResults for host: {host}")
    print("-" * 30)
    print(f"Scan Type\tOpen Ports\tTime Taken (s)")
    print("-" * 30)
    for result in results:
        print(f"{result['Scan Type']}\t\t{result['Open Ports']}\t\t{result['Time Taken (s)']:.2f}")
        export_results(results)


# Export results to a CSV file

def export_results(results):
    df = pd.DataFrame(results)
    df.to_csv("scan_results.csv", index=False)
    print("Scan results exported to scan_results.csv")

if __name__ == "__main__":
    main()


