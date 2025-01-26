"""
How to run:

Basic usage:
python3 sniffer_network.py -i <interface>

Example 1: Sniff packets on interface 'eth0':
python3 sniffer_network.py -i eth0

Example 2: Sniff packets on interface 'enp0s3':
python3 sniffer_network.py -i enp0s3

Optional arguments:
  -c, --count <number>    Number of packets to sniff (default: unlimited)
  -f, --filter <BPF>      Apply a BPF filter to sniff specific packets (e.g., "tcp", "port 80")

Examples with optional arguments:
1. Sniff packets on interface 'wlan0', limited to 100 packets:
   python3 sniffer_network.py -i wlan0 -c 100

2. Sniff TCP packets on interface 'eth0':
   python3 sniffer_network.py -i eth0 -f "tcp"

3. Sniff packets on port 80 using interface 'wlan0':
   python3 sniffer_network.py -i wlan0 -f "port 80"

Notes:
- Replace `<interface>` with the name of the network interface (e.g., eth0, wlan0, lo, etc.).
- Use `ifconfig` or `ip link show` to check available network interfaces.
- Run the script with `sudo` for permission to sniff network traffic:
  sudo python3 sniffer_network.py -i eth0
"""


from scapy.all import sniff, IP, TCP, UDP
import argparse

def packet_callback(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = "Unknown"
        sport = "Unknown"
        dport = "Unknown"

        if TCP in packet:
            proto = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
        elif UDP in packet:
            proto = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport

        print(f"IP src: {ip_src} | To: {ip_dst} | Protocol: {proto} | Source Port: {sport} | Destination Port: {dport}")

def main():
    parser = argparse.ArgumentParser(description="Network Sniffer")
    parser.add_argument("ip", help="IP address to monitor (example: 127.0.0.1)", nargs="?", default=None)
    parser.add_argument("-i", "--interface", help="Interface to sniff on (example: eth0, wlan0)", required=True)
    parser.add_argument("-c", "--count", type=int, help="Number of packets to capture (0 for unlimited)", default=0)
    parser.add_argument("-f", "--filter", help="BPF filter for packets", default="")
    args = parser.parse_args()

    ip = args.ip
    iface = args.interface
    count = args.count
    filter_ = args.filter

    if ip:
        print(f"[INFO] Monitoring IP: {ip}")

    try:
        print(f"[INFO] Starting sniffer on interface: {iface}")
        sniff(iface=iface, prn=packet_callback, count=count, filter=filter_)
    except Exception as e:
        print(f"[ERROR] {e}")

    print("[INFO] Sniffer completed")


if __name__ == "__main__":
    main()
