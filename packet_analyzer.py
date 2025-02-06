"""
How to run the script:

1. Basic usage with a PCAP file:
   python3 packet_analyzer.py /path/to/capture.pcap
   (Replace "/path/to/capture.pcap" with the actual path to your PCAP file.)

2. Running with a PCAP file in the current directory:
   python3 packet_analyzer.py capture.pcap
   (This assumes the capture.pcap file is in the same directory as the script.)

3. Running with a log level (DEBUG) and saving output to a file (output.log):
   python3 packet_analyzer.py capture.pcap -l DEBUG -o output.log
   (This sets the log level to DEBUG and saves logs to output.log.)
"""



import logging
import argparse
from scapy.all import rdpcap, IP, TCP, UDP, DNS
from scapy.layers.http import HTTPRequest, HTTPResponse

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

def analyze_ip_packet(packet):
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

    logger.info(f"Sumber IP: {ip_src} | Tujuan IP: {ip_dst} | Protokol: {proto} | Port Sumber: {sport} | Port Tujuan: {dport}")
    return packet, ip_src, ip_dst, proto, sport, dport

def analyze_http(packet):
    if HTTPRequest in packet:
        method = packet[HTTPRequest].Method.decode("utf-8")
        host = packet[HTTPRequest].Host.decode("utf-8")
        logger.info(f"  HTTP Request: {method} {host}")
        if hasattr(packet[HTTPRequest], "Cookie"):
            logger.info(f"    Cookies: {packet[HTTPRequest].Cookie.decode('utf-8')}")
    if HTTPResponse in packet:
        status_code = packet[HTTPResponse].Status
        logger.info(f"  HTTP Response Status: {status_code}")

def analyze_dns(packet):
    if DNS in packet:
        if packet.haslayer("DNSQR"):
            qname = packet["DNSQR"].qname.decode("utf-8")
            logger.info(f"   DNS Query: {qname}")
        if packet.haslayer("DNSRR"):
            for i, dnsrr in enumerate(packet["DNSRR"]):
                if dnsrr.type == 1:
                    logger.info(f"   DNS Answer: {dnsrr.rdata}")

def analyze_packet(packet):
    try:
        if IP in packet:
            packet, ip_src, ip_dst, proto, sport, dport = analyze_ip_packet(packet)
            analyze_http(packet)
            analyze_dns(packet)
    except Exception as e:
        logger.error(f"Failed to analyze packet: {e}")

def process_pcap(pcap_file):
    try:
        packets = rdpcap(pcap_file)
        logger.info(f"Processing {len(packets)} packets from {pcap_file}")
        for packet in packets:
            analyze_packet(packet)
    except Exception as e:
        logger.error(f"Error processing PCAP file: {e}")

def main():
    parser = argparse.ArgumentParser(description="Packet Analyzer")
    parser.add_argument("pcap_file", help="Path to the PCAP file")
    parser.add_argument("-l", "--log", choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                        default="INFO", help="Set the logging level")
    parser.add_argument("-o", "--output", help="Output file to save the results")
    args = parser.parse_args()

    logger.setLevel(args.log.upper())

    pcap_file = args.pcap_file
    output_file = args.output

    if output_file:
        file_handler = logging.FileHandler(output_file)
        file_handler.setLevel(args.log.upper())
        file_handler.setFormatter(logging.Formatter("%(asctime)s - %(levelname)s - %(message)s"))
        logger.addHandler(file_handler)

    process_pcap(pcap_file)

if __name__ == "__main__":
    main()
