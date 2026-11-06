"""
COMP5002 CW1 - Initial Automated PCAP Triage Script (analyze_pcap.py)
Purpose: Generated with local LLM assistance (qwen2.5-coder:14b) and manually refined
to extract IP conversation pairs, DNS queries, HTTP GET requests, and non-standard ports
from 'COMP5002 CW1.pcap' into 'pcap_summary.txt'.
"""

from scapy.all import *
from collections import defaultdict

def analyze_pcap(pcap_file, output_file):
    # Load the raw packet capture file into memory using Scapy
    packets = rdpcap(pcap_file)

    # Initialize data structures to aggregate network telemetry
    ip_pairs = defaultdict(int)  # Tracks packet counts per (source_ip, destination_ip) pair
    dns_queries = []             # Stores extracted DNS domain lookups
    http_requests = []           # Stores parsed HTTP GET metadata (URL, User-Agent, Filename)
    unusual_ports = {}           # Counts packets sent to non-standard TCP/UDP destination ports

    # Iterate through each packet in the capture file
    for packet in packets:
        try:
            # 1. Layer-3 IP Conversation Volume Analysis
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_pairs[(src_ip, dst_ip)] += 1

            # 2. Layer-7 DNS Query Extraction (UDP/TCP Port 53 Query Records)
            if DNS in packet and packet[DNS].qd:
                dns_query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                dns_queries.append(f"Query: {dns_query}")

            # 3. Layer-7 HTTP GET Request Inspection (TCP Destination Port 80)
            if TCP in packet and packet[TCP].dport == 80:
                if Raw in packet:
                    raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                    if 'GET ' in raw_data:
                        try:
                            # Extract requested URI path
                            url_start = raw_data.index('GET ') + 4
                            url_end = raw_data.find(' ', url_start)
                            url = raw_data[url_start:url_end]

                            # Extract client browser and OS User-Agent string
                            ua_start = raw_data.find('User-Agent: ') + 12
                            ua_end = raw_data.find('\r\n', ua_start)
                            user_agent = raw_data[ua_start:ua_end]

                            # Extract attachment or payload filename if present in headers
                            filename = None
                            if 'filename=' in raw_data:
                                filename_start = raw_data.find('filename=') + 9
                                filename_end = raw_data.find('\r\n', filename_start)
                                filename = raw_data[filename_start:filename_end]

                            http_requests.append({
                                'URL': url,
                                'User-Agent': user_agent,
                                'Filename': filename
                            })
                        except Exception as e:
                            print(f"Error processing HTTP packet: {e}")

            # 4. Layer-4 Destination Port Filtering (Excluding common standard service ports)
            dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
            if dst_port and dst_port not in [22, 80, 443, 53, 25, 110, 143, 993, 995]:
                unusual_ports[dst_port] = unusual_ports.get(dst_port, 0) + 1

        except Exception as e:
            # Gracefully handle malformed or truncated packets without halting execution
            print(f"Error processing packet: {e}")

    # Write aggregated triage findings to the summary text file
    with open(output_file, 'w') as f:
        f.write("Unique Source and Destination IP Pairs with Packet Counts:\n")
        for (src_ip, dst_ip), count in ip_pairs.items():
            f.write(f"{src_ip} -> {dst_ip}: {count} packets\n")
        f.write("\n")

        f.write("DNS Queries:\n")
        for query in dns_queries:
            f.write(f"{query}\n")
        f.write("\n")

        f.write("HTTP Requests:\n")
        for request in http_requests:
            f.write(f"URL: {request['URL']}\n")
            f.write(f"User-Agent: {request['User-Agent']}\n")
            f.write(f"Filename: {request['Filename'] if request['Filename'] else 'None'}\n")
            f.write("\n")

        f.write("Unusual Destination Ports with Packet Counts:\n")
        for port, count in unusual_ports.items():
            f.write(f"Port {port}: {count} packets\n")

if __name__ == "__main__":
    # Corrected input filename from AI-generated 'COMP5002_CW1.pcap' to 'COMP5002 CW1.pcap'
    analyze_pcap('COMP5002 CW1.pcap', 'pcap_summary.txt')
