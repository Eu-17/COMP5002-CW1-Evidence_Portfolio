"""
COMP5002 CW1 - Host Identity and HTTP Header Extraction Script (get_host_and_http.py)
Purpose: Parses 'COMP5002 CW1.pcap' to extract the compromised host's physical MAC address,
raw NetBIOS/DHCP hostname broadcasts, and baseline HTTP request/response headers.
"""

from scapy.all import *

# Load the raw network packet capture file into memory
packets = rdpcap('COMP5002 CW1.pcap')

# Initialize sets and lists to store deduplicated host indicators and HTTP streams
mac_map = set()       # Stores unique IP-to-MAC address mappings
nbns_names = set()    # Stores raw NetBIOS Name Service and DHCP payload strings
http_streams = []     # Stores chronological HTTP header lines

# Iterate through every packet in the PCAP file
for pkt in packets:
    
    # 1. Layer-2 / Layer-3 Host Profiling: Map internal IP 172.16.4.193 to its Ethernet MAC address
    if Ether in pkt and IP in pkt:
        if pkt[IP].src == '172.16.4.193':
            mac_map.add(f"IP: {pkt[IP].src} -> MAC: {pkt[Ether].src}")
            
    # 2. Hostname Resolution: Extract raw NetBIOS (UDP ports 137/138) and DHCP (UDP ports 67/68) payloads
    if UDP in pkt and (pkt[UDP].sport in [137, 138, 67, 68] or pkt[UDP].dport in [137, 138, 67, 68]):
        if Raw in pkt:
            # Decode raw bytes using latin-1 to preserve ASCII characters without throwing UTF-8 errors
            raw_nb = pkt[Raw].load.decode('latin-1', errors='ignore')
            nbns_names.add(repr(raw_nb[:120]))
            
    # 3. Layer-7 Web Traffic Inspection: Filter TCP port 80 (HTTP) packets containing raw payload data
    if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and Raw in pkt:
        payload = pkt[Raw].load.decode('latin-1', errors='ignore')
        
        # Split the HTTP payload by carriage return/newline and filter for key forensic headers
        for line in payload.split('\r\n'):
            if any(line.startswith(k) for k in [
                'GET ', 'POST ', 'Host:', 'Referer:', 'User-Agent:', 
                'HTTP/1.1 ', 'Content-Type:', 'Content-Disposition:'
            ]):
                http_streams.append(f"{pkt[IP].src} -> {pkt[IP].dst} | {line}")

# Write the extracted forensic artifacts to a structured text file
with open('host_and_http_evidence.txt', 'w') as f:
    f.write("=== INFECTED HOST MAC ===\n" + "\n".join(mac_map) + "\n\n")
    f.write("=== NETBIOS / DHCP RAW STRINGS ===\n" + "\n".join(list(nbns_names)[:25]) + "\n\n")
    f.write("=== HTTP HEADERS & TIMELINE ===\n" + "\n".join(http_streams[:100]) + "\n")

# Output the saved evidence summary directly to the terminal for verification
print(open('host_and_http_evidence.txt').read())
