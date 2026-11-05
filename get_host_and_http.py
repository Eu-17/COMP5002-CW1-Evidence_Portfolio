from scapy.all import *

packets = rdpcap('COMP5002 CW1.pcap')
mac_map = set()
nbns_names = set()
http_streams = []

for pkt in packets:
    if Ether in pkt and IP in pkt:
        if pkt[IP].src == '172.16.4.193':
            mac_map.add(f"IP: {pkt[IP].src} -> MAC: {pkt[Ether].src}")
    if UDP in pkt and (pkt[UDP].sport in [137, 138, 67, 68] or pkt[UDP].dport in [137, 138, 67, 68]):
        if Raw in pkt:
            raw_nb = pkt[Raw].load.decode('latin-1', errors='ignore')
            nbns_names.add(repr(raw_nb[:120]))
    if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and Raw in pkt:
        payload = pkt[Raw].load.decode('latin-1', errors='ignore')
        for line in payload.split('\r\n'):
            if any(line.startswith(k) for k in ['GET ', 'POST ', 'Host:', 'Referer:', 'User-Agent:', 'HTTP/1.1 ', 'Content-Type:', 'Content-Disposition:']):
                http_streams.append(f"{pkt[IP].src} -> {pkt[IP].dst} | {line}")

with open('host_and_http_evidence.txt', 'w') as f:
    f.write("=== INFECTED HOST MAC ===\n" + "\n".join(mac_map) + "\n\n")
    f.write("=== NETBIOS / DHCP RAW STRINGS ===\n" + "\n".join(list(nbns_names)[:25]) + "\n\n")
    f.write("=== HTTP HEADERS & TIMELINE ===\n" + "\n".join(http_streams[:100]) + "\n")

print(open('host_and_http_evidence.txt').read())
