from scapy.all import *
from collections import defaultdict

def analyze_pcap(pcap_file, output_file):
    packets = rdpcap(pcap_file)
    
    ip_pairs = defaultdict(int)
    dns_queries = []
    http_requests = []
    unusual_ports = {}

    for packet in packets:
        try:
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                ip_pairs[(src_ip, dst_ip)] += 1

                if DNS in packet and packet[DNS].qd:
                    dns_query = packet[DNS].qd.qname.decode('utf-8', errors='ignore')
                    dns_queries.append(f"Query: {dns_query}")

                if TCP in packet and (packet[TCP].dport == 80 or packet[TCP].sport == 80):
                    if Raw in packet:
                        raw_data = packet[Raw].load.decode('utf-8', errors='ignore')
                        if 'GET ' in raw_data or 'POST ' in raw_data or 'HTTP/' in raw_data:
                            try:
                                url_start = raw_data.find('GET ') + 4 if 'GET ' in raw_data else 0
                                url_end = raw_data.find(' ', url_start)
                                url = raw_data[url_start:url_end] if url_start > 0 else "HTTP Response/Data"

                                ua_start = raw_data.find('User-Agent: ') + 12
                                ua_end = raw_data.find('\r\n', ua_start)
                                user_agent = raw_data[ua_start:ua_end] if 'User-Agent: ' in raw_data else "N/A"

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

                dst_port = packet[TCP].dport if TCP in packet else packet[UDP].dport if UDP in packet else None
                if dst_port and dst_port not in [22, 80, 443, 53, 25, 110, 143, 993, 995]:
                    unusual_ports[dst_port] = unusual_ports.get(dst_port, 0) + 1

        except Exception as e:
            print(f"Error processing packet: {e}")

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
    analyze_pcap('COMP5002 CW1.pcap', 'pcap_summary.txt')
