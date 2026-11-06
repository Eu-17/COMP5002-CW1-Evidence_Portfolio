"""
COMP5002 CW1 - Targeted Malicious HTTP & Timestamp Extraction (extract_malicious_http.py)
Purpose: Resolves local LLM context-window exhaustion (4,096-token limit) by filtering out
benign Microsoft/Bing baseline traffic (204.79.197.200, msftncsi.com) and server HTTP 200 OK
responses, correlating outbound GET/POST requests with UTC timestamps for AI threat reasoning.
"""

from scapy.all import rdpcap, IP, TCP, Raw
from datetime import datetime, timezone

# Load the raw packet capture file
packets = rdpcap('COMP5002 CW1.pcap')

# Define benign baseline hosts/IPs to exclude from the LLM prompt payload
benign_domains = ['bing.com', 'msftncsi.com', 'microsoft.com', 'live.com']
benign_ips = ['204.79.197.200', '66.152.103.72', '131.253.61.100']

clean_lines = []
seen_requests = set()

# Prepend verified Layer-2 and NetBIOS host identity metadata for the LLM
clean_lines.append("INFECTED HOST: 172.16.4.193 | MAC: 5c:26:0a:02:a8:e4 (Dell) | Hostname: STEWIE-PC")
clean_lines.append("=== CHRONOLOGICAL MALICIOUS HTTP REQUESTS (UTC) ===")

for pkt in packets:
    # Inspect only TCP port 80 (HTTP) packets containing raw application-layer payloads
    if IP in pkt and TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80) and Raw in pkt:
        src = pkt[IP].src
        dst = pkt[IP].dst

        # Skip known benign Microsoft/Bing search and connectivity-check IP addresses
        if src in benign_ips or dst in benign_ips:
            continue

        payload = pkt[Raw].load.decode('latin-1', errors='ignore')
        lines = payload.split('\r\n')
        if not lines:
            continue

        first_line = lines[0]

        # Capture only outbound client HTTP GET and POST requests (strip noisy HTTP/1.1 200 OK responses)
        if first_line.startswith(('GET ', 'POST ')):
            # Convert packet epoch timestamp to human-readable UTC format
            ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

            # Extract critical forensic HTTP headers (Host, Referer, and User-Agent)
            headers = [
                l for l in lines[1:]
                if l.startswith(('Host:', 'Referer:', 'User-Agent:'))
            ]
            header_str = " || ".join(headers)

            # Skip requests destined for benign baseline domains
            if any(b in header_str.lower() for b in benign_domains):
                continue

            # Deduplicate identical consecutive requests while preserving chronological order
            dedup_key = f"{src}->{dst}|{first_line}|{header_str}"
            if dedup_key not in seen_requests:
                seen_requests.add(dedup_key)
                clean_lines.append(f"[{ts}] {src} -> {dst} | {first_line} || {header_str}")

# Save the compressed, high-signal timeline to 'clean_evidence_for_ai.txt'
with open('clean_evidence_for_ai.txt', 'w') as f:
    f.write("\n".join(clean_lines) + "\n")

print(f"Saved clean_evidence_for_ai.txt (Total lines: {len(clean_lines)})")
print("\n".join(clean_lines))
