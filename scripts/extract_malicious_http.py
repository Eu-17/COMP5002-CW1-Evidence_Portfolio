from scapy.all import *
from datetime import datetime, timezone

packets = rdpcap('COMP5002 CW1.pcap')
out = []
out.append(f"Capture Start UTC: {datetime.fromtimestamp(float(packets[0].time), tz=timezone.utc)}")
out.append("Infected IP: 172.16.4.193 | MAC: 5c:26:0a:02:a8:e4 | NetBIOS Hostname: STEWIE-PC")
out.append("\n=== OUTBOUND HTTP GET/POST REQUESTS (NON-BING/MSN) ===")

seen = set()
for pkt in packets:
    if TCP in pkt and pkt[TCP].dport == 80 and Raw in pkt:
        payload = pkt[Raw].load.decode('latin-1', errors='ignore')
        if payload.startswith(('GET ', 'POST ')):
            if not any(b in payload for b in ['bing.com', 'bing.net', 'msftncsi.com', 'live.com', 'microsoft.com']):
                ts = datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
                lines = [l for l in payload.split('\r\n') if any(l.startswith(k) for k in ['GET ', 'POST ', 'Host:', 'Referer:', 'User-Agent:'])]
                entry = f"[{ts}] {pkt[IP].src} -> {pkt[IP].dst} | " + " || ".join(lines)
                if entry not in seen:
                    seen.add(entry)
                    out.append(entry)

with open('clean_evidence_for_ai.txt', 'w') as f:
    f.write("\n".join(out))

print("\n".join(out))
print(f"\nTotal lines: {len(out)}")
