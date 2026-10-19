from scapy.all import sniff, IP, TCP, UDP, Raw

def process_packet(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        
        # packet contains a Raw application payload
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            
            
            if b"GET" in payload or b"HTTP" in payload or b"Host" in payload:
                print("\n" + "="*50)
                print(f"🚨 [ALERT] UNENCRYPTED HTTP WEB TRAFFIC DETECTED!")
                print(f"    Direction: {src_ip} -> {dst_ip}")
                print(f"    Raw Content: {payload[:200]}") 
                print("="*50 + "\n")
            else:
                # background packets print out 
                print(f"[.] Packet: {src_ip} -> {dst_ip} | Background Data")


def main():
    print("[*] Starting network sniffer... Press Ctrl+C to stop.")
    
   
    try:
       
        sniff(prn=process_packet, store=False)
    except Exception as e:
        print(f"[-] An error occurred: {e}")

if __name__ == "__main__":
    main()

