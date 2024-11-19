import os
import random
import string
import time
import hashlib
import threading
import zlib
import datetime
import base64
import uuid
from scapy.all import IP, ICMP, UDP, TCP, DNS, DNSQR, send, sniff, conf, Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# Configuration
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
received_chunks_icmp = {}  # Dictionary to hold received ICMP chunks
received_chunks_dns = {}   # Dictionary to hold received DNS chunks
stop_sniffer = threading.Event()  # Event to signal the sniffer to stop
dict_lock = threading.Lock()  # Lock for thread-safe access to received_chunks
DNS_DOMAIN = "example.com"  # Example domain for DNS queries
dns_servers = ["8.8.8.8", "8.8.4.4"]  # Public DNS servers for testing
HTTP_SERVER_IP = "127.0.0.1"  # Localhost for testing HTTP dummy traffic
salt = get_random_bytes(16) # Salt generation

# Encryption and Compression function
def encrypt_and_compress_payload(payload):
    # Compress the payload
    compressed_payload = zlib.compress(payload.encode())
    # Encrypt the compressed payload
    key = PBKDF2(SECRET_KEY, salt, dkLen=32, count=1000000)  # Generate a 256-bit PBKDF2-based key with a high iteration count
    #key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(compressed_payload, AES.block_size))
    return cipher.iv + ct_bytes

# Decryption and Decompression function
def decrypt_and_decompress_payload(encrypted_payload):
    try:
        key = PBKDF2(SECRET_KEY, salt, dkLen=32, count=1000000)  # Generate a 256-bit PBKDF2-based key with a high iteration count
        #key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
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

# Generate Encrypted Identifier
def generate_encrypted_identifier():
    # Generate a fixed-length UUID string
    plaintext_id = str(uuid.uuid4())  # 36 characters
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext_id.encode(), AES.block_size))
    identifier = cipher.iv + ct_bytes
    return identifier

# Dummy Traffic Sender
def send_dummy_traffic():
    while not stop_sniffer.is_set():
        # Decide randomly which dummy traffic to send
        traffic_type = random.choice(['icmp', 'dns', 'http', 'https'])
        if traffic_type == 'icmp':
            send_dummy_icmp()
        elif traffic_type == 'dns':
            send_dummy_dns()
        elif traffic_type == 'http':
            send_dummy_http()
        elif traffic_type == 'https':
            send_dummy_https()
        # Random sleep to mimic human behavior
        time.sleep(random.uniform(0.5, 2))

# Dummy ICMP Traffic Sender
def send_dummy_icmp():
    target_ip = random.choice(['8.8.8.8', '1.1.1.1'])
    # Generate realistic ICMP echo request
    dummy_payload = os.urandom(random.randint(32, 64))  # Random binary data
    sequence_number = random.randint(0, 65535)
    ttl_value = random.randint(30, 128)
    packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type='echo-request', seq=sequence_number) / Raw(load=dummy_payload)
    send(packet, verbose=False)
    print(f"[Dummy ICMP] Sent dummy ICMP echo request to {target_ip}")

# Dummy DNS Traffic Sender
def send_dummy_dns():
    # Use real domain names
    domain = random.choice(['google.com', 'facebook.com', 'amazon.com', 'github.com'])
    dns_server = random.choice(dns_servers)
    packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    send(packet, verbose=False)
    print(f"[Dummy DNS] Sent dummy DNS query for {domain} to {dns_server}")

# Dummy HTTP Traffic Sender
def send_dummy_http():
    # Generate a simple HTTP GET request
    host = random.choice(['example.com', 'test.com', 'mywebsite.com'])
    path = random.choice(['/index.html', '/about', '/contact'])
    http_payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DummyAgent\r\n\r\n".encode()
    target_ip = HTTP_SERVER_IP
    packet = IP(dst=target_ip) / TCP(dport=80, sport=random.randint(1024, 65535), flags='S') / Raw(load=http_payload)
    send(packet, verbose=False)
    print(f"[Dummy HTTP] Sent dummy HTTP GET request to {host}{path}")

# Dummy HTTPS Traffic Sender
def send_dummy_https():
    # Generate a simple HTTPS Client Hello (simulated)
    host = random.choice(['secure.com', 'bank.com', 'login.com'])
    tls_payload = os.urandom(random.randint(64, 128))  # Random binary data to simulate TLS handshake
    target_ip = HTTP_SERVER_IP
    packet = IP(dst=target_ip) / TCP(dport=443, sport=random.randint(1024, 65535), flags='S') / Raw(load=tls_payload)
    send(packet, verbose=False)
    print(f"[Dummy HTTPS] Sent dummy HTTPS Client Hello to {host}")

# ICMP Payload Sender with Enhanced Dummy Traffic
def send_icmp_payload_with_dummy(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        sequence_number = random.randint(0, 65535)
        ttl_value = random.randint(30, 128)

        # Generate encrypted identifier
        identifier = generate_encrypted_identifier()
        identifier_length = len(identifier)

        # Include the chunk index (4 bytes) in the payload
        chunk_index = i.to_bytes(4, byteorder='big')

        # Construct the packet payload: identifier length (4 bytes) + identifier + chunk index (4 bytes) + chunk
        packet_payload = identifier_length.to_bytes(4, byteorder='big') + identifier + chunk_index + chunk

        # Send the actual payload packet
        packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type='echo-request', seq=sequence_number) / Raw(load=packet_payload)
        send(packet, verbose=False)
        print(f"[Sender - ICMP] Sent payload packet with sequence number {sequence_number}")
        print(f"[Sender - ICMP] Sending chunk index {i}, chunk: {chunk}")

        # Sleep for a realistic time before sending next packet
        time.sleep(random.uniform(0.5, 1.5))

# DNS Payload Sender with Enhanced Dummy Traffic
def send_dns_payload_with_dummy(payload):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        # Generate encrypted identifier
        identifier = generate_encrypted_identifier()
        identifier_length = len(identifier)

        # Include the chunk index (4 bytes) in the payload
        chunk_index = i.to_bytes(4, byteorder='big')

        # Encode the identifier to Base64 for use in the domain name
        identifier_b64 = base64.urlsafe_b64encode(identifier).decode().rstrip('=')

        query_domain = f"{identifier_b64}.{DNS_DOMAIN}"
        dns_server = random.choice(dns_servers)

        # Include the identifier length and chunk index in the packet payload
        packet_payload = identifier_length.to_bytes(4, byteorder='big') + identifier + chunk_index + chunk

        # Send the actual payload packet
        packet = IP(dst="127.0.0.1") / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain)) / Raw(load=packet_payload)
        send(packet, verbose=False)
        print(f"[Sender - DNS] Sent payload DNS query: {query_domain}")
        print(f"[Sender - DNS] Sending chunk index {i}, chunk: {chunk}")

        # Sleep for a realistic time before sending next packet
        time.sleep(random.uniform(0.5, 1.5))

# Packet Sniffer and Reassembler
def packet_sniffer():
    def icmp_sniffer(packet):
        if stop_sniffer.is_set():
            return

        if packet.haslayer(ICMP) and packet.haslayer(Raw):
            try:
                payload_data = packet[Raw].load
                seq_num = packet[ICMP].seq

                # Extract identifier length
                identifier_length = int.from_bytes(payload_data[:4], byteorder='big')
                # Extract the encrypted identifier
                identifier = payload_data[4:4 + identifier_length]
                # Extract the chunk index
                index_start = 4 + identifier_length
                chunk_index = int.from_bytes(payload_data[index_start:index_start+4], byteorder='big')
                # Extract the actual payload chunk
                actual_payload = payload_data[index_start + 4:]

                # Decrypt the identifier
                key = hashlib.sha256(SECRET_KEY.encode()).digest()
                iv = identifier[:16]
                ct = identifier[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext_id = unpad(cipher.decrypt(ct), AES.block_size).decode()

                # If decryption is successful, it's a payload packet
                with dict_lock:
                    if chunk_index not in received_chunks_icmp:
                        received_chunks_icmp[chunk_index] = actual_payload
                        print(f"[Sniffer - ICMP] Payload packet received with sequence number {seq_num}, chunk index {chunk_index}")
                        print(f"[Sniffer - ICMP] Stored payload chunk: {actual_payload}")
                    else:
                        print(f"[Sniffer - ICMP] Duplicate packet with chunk index {chunk_index} ignored.")
            except Exception as e:
                # This is likely a dummy packet
                pass  # Optionally, print debug information

    def dns_sniffer(packet):
        if stop_sniffer.is_set():
            return

        if packet.haslayer(DNS) and packet.haslayer(Raw):
            try:
                query_name = packet[DNS].qd.qname.decode().strip('.')
                # Extract the Base64-encoded identifier from the subdomain
                subdomain = query_name.split('.')[0]
                # Add padding for base64 decoding
                missing_padding = len(subdomain) % 4
                if missing_padding:
                    subdomain += '=' * (4 - missing_padding)
                encrypted_identifier = base64.urlsafe_b64decode(subdomain.encode())

                # Extract identifier length
                payload_data = packet[Raw].load
                identifier_length = int.from_bytes(payload_data[:4], byteorder='big')
                # Extract the encrypted identifier
                identifier = payload_data[4:4 + identifier_length]
                # Extract the chunk index
                index_start = 4 + identifier_length
                chunk_index = int.from_bytes(payload_data[index_start:index_start+4], byteorder='big')
                # Extract the actual payload chunk
                actual_payload = payload_data[index_start + 4:]

                # Decrypt the identifier
                key = hashlib.sha256(SECRET_KEY.encode()).digest()
                iv = identifier[:16]
                ct = identifier[16:]
                cipher = AES.new(key, AES.MODE_CBC, iv)
                plaintext_id = unpad(cipher.decrypt(ct), AES.block_size).decode()

                with dict_lock:
                    if chunk_index not in received_chunks_dns:
                        received_chunks_dns[chunk_index] = actual_payload
                        print(f"[Sniffer - DNS] Payload DNS query received: {query_name}, chunk index {chunk_index}")
                        print(f"[Sniffer - DNS] Stored payload chunk: {actual_payload}")
                    else:
                        print(f"[Sniffer - DNS] Duplicate packet with chunk index {chunk_index} ignored.")
            except Exception as e:
                # This is likely a dummy packet
                pass  # Optionally, print debug information

    # Start sniffing packets
    def process_packet(pkt):
        icmp_sniffer(pkt)
        dns_sniffer(pkt)

    # Use the interface name that was working for you
    sniff(filter="icmp or udp port 53 or tcp port 80 or tcp port 443",
          prn=process_packet,
          store=0,
          iface="lo",  # Using the original interface name
          stop_filter=lambda x: stop_sniffer.is_set())

# Run Payload Transmission
if __name__ == "__main__":
    target_ip = "127.0.0.1"
    text_payload = "This is my hardcoded payload that I am tunneling over."

    # Encrypt and compress the payload before transmission
    encrypted_payload = encrypt_and_compress_payload(text_payload)
    print(f"[Main] Original Encrypted Payload Length: {len(encrypted_payload)}")

    # Start the sniffer thread
    print("[Main] Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=packet_sniffer, daemon=True)
    sniffer_thread.start()

    # Start the dummy traffic sender thread
    print("[Main] Starting dummy traffic thread...")
    dummy_thread = threading.Thread(target=send_dummy_traffic, daemon=True)
    dummy_thread.start()

    # Give the sniffer and dummy traffic threads time to initialize
    time.sleep(2)
    print("[Main] Threads started. Sending payload with enhanced dummy traffic...")

    # Send the payload via ICMP with enhanced dummy traffic
    send_icmp_payload_with_dummy(encrypted_payload, target_ip)
    # Optionally, send the payload via DNS with enhanced dummy traffic
    send_dns_payload_with_dummy(encrypted_payload)

    print("[Main] Payload transmission complete.")

    # Wait to ensure all packets are processed
    time.sleep(20)

    # Signal the sniffer and dummy traffic to stop
    stop_sniffer.set()

    # Attempt to reassemble and decrypt the ICMP payload after sending is complete
    with dict_lock:
        if received_chunks_icmp:
            try:
                # Sort the chunks based on their chunk index
                sorted_chunks = [received_chunks_icmp[key] for key in sorted(received_chunks_icmp.keys())]
                reassembled_payload = b''.join(sorted_chunks)
                print(f"[Debug - ICMP] Reassembled Payload Length: {len(reassembled_payload)}")
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
                print(f"[Receiver - ICMP] Final Reassembled and Decrypted Payload: {decrypted_payload}")
            except Exception as e:
                print(f"[Receiver - ICMP] Error reassembling or decrypting payload: {e}")
        else:
            print("[Receiver - ICMP] No ICMP packets were received.")

    # Attempt to reassemble and decrypt the DNS payload after sending is complete
    with dict_lock:
        if received_chunks_dns:
            try:
                sorted_chunks = [received_chunks_dns[key] for key in sorted(received_chunks_dns.keys())]
                reassembled_payload = b''.join(sorted_chunks)
                print(f"[Debug - DNS] Reassembled Payload Length: {len(reassembled_payload)}")
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
                print(f"[Receiver - DNS] Final Reassembled and Decrypted Payload: {decrypted_payload}")
            except Exception as e:
                print(f"[Receiver - DNS] Error reassembling or decrypting payload: {e}")
        else:
            print("[Receiver - DNS] No DNS packets were received.")

    # Wait for the threads to finish
    sniffer_thread.join(timeout=5)
    dummy_thread.join(timeout=5)

    print("[Main] Threads have been stopped. Exiting program.")
