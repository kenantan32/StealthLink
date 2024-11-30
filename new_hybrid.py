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
from flask import Flask, request, jsonify
from scapy.all import IP, ICMP, UDP, Raw, send, sniff
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
dict_lock = threading.Lock()
received_chunks = {}
dns_servers = ["127.0.0.1"]  # Replace with your actual IP
http_server_ip = "192.168.86.132"  # Replace with your actual IP
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

# Split Payload
def split_payload(payload):
    payload_chunks = [payload[i:i + chunk_size] for i in range(0, len(payload), chunk_size)]
    protocols = ['http']  # Use only HTTP initially
    assigned_chunks = {protocol: [] for protocol in protocols}

    for i, chunk in enumerate(payload_chunks):
        protocol = protocols[i % len(protocols)]
        assigned_chunks[protocol].append((i, chunk))
        print(f"[Debug] Assigned chunk index {i} to protocol {protocol}: {chunk}")

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

# Send Payload
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

# Reassemble Payload
def reassemble_payload():
    with dict_lock:
        if received_chunks:
            print(f"[Reassembler] Received chunks: {sorted(received_chunks.keys())}")
            sorted_chunks = [received_chunks[key] for key in sorted(received_chunks.keys())]
            reassembled_payload = b''.join(sorted_chunks)
            print(f"[Reassembler] Reassembled payload (bytes): {reassembled_payload}")
            # Compare with original encrypted payload
            if reassembled_payload == encrypted_payload:
                print("[Reassembler] Reassembled payload matches the original encrypted payload")
            else:
                print("[Reassembler] Reassembled payload does NOT match the original encrypted payload")
            try:
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
                print(f"[Receiver] Final Reassembled and Decrypted Payload: {decrypted_payload}")
            except Exception as e:
                print(f"[Receiver] Error reassembling payload: {e}")
        else:
            print("[Receiver] No chunks received.")

# Main
if __name__ == "__main__":
    target_ip = "192.168.86.132"  # Replace with your actual IP
    # Use random payload to avoid over-compression
    text_payload = generate_random_payload(1500)  # Adjust the length as needed
    encrypted_payload = encrypt_and_compress_payload(text_payload)

    print(f"[Main] Encrypted payload size: {len(encrypted_payload)} bytes")
    assigned_chunks = split_payload(encrypted_payload)

    print("[Main] Starting HTTP server...")
    threading.Thread(target=start_http_server, daemon=True).start()

    time.sleep(2)  # Allow server to initialize

    # Send payload over HTTP
    print("[Main] Sending payload over HTTP...")
    send_http_payload(assigned_chunks['http'], http_server_ip)

    time.sleep(5)  # Allow time for packets to be processed

    print("[Main] Reassembling payload...")
    reassemble_payload()
