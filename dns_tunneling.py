import os
import time
import base64
import hashlib
import threading
from scapy.all import IP, ICMP, send, sniff
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# Configuration
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
received_chunks = {}  # Dictionary to hold received chunks
dict_lock = threading.Lock()  # Lock for thread synchronization

# Encryption function
def encrypt_payload(payload):
    key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
    cipher = AES.new(key, AES.MODE_CBC)  # Use AES in CBC mode
    ct_bytes = cipher.encrypt(pad(payload.encode(), AES.block_size))
    iv = base64.urlsafe_b64encode(cipher.iv).decode().rstrip('=')
    ct = base64.urlsafe_b64encode(ct_bytes).decode().rstrip('=')
    return f"{iv}:{ct}"

# Decryption function
def decrypt_payload(encrypted_payload):
    try:
        key = hashlib.sha256(SECRET_KEY.encode()).digest()  # Derive a 256-bit key from the secret key
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

# ICMP Payload Sender
def send_payload(payload, target_ip):
    # Encrypt the payload before transmission
    encrypted_payload = encrypt_payload(payload)
    # Convert the encrypted payload to hex
    hex_data = encrypted_payload.encode().hex()

    # Split the hex data into smaller chunks (e.g., 56 bytes per ICMP packet)
    chunk_size = 56
    for i in range(0, len(hex_data), chunk_size):
        chunk = hex_data[i:i + chunk_size]
        packet = IP(dst=target_ip) / ICMP(type=8, seq=i // chunk_size) / bytes.fromhex(chunk)  # send raw hex as bytes
        send(packet, verbose=False)
        print(f"[Sender] Sent packet with chunk: {chunk}")

# Packet Sniffer and Reassembler
def packet_sniffer():
    def icmp_sniffer(packet):
        if packet.haslayer(ICMP) and packet[ICMP].type == 8 and packet.haslayer(Raw):  # ICMP Echo Request
            try:
                payload_data = packet[Raw].load.hex()
                seq_num = packet[ICMP].seq

                print(f"[Sniffer] ICMP packet received with sequence number {seq_num}")

                with dict_lock:
                    received_chunks[seq_num] = payload_data
                    print(f"[Sniffer] ICMP chunk received: {payload_data}")
                    print(f"[Sniffer] Current received chunks: {received_chunks}")

                    # Reassemble and decrypt payload
                    reassembled_payload = ''.join([received_chunks[key] for key in sorted(received_chunks.keys())])
                    reassembled_text = bytes.fromhex(reassembled_payload).decode(errors='ignore')
                    decrypted_payload = decrypt_payload(reassembled_text)
                    print(f"[Receiver] Reassembled and Decrypted Payload: {decrypted_payload}")

            except Exception as e:
                print(f"[Sniffer] Error decoding ICMP packet: {e}")

    # Start sniffing ICMP packets
    interface = "lo"  # Use the loopback interface for local testing
    sniff(filter="icmp", prn=icmp_sniffer, store=0, iface=interface)

# Run ICMP Tunneling
if __name__ == "__main__":
    target_ip = "127.0.0.1"
    text_payload = "This is a hardcoded ICMP payload."

    # Start the sniffer thread
    print("[Main] Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=packet_sniffer)
    sniffer_thread.daemon = True
    sniffer_thread.start()

    # Give the sniffer some time to initialize
    time.sleep(2)
    print("[Main] Sniffer thread started. Sending payload...")

    # Send the payload
    send_payload(text_payload, target_ip)

    print("[Main] Payload transmission complete.")
