# ![image](https://github.com/user-attachments/assets/b0e04f46-d7d6-4e3a-b23e-0894857280a8)

## What is StealthLink?
StealthLink is an an advanced anti-forensic tool that is designed to exploit network protocols for covert communication. It leverages a hybrid approach by using HTTP, HTTPS, ICMP and DNS protocols as covert channels to send and receive secret payloads. This tool contains features like segmented payload transmission,, that splits the payload transmission among 4 protocols, and dummy traffic generation, ensuring the payloads are concealed within normal network behaviour.

## How does StealthLink work?
![image](https://github.com/user-attachments/assets/84e2dc8f-979d-493e-88b7-01656d68adf3)

## How to use?
For **BOTH** sender-side and receiver-side:
```
git clone https://github.com/kenantan32/StealthLink.git
```
For **receiver-side: (Important: RUN THIS FIRST)**
1. Run ```receiver.py```
```
sudo python3 receiver.py
```

For **sender-side:**
1. Open ```sender.py``` and change the configuration to match your network environtment, target IP and file path(payload).
```
# Configuration
http_server_ip = "192.168.186.129"  # Replace with the receiver's actual IP
dns_server_ip = "192.168.186.129"  # Replace with the DNS server's actual IP
target_ip = "192.168.186.129"      # Replace with the receiver's actual IP
file_path = "payload.pdf"      # Replace with your actual file path
```

2. Run ```sender.py```
```
sudo python3 sender.py
```
