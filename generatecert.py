from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta

# Generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Write the private key to a file
with open("key.pem", "wb") as key_file:
    key_file.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

# Create a self-signed certificate
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My Organization"),
    x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
])

certificate = x509.CertificateBuilder() \
    .subject_name(subject) \
    .issuer_name(issuer) \
    .public_key(private_key.public_key()) \
    .serial_number(x509.random_serial_number()) \
    .not_valid_before(datetime.utcnow()) \
    .not_valid_after(datetime.utcnow() + timedelta(days=365)) \
    .add_extension(
        x509.SubjectAlternativeName([x509.DNSName("localhost")]),
        critical=False
    ) \
    .sign(private_key, hashes.SHA256())

# Write the certificate to a file
with open("cert.pem", "wb") as cert_file:
    cert_file.write(certificate.public_bytes(serialization.Encoding.PEM))

print("Self-signed certificate and key have been generated as 'cert.pem' and 'key.pem'.")
