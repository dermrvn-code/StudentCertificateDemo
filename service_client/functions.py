import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Certificate import (
    load_request_from_bytes,
    generate_certificate_builder,
)
from certificates.CA import load_ca, sign_certificate
from cryptography.hazmat.primitives import serialization


def generate_certificate(request: bytes):
    cert_folder = os.path.join(script_dir, "certs")
    ca_cert, ca_key = load_ca(
        os.path.join(cert_folder, "ca_cacampusofficehshl.crt"),
        os.path.join(cert_folder, "ca_private_cacampusofficehshl.key"),
        os.path.join(cert_folder, "passphrase_cacampusofficehshl.txt"),
    )
    csr = load_request_from_bytes(request)
    print(csr)

    cert = generate_certificate_builder(csr, ca_cert=ca_cert)
    cert = sign_certificate(ca_cert, ca_key, cert)

    cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)

    # temp_folder = os.path.join(script_dir, "temp")
    # os.makedirs(temp_folder, exist_ok=True)
    # cert_path = os.path.join(temp_folder, "generated_certificate.pem")
    # with open(cert_path, "wb") as cert_file:
    #     cert_file.write(cert_bytes)

    return cert_bytes
