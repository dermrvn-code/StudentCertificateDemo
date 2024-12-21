import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Certificate import (
    load_request_from_bytes,
    generate_certificate_builder,
    save_cert_to_file,
)
from certificates.CA import load_ca, sign_certificate
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID


def generate_certificate(request: bytes):
    cert_folder = os.path.join(script_dir, "certs")
    ca_cert, ca_key = load_ca(
        os.path.join(cert_folder, "ca_cacampusofficehshl.crt"),
        os.path.join(cert_folder, "ca_private_cacampusofficehshl.key"),
        os.path.join(cert_folder, "passphrase_cacampusofficehshl.txt"),
    )
    csr = load_request_from_bytes(request)

    cert = generate_certificate_builder(csr, ca_cert=ca_cert)
    cert = sign_certificate(ca_cert, ca_key, cert)

    cert_bytes = cert.public_bytes(encoding=serialization.Encoding.PEM)

    save_path = os.path.join(script_dir, "student_certs")
    common_name = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    save_cert_to_file(cert, save_path, common_name=common_name)

    return cert_bytes
