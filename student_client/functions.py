import os
import sys
from cryptography.hazmat.primitives import hashes, serialization

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Keys import generate_passphrase, generate_rsa_keys
from certificates.Certificate import generate_certificate_request_builder


def generate_certificate_request(name: str, email: str, matriclenr: int) -> bytes:
    dest = os.path.join(script_dir, "data")
    if not os.path.exists(dest):
        os.makedirs(dest)

    common_name = f"{"".join(name.split())}_{matriclenr}"
    passphrase, passphrase_path = generate_passphrase(dest, common_name)
    private_key, public_key, private_key_path, public_key_path = generate_rsa_keys(
        passphrase, dest, common_name
    )

    cert_request = generate_certificate_request_builder(
        country_code="DE",
        common_name=common_name,
        organization_name="HSHL",
        organizational_unit_name="IT-Security",
    ).sign(private_key, hashes.SHA256())

    request_bytes = cert_request.public_bytes(encoding=serialization.Encoding.PEM)

    return request_bytes
