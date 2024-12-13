import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Keys import generate_passphrase, generate_rsa_keys


def generate_certificate(name, email, matriclenr):
    dest = os.path.join(script_dir, "data")
    if not os.path.exists(dest):
        os.makedirs(dest)

    common_name = f"cert_{matriclenr}"
    passphrase, passphrase_path = generate_passphrase(dest, common_name)
    private_key, public_key, private_key_path, public_key_path = generate_rsa_keys(
        passphrase, dest, common_name
    )

    return True, None
