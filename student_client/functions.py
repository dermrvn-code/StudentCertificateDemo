import os
import sys
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Keys import generate_passphrase, generate_rsa_keys
from certificates.Certificate import generate_certificate_request_builder


def generate_certificate_request(name: str, matriclenr: int) -> bytes:
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


def upload_certificate():
    dest = os.path.join(script_dir, "data")
    if not os.path.exists(dest):
        os.makedirs(dest)

    open_path = filedialog.askopenfilename(
        defaultextension=".crt",
        filetypes=[("Zertifikat", "*.crt"), ("Alle Dateien", "*.*")],
        title="Hochladen",
    )

    if open_path:
        dest_path = os.path.join(dest, "cert.cert")
        with open(open_path, "rb") as src_file:
            with open(dest_path, "wb") as dest_file:
                dest_file.write(src_file.read())
        messagebox.showinfo(title="Erfolgreich", message="Zertifikat hochgeladen!")
