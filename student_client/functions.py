import base64
import hashlib
import os
import sys
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Keys import (
    generate_passphrase,
    generate_rsa_keys,
    load_passphrase_from_path,
    load_private_key_from_path,
)
from certificates.Certificate import (
    generate_certificate_request_builder,
    load_certificate_from_path,
)


def generate_certificate_request(name: str, matriclenr: int) -> bytes:
    dest = os.path.join(script_dir, "data")
    if not os.path.exists(dest):
        os.makedirs(dest)

    common_name = f"{"-".join(name.split())}_{matriclenr}"
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
        filetypes=[("Zertifikat", "*.crt")],
        title="Hochladen",
    )

    if open_path:
        dest_path = os.path.join(dest, "cert.cert")
        with open(open_path, "rb") as src_file:
            with open(dest_path, "wb") as dest_file:
                dest_file.write(src_file.read())

        messagebox.showinfo(title="Erfolgreich", message="Zertifikat hochgeladen!")


def upload_inst_certificate():
    dest = os.path.join(script_dir, "data")
    if not os.path.exists(dest):
        os.makedirs(dest)

    open_path = filedialog.askopenfilename(
        defaultextension=".crt",
        filetypes=[("Zertifikat", "*.crt")],
        title="Hochladen",
    )

    if open_path:
        dest_path = os.path.join(dest, "inst_cert.cert")
        with open(open_path, "rb") as src_file:
            with open(dest_path, "wb") as dest_file:
                dest_file.write(src_file.read())

        messagebox.showinfo(title="Erfolgreich", message="Zertifikat hochgeladen!")


def get_private_key(suffix):
    data_folder = os.path.join(script_dir, "data")

    passphrase_path = os.path.join(data_folder, f"passphrase_{suffix}.txt")
    private_key_path = os.path.join(data_folder, f"cert_private_{suffix}.key")

    if not os.path.exists(passphrase_path) or not os.path.exists(private_key_path):
        messagebox.showerror(
            "Fehler", "Passphrase oder privater Schlüssel nicht gefunden."
        )
        return None

    passphrase = load_passphrase_from_path(passphrase_path)
    private_key = load_private_key_from_path(private_key_path, passphrase)

    return private_key


def sign_file(open_path, suffix):
    private_key = get_private_key(suffix)

    if private_key is None:
        return

    # Read file content
    with open(open_path, "rb") as file:
        file_data = file.read()
        prehashed = hashlib.sha256(file_data).digest()

    # Sign the file
    signature = private_key.sign(  # type: ignore
        prehashed,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),  # type: ignore
        hashes.SHA256(),  # type: ignore
    )

    # Save the signature
    signature_path = open_path + ".sig"
    with open(signature_path, "wb") as sig_file:
        sig_file.write(base64.b64encode(signature))

    messagebox.showinfo(
        "Erfolg",
        f"Datei erfolgreich signiert.\nSignatur gespeichert unter {signature_path}.sig",
    )


# Encrypt file using public certificate
def encrypt_file(file_location, inst_cert=True):

    if inst_cert:
        cert_name = "inst_cert"
    else:
        cert_name = "cert"

    cert_location = os.path.join(script_dir, "data", f"{cert_name}.cert")
    print(cert_location)
    cert = load_certificate_from_path(cert_location)
    public_key = cert.public_key()

    # Generate Fernet key
    fernet_key = Fernet.generate_key()

    # Encrypt Fernet key with RSA public key
    encrypted_fernet_key = public_key.encrypt(  # type: ignore
        fernet_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    # Encrypt file content using Fernet key
    fernet = Fernet(fernet_key)
    with open(file_location, "rb") as f:
        plaintext = f.read()
    encrypted_data = fernet.encrypt(plaintext)

    # Combine encrypted Fernet key and encrypted file content
    combined_data = encrypted_fernet_key + encrypted_data

    # Save encrypted file
    with open(file_location + ".enc", "wb") as f:
        f.write(combined_data)

    print("File encrypted")

    messagebox.showinfo(
        "Erfolg",
        f"Datei erfolgreich verschlüsselt.\nDatei gespeichert unter {file_location}.enc",
    )


def decrypt_file(open_path, suffix):

    # Read encrypted data
    key = get_private_key(suffix)

    if key is None:
        messagebox.showerror("Fehler", "Privater Schlüssel nicht gefunden.")
        return

    with open(open_path, "rb") as f:
        combined_data = f.read()

    # Extract encrypted Fernet key and encrypted file content
    encrypted_fernet_key = combined_data[:256]
    encrypted_data = combined_data[256:]

    try:
        # Decrypt Fernet key with RSA private key
        fernet_key = key.decrypt(  # type: ignore
            encrypted_fernet_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
    except:
        messagebox.showerror("Fehler", "Entschlüsselung fehlgeschlagen.")
        return

    # Decrypt file content with Fernet key
    fernet = Fernet(fernet_key)
    decrypted_data = fernet.decrypt(encrypted_data)

    # Save decrypted file
    with open(open_path.replace(".enc", ""), "wb") as f:
        f.write(decrypted_data)

    messagebox.showinfo("Erfolg", "Datei erfolgreich entschlüsselt.")


def verify_file(open_path, check_with_inst_cert):

    if check_with_inst_cert:
        inst_cert_path = os.path.join(script_dir, "data", "inst_cert.cert")

        if not os.path.exists(inst_cert_path):
            messagebox.showerror("Fehler", "Institutszertifikat nicht gefunden.")
            return

        inst_cert = load_certificate_from_path(inst_cert_path)
        pubkey = inst_cert.public_key()
    else:
        cert_path = os.path.join(script_dir, "data", "cert.cert")

        if not os.path.exists(cert_path):
            messagebox.showerror("Fehler", "Zertifikat nicht gefunden.")
            return

        cert = load_certificate_from_path(cert_path)
        pubkey = cert.public_key()

    print(open_path)

    # Read file content
    with open(open_path, "rb") as file:
        file_data = file.read()
        prehashed = hashlib.sha256(file_data).digest()

    with open(open_path + ".sig", "rb") as s:
        sig = s.read()
        decoded_sig = base64.b64decode(sig)

    try:
        pubkey.verify(  # type: ignore
            decoded_sig,
            prehashed,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),  # type: ignore
            hashes.SHA256(),  # type: ignore
        )
        messagebox.showinfo("Erfolgreich", "Signatur ist valide!")
        print("valid!")

    except:
        messagebox.showerror("Fehler", "Signatur konnte nicht verifiziert werden.")
