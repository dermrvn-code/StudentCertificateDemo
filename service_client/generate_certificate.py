import os
import sys

# Add parent directory to path
script_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.abspath(os.path.join(script_dir, os.pardir))
sys.path.append(parent_dir)

from certificates.Certificate import generate_tls_server_cert
from certificates.CA import generate_certificate_authority


def main():
    dest = os.path.join(script_dir, "certs")
    ca_cert_path, ca_private_path, ca_public_path, ca_passphrase_path = (
        generate_certificate_authority(
            dest, country_code="DE", common_name="CACampusOfficeHSHL"
        )
    )
    generate_tls_server_cert(
        ca_cert_path=ca_cert_path,
        ca_key_path=ca_private_path,
        ca_passphrase_path=ca_passphrase_path,
        dest_folder=dest,
        country_code="DE",
        common_name="CampusOfficeHSHL",
        hostname="localhost",
        organization_name="HSHL",
        organizational_unit_name="CampusOffice",
    )

    print("Certificates generated successfully.")


if __name__ == "__main__":
    main()
