#!/usr/bin/env python

import argparse
from datetime import datetime,timedelta
import sys

from typing import Dict
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from chia.cmds.init_funcs import check_keys
from chia.util.config import load_config

crowdstorage_csr = """-----BEGIN CERTIFICATE REQUEST-----
MIICpDCCAYwCAQAwXzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMQ0wCwYDVQQH
EwRMZWhpMRUwEwYDVQQKDAxDcm93ZHN0b3JhZ2UxHTAbBgNVBAMMFENTIENoaWEg
SW50ZXJtZWRpYXRlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsrBv
mBTZjOKlG8GRFR5xV1HQtHg1p0GgV4nOICu/OdfMBR4zdXBGHmJYhgTZtiEMB06z
LzEPvhtUK2FX1mEsV/8TpBvVE6lUP2NLeZxZcCLiFSiD2irdTgMnMXjG367kYuft
4RR3MOUfsckjBkQfkZNxvd77DwjHj0hJHCV+Wrc6mykGwfJJQnOekc+gW26U6O0f
jKKo97IvRsTMO277Y3gewIlwA7f7EQ8GFwN/4xiQZ+23BR0P5OIgGScGAhsbMzoN
lZF8CH9YCmNql5XWmmbCIwtjIdzomRm8VL0Nk2Ev6KhEimm9mlAliidzGkFrF5tD
w2oYeeyRM2yFRlCoOQIDAQABoAAwDQYJKoZIhvcNAQEFBQADggEBAADVCPbWFszi
3jk+56P2gc23HgHajKE9pPE7aUN0YW8DOwc5AzZkub0PCUgNOYbcFp3Ng0yLP2RP
tYTVd7G/AaXHBAkY+lyLq5u1Gu2ezf8jhp3db979OsFRju0jgGHr1NbMhpeXbFNb
wbXbT+K580LSgbl4jvoB9qNwP6U0tqPvn+cs0Ecuf8qMX8hZGKHa5F1S8UM/Jg7c
fDpfYvKxo2zEq1E5bjy9q7dFcO1vy7w3cEHTEJaZ1IBV87Buvt84InYC0F6yuWYi
PvnQv6eKuHrYVREEtUm0OcqrUi0Xxdzydo3Em8VezRR/b7vvFvtFomxQQhFj3sqw
kKOv+o1vF48=
-----END CERTIFICATE REQUEST-----"""

def sign_certificate_request(csr_cert, ca_cert, private_ca_key):
    cert = x509.CertificateBuilder().subject_name(
        csr_cert.subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        csr_cert.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=100 * 365) # 100 years
    ).sign(private_ca_key, hashes.SHA256())

    return cert

if __name__ == "__main__":
    from chia.util.default_root import DEFAULT_ROOT_PATH
    check_keys(DEFAULT_ROOT_PATH)

    config: Dict = load_config(DEFAULT_ROOT_PATH, "config.yaml")

    ca_path = DEFAULT_ROOT_PATH / config["harvester"]["private_ssl_ca"]["crt"]
    key_path = DEFAULT_ROOT_PATH / config["harvester"]["private_ssl_ca"]["key"]
    key = load_pem_private_key(key_path.read_bytes(), None, default_backend())

    cert = x509.load_pem_x509_certificate(ca_path.read_bytes(), default_backend())

    csr = x509.load_pem_x509_csr(str.encode(crowdstorage_csr))

    inter_cert = sign_certificate_request(csr, cert, key)

    inter_cert_path = Path("crowdstorage_intermediate.crt")
    with inter_cert_path.open("bw") as f:
        f.write(
            inter_cert.public_bytes(
                encoding=serialization.Encoding.PEM,
                )
            )
        f.write(
            cert.public_bytes(
                encoding=serialization.Encoding.PEM,
                ),
            )
    print(f"Success! Signed intermediate cert can be found at {inter_cert_path.absolute()}")


