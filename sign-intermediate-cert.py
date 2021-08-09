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
MIICoDCCAYgCAQAwWzELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAlVUMQ0wCwYDVQQH
EwRMZWhpMRswGQYDVQQKDBJDcm93ZFN0b3JhZ2UsIEluYy4xEzARBgNVBAMMCmNo
aWEtaW50ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDHEU1LSzL1
EkeIl9820dJrnytVGvXIBdH8MV4hZGOiV+SkkT6XpaMi3x0T02sB3YAQolWaotEM
/TsCXXwRhqsZSsrkyhQYxn4oVkKbGL8Nrq1ckSSiVAuFQFVkAjlbwTGBN8RYyDpU
EF05Y6lCgBp+6QecQP8oW6QlV+L0IVUjG5rpAob7KWgOKsIiSLXfVlh0YoyU0XID
0+ONdc+IJGvALf1euj7Ctsbq0UQX7zipmy9R9NZw4sQHlXRrI/+PcvJx9brnsVqq
rlzLSJm1IQjSbwlHiJTNSAuRsdyX7kCvsff/N8gflkP0zRHDLJtFv/KjiE3vxhCY
xqYg0KpKV/KbAgMBAAGgADANBgkqhkiG9w0BAQUFAAOCAQEAc3K/7OmfxlEdadM4
rdpOTZIAn8zU1AnmihPO+UpkCbp1lqHKS60Aw7BSa9zkf/ZXxFr3KYQL7LI8q530
FwwV9gLhVRZ5P0PVDQMHJ6Osj9UMVMLDBlXsKI3/ElDMmQd3f3wY5L6L45NxQ9qX
LM0X+JfaBVoVHLu4TMH2OgTl1KJcadFUnMeYcR8xMn4GQgNB5AMjf17MYY3Nqknf
r1c6wQ0XsGcGBA6wzjM6S5MWTw/vlnUlM1n22a7iWcoNKpxmBnFckok0XL85QF/Z
CbgPKet5YMd5V7b+LckUpEUzQL2Z1Tsufctyc+gSLedsRUbdypAHl14jwB4LW+NY
De8HiA==
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


