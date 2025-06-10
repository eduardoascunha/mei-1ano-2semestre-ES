#!/usr/bin/env python3
import argparse
import base64
import sys
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

CA_KEY_PATH = "misc/certs/ca.key.pem"
CA_CERT_PATH = "misc/certs/ca.cert.pem"

def carregar_chaves_ca():
    # Carrega chave privada da CA
    with open(CA_KEY_PATH, "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )
    # Carrega certificado público da CA (para preencher issuer_name)
    with open(CA_CERT_PATH, "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    return ca_private_key, ca_cert

def assinar_csr(csr_pem: bytes, email: str) -> bytes:
    ca_private_key, ca_cert = carregar_chaves_ca()
    csr = x509.load_pem_x509_csr(csr_pem, default_backend())

    # Build do certificado
    cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([x509.RFC822Name(email)]),
            critical=False,
        )
        .sign(private_key=ca_private_key, algorithm=hashes.SHA256())
    )

    return cert.public_bytes(serialization.Encoding.PEM)


def main():
    parser = argparse.ArgumentParser(
        description="CA Script: recebe CSR em base64 + email, retorna certificado (base64)."
    )
    parser.add_argument(
        "--csr-base64",
        required=True,
        help="CSR codificado em base64 (output do openssl req ou do cliente)",
    )
    parser.add_argument(
        "--email",
        required=True,
        help="Email (CN/SAN) que será incluído no certificado",
    )

    args = parser.parse_args()
    try:
        csr_pem = base64.b64decode(args.csr_base64.encode("utf-8"))
    except Exception as e:
        print(f"Erro ao decodificar CSR base64: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        cert_pem = assinar_csr(csr_pem, args.email)
        cert_base64 = base64.b64encode(cert_pem).decode("utf-8")
        # Imprime apenas a string base64 no stdout para o cliente capturar
        print(cert_base64)
    except Exception as e:
        print(f"Erro ao assinar CSR: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
