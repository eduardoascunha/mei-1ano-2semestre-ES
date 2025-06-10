#!/usr/bin/env python3
import os
import ipaddress
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

# --- Parâmetros de validade ---
CA_VALIDITY_DAYS = 3650       # 10 anos
SERVER_VALIDITY_DAYS = 365    # 1 ano

# --- Função utilitária para gravar no disco ---
def grava_pem(path: str, data: bytes):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    print(f"[+] Gravado: {path}")


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    certs_dir = os.path.join(base_dir, "certs")

    # 1) Gerar CA Root --------------------------------------------------------
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Portugal"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ES_CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ES_CA Root"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    # Gravar CA
    grava_pem(os.path.join(certs_dir, "ca.key.pem"), ca_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    grava_pem(os.path.join(certs_dir, "ca.cert.pem"), ca_cert.public_bytes(serialization.Encoding.PEM))

    # 2) Gerar chave do servidor + CSR ---------------------------------------
    server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Portugal"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CofreDigital"),
            x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
        ]))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(server_key, hashes.SHA256())
    )
    # Gravar chave e CSR
    grava_pem(os.path.join(certs_dir, "server.key.pem"), server_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    grava_pem(os.path.join(certs_dir, "server.csr.pem"), server_csr.public_bytes(serialization.Encoding.PEM))

    # 3) Assinar CSR com a CA ------------------------------------------------
    csr = server_csr  # opcional
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(csr.subject)
        .issuer_name(ca_cert.subject)
        .public_key(csr.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=SERVER_VALIDITY_DAYS))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.DNSName("localhost"),
            ]),
            critical=False,
        )
        .sign(private_key=ca_key, algorithm=hashes.SHA256())
    )
    # Gravar certificado do servidor
    server_cert_pem = server_cert.public_bytes(serialization.Encoding.PEM)
    grava_pem(os.path.join(certs_dir, "server.cert.pem"), server_cert_pem)

    # 4) Criar fullchain (server + CA) ----------------------------------------
    ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM)
    fullchain = server_cert_pem + ca_cert_pem
    grava_pem(os.path.join(certs_dir, "fullchain.pem"), fullchain)

    print("\n [+] Todos os certificados e chaves foram gerados com sucesso!\n")

if __name__ == "__main__":
    main()
