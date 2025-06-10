from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import ipaddress

# Gerar chave privada
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

# Detalhes do certificado
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "PT"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Portugal"),
    x509.NameAttribute(NameOID.LOCALITY_NAME, "Braga"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "CofreDigital"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Development"),
    x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1"),
])

# Criar certificado com SAN para 127.0.0.1 e localhost
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.utcnow())
    .not_valid_after(datetime.utcnow() + timedelta(days=365))
    .add_extension(
        x509.SubjectAlternativeName([
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
            x509.DNSName("localhost"),
        ]),
        critical=False,
    )
    .sign(key, hashes.SHA256())
)

# Guardar chave privada
with open("misc/server.key", "wb") as f:
    f.write(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))

# Guardar certificado
with open("misc/server.crt", "wb") as f:
    f.write(cert.public_bytes(serialization.Encoding.PEM))
