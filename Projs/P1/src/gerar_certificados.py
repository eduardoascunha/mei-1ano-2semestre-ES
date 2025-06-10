# gerar_certificados.py
from OpenSSL import crypto
import os

def criar_certificado():
    # Gerar chave privada
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)

    # Criar certificado
    cert = crypto.X509()
    cert.get_subject().C = "PT"
    cert.get_subject().ST = "Portugal"
    cert.get_subject().L = "Braga"
    cert.get_subject().O = "CofreDigital"
    cert.get_subject().OU = "Development"
    cert.get_subject().CN = "localhost"

    cert.set_serial_number(1000)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365*24*60*60)  # Válido por 1 ano
    cert.set_issuer(cert.get_subject())
    cert.set_pubkey(k)
    cert.sign(k, 'sha256')

    # Salvar certificado e chave privada
    with open("server.crt", "wb") as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    with open("server.key", "wb") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

if __name__ == '__main__':
    criar_certificado()