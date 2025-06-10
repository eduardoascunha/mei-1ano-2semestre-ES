from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT, TLSVersion, CERT_NONE

def run_client():
    hostname = 'uminho.org'
    ip = '127.0.0.1'
    port = 8443

    # contexto TLS
    context = SSLContext(PROTOCOL_TLS_CLIENT)
    
    # TLS 1.3
    context.minimum_version = TLSVersion.TLSv1_3
    context.maximum_version = TLSVersion.TLSv1_3
    
    # load certificado para verificação
    context.load_verify_locations('cert.pem')
    
    try:
        with create_connection((ip, port)) as client:
            with context.wrap_socket(client, server_hostname=hostname) as tls:
                
                # informações sobre a conexão TLS
                print(f"Conectado com sucesso ao servidor usando {tls.version()}")
                print(f"Cifra em uso: {tls.cipher()[0]}")
                
                # loop de chat
                try:
                    while True:
                        
                        # enviar mensagem
                        mensagem = input("Mensagem: ")
                        tls.sendall(mensagem.encode('utf-8'))
                        
                        # se o cliente enviar "sair", finalizar o chat
                        if mensagem.lower() == 'sair':
                            print("Chat Closed.")
                            break
                        
                        # receber resposta
                        data = tls.recv(1024)
                        
                        if not data:
                            print("Servidor desconectado")
                            break
                            
                        resposta = data.decode('utf-8')
                        print(f"Servidor diz: {resposta}")
                        
                        if resposta.lower() == 'sair':
                            print("Chat encerrado pelo servidor")
                            break

                except Exception as e:
                    print(f"Erro durante o chat: {e}")

    except Exception as e:
        print(f"Erro ao conectar: {e}")


if __name__ == "__main__":
    run_client()