from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER, TLSVersion

def run_server():
    ip = '127.0.0.1'
    port = 8443

    # criar contexto TLS
    context = SSLContext(PROTOCOL_TLS_SERVER)
    
    # TLS 1.3
    context.minimum_version = TLSVersion.TLSv1_3
    context.maximum_version = TLSVersion.TLSv1_3
    
    # load do certificado e chave
    context.load_cert_chain('cert.pem', 'key.pem')
    
    with socket(AF_INET, SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen(1)
        print(f"Servidor iniciado em {ip}:{port}")
        print("Aguardando conexão do cliente...")
        
        with context.wrap_socket(server, server_side=True) as tls:
            connection, address = tls.accept()
            print(f'Cliente conectado: {address}')
            
            # informações sobre a conexão TLS
            print(f"Versão do protocolo: {connection.version()}")
            print(f"Cifra em uso: {connection.cipher()[0]}")
            
            # loop de chat
            try:
                while True:
                    # receber mensagem do cliente
                    data = connection.recv(1024)
                    
                    if not data:
                        print("Cliente desconectado")
                        break
                        
                    msg = data.decode('utf-8')
                    print(f"Cliente diz: {msg}")
                    
                    # finalizar o chat
                    if msg.lower() == 'sair':
                        print("Chat closed.")
                        connection.sendall("Chat encerrado pelo servidor.".encode('utf-8'))
                        break
                    
                    # enviar resposta
                    resposta = input("Resposta: ")
                    connection.sendall(resposta.encode('utf-8'))
                    
                    if resposta.lower() == 'sair':
                        print("Encerrando chat")
                        break

            except Exception as e:
                print(f"Erro durante o chat: {e}")

            finally:
                connection.close()
                print("Conexão encerrada")

if __name__ == "__main__":
    run_server()