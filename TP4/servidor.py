import asyncio
import hashlib
import os

conn_cnt = 0
conn_port = 8443
max_msg_size = 9999

P = 21907153604610140591413853060873569488799889545658499345199954499288513214495373162018722276190048176453652397664537072464364660353276556674291687790361787435091460602031819701696205848778364694457002959752093446607221996010036337184792838247025102191936341390662068744021282838757199568626081187227742559172776873502282499069629660067520588953222350511785313015510628099851763437253603253292206693665849951761355348626222976632736302988522601311275484771250652762026921947170188217539811008577940147903383872484450616566697941278828073032953299017447498073055295325961865824002868867473303760698067810206224428310567
G = 2

def H(*args):
    hash_obj = hashlib.sha256()
    for arg in args:
        if isinstance(arg, int):
            arg = arg.to_bytes((arg.bit_length() + 7) // 8, byteorder='big')
        elif isinstance(arg, str):
            arg = arg.encode('utf-8')
        hash_obj.update(arg)
    return int.from_bytes(hash_obj.digest(), byteorder='big')

def generate_random():
    return int.from_bytes(os.urandom(32), byteorder='big')

class ServerWorker:
    def __init__(self, cnt, addr=None):
        self.id = cnt
        self.addr = addr
        self.b = generate_random()
        self.s = int.from_bytes(os.urandom(16), byteorder='big')
        self.password = "password"  # teste
        self.v = pow(G, H(self.s, self.password), P)
        self.B = (self.v + pow(G, self.b, P)) % P  
        self.K = None
        self.A = None

    def process(self, msg):
        txt = msg.decode()
        if not self.A: 
            self.A = int(txt)
            print(f"[{self.id}] Nova conexão de {self.addr}. Recebido A = {self.A}")
            return f"{self.s},{self.B}".encode()
        
        else: 
            proof = int(txt)
            u = H(self.A, self.B)
            S = pow(self.A * pow(self.v, u, P), self.b, P)
            self.K = H(S)

            if proof == H(self.A, self.B, self.K):  # Comparação corrigida
                print(f"[{self.id}] Autenticação bem-sucedida para {self.addr}!")
                return b"OK"
            else:
                print(f"[{self.id}] Falha na autenticação para {self.addr}.")
                return b"FAIL"

async def handle_echo(reader, writer):
    global conn_cnt
    conn_cnt += 1
    addr = writer.get_extra_info('peername')
    srvwrk = ServerWorker(conn_cnt, addr)

    data = await reader.read(max_msg_size)
    while data:
        if data[:1] == b'\n': break
        data = srvwrk.process(data)
        if not data: break
        writer.write(data)
        await writer.drain()
        data = await reader.read(max_msg_size)

    print(f"[{srvwrk.id}] Conexão fechada com {addr}")
    writer.close()

def run_server():
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    coro = asyncio.start_server(handle_echo, '127.0.0.1', conn_port)
    server = loop.run_until_complete(coro)
    print(f'Servidor iniciado em {server.sockets[0].getsockname()}')
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('\nServidor finalizado!')

run_server()