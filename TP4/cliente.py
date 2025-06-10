import asyncio
import hashlib
import os

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

class Client:
    def __init__(self, sckt=None):
        self.sckt = sckt
        self.a = generate_random()
        self.A = pow(G, self.a, P)
        self.K = None

    def process(self, msg=b""):
        if not msg:
            return str(self.A).encode()  # Enviar A para o servidor
        
        parts = msg.decode().split(',')
        if len(parts) == 2:  
            s, B = int(parts[0]), int(parts[1])
            u = H(self.A, B)
            x = H(s, "password")  # teste
            S = pow(B - pow(G, x, P), self.a + u * x, P)
            self.K = H(S)
            proof = H(self.A, B, self.K)  
            return str(proof).encode()

        elif msg.decode() == "OK":
            print("Autenticação bem-sucedida!")
        else:
            print("Falha na autenticação.")
        return None  

async def tcp_echo_client():
    reader, writer = await asyncio.open_connection('127.0.0.1', conn_port)
    client = Client()
    msg = client.process()
    while msg:
        writer.write(msg)
        msg = await reader.read(max_msg_size)
        if msg:
            msg = client.process(msg)
        else:
            break
    writer.write(b'\n')
    print('Socket closed!')
    writer.close()

#def run_client():
#    loop = asyncio.get_event_loop()
#    loop.run_until_complete(tcp_echo_client())

def run_client():
    asyncio.run(tcp_echo_client())

run_client()