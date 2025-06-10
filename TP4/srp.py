import os
import hashlib

P = 21907153604610140591413853060873569488799889545658499345199954499288513214495373162018722276190048176453652397664537072464364660353276556674291687790361787435091460602031819701696205848778364694457002959752093446607221996010036337184792838247025102191936341390662068744021282838757199568626081187227742559172776873502282499069629660067520588953222350511785313015510628099851763437253603253292206693665849951761355348626222976632736302988522601311275484771250652762026921947170188217539811008577940147903383872484450616566697941278828073032953299017447498073055295325961865824002868867473303760698067810206224428310567
Q = 10953576802305070295706926530436784744399944772829249672599977249644256607247686581009361138095024088226826198832268536232182330176638278337145843895180893717545730301015909850848102924389182347228501479876046723303610998005018168592396419123512551095968170695331034372010641419378599784313040593613871279586388436751141249534814830033760294476611175255892656507755314049925881718626801626646103346832924975880677674313111488316368151494261300655637742385625326381013460973585094108769905504288970073951691936242225308283348970639414036516476649508723749036527647662980932912001434433736651880349033905103112214155283
G = 2

# Função de hash copiada da net
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

# Cliente
def client_step1():
    a = generate_random()
    A = pow(G, a, P)
    
    return A, a

def client_step2(s, B, a, password, u):
    x = H(s, password)
    S = pow(B - k * pow(G, x, P), a + u * x, P)
    K = H(S)

    return K

# Servidor
def server_step1(password):
    b = generate_random()
    
    s = os.urandom(16)  # random salt
    x = H(s, password)

    # supostamente seria recuperada da base de dados
    v = pow(G, x, P)

    B = (k * v + pow(G, b, P)) % P

    return s, B, b

def server_step2(A, b, v, u):
    S = pow(A * pow(v, u, P), b, P)
    K = H(S)

    return K

# Exemplo de uso
username = "user"
password = "password"

# Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
k = H(P, G)

# Cliente step 1
A, a = client_step1()

# Servidor step 1
s, B, b = server_step1(password)

# both
u = H(A, B)

# Cliente step 2
K_client = client_step2(s, B, a, password, u)

# Servidor step 2
# supostamente seria recuperado da base de dados
v = pow(G, H(s, password), P)  # password verifier
K_server = server_step2(A, b, v, u)

# check
assert K_client == K_server
print("Valid.")