import os
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.serialization import load_pem_parameters

g_private_key = rsa.generate_private_key( #generate private key for gateway
    public_exponent = 65537,  #standard public exponent
    key_size = 3072
)
g_public_key = g_private_key.public_key()  #generate public key for gateway

n_private_key = rsa.generate_private_key( #generate private key for node
    public_exponent = 65537,  #standard public exponent
    key_size = 3072
)
n_public_key = n_private_key.public_key()  #generate public key for node

with open("ffdhe3072.pem", "rb") as pem:
    pem_data = pem.read()

dh_values = load_pem_parameters(pem_data)
g_ephemeral_private_key = dh_values.generate_private_key()
g_ephemeral_public_key = g_ephemeral_private_key.public_key()
n_ephemeral_private_key = dh_values.generate_private_key()
n_ephemeral_public_key = n_ephemeral_private_key.public_key()

g_nonce = os.urandom(16)
n_nonce = os.urandom(16)

#Transcript - byte string
protocol = b"CSCE465-HS-v2"
group_id = b"ffdhe3072"
gateway_id = b"Gateway"
node_id = b"Node"


#Convert public keys to byte strings
g_public_value_int = g_ephemeral_public_key.public_numbers().y #extract raw integer public values
g_public_bytes = g_public_value_int.to_bytes(384, byteorder='big') #encode as 384 byte big endian byte string

n_public_value_int = n_ephemeral_public_key.public_numbers().y #extract raw int>
n_public_bytes = n_public_value_int.to_bytes(384, byteorder='big') #encode as 3>

transcript = (
    len(protocol).to_bytes(4, byteorder='big') + protocol +
    len(group_id).to_bytes(4, byteorder='big') + group_id +
    len(gateway_id).to_bytes(4, byteorder='big') + gateway_id +
    len(node_id).to_bytes(4, byteorder='big') + node_id +
    len(g_public_bytes).to_bytes(4, byteorder='big') + g_public_bytes +
    len(n_public_bytes).to_bytes(4, byteorder='big') + n_public_bytes +
    len(g_nonce).to_bytes(4, byteorder='big') + g_nonce +
    len(n_nonce).to_bytes(4, byteorder='big') + n_nonce
)

#Authentication
th_hasher = hashes.Hash(hashes.SHA256())
th_hasher.update(transcript)
TH = th_hasher.finalize()

g_message = b"gateway" + TH #sign role || TH
g_signature = g_private_key.sign(
    g_message,
    padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

n_message = b"node" + TH #sign role || TH
n_signature = n_private_key.sign( 
    n_message,
    padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

g_public_key.verify( #verify() will raise InvalidSignature exception if invalid
    g_signature,
    g_message,
    padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

n_public_key.verify(
    n_signature,
    n_message,
    padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

#Key Derivation
raw_Z = g_ephemeral_private_key.exchange(n_ephemeral_public_key) #shared key
Z_int = int.from_bytes(raw_Z, byteorder = 'big')
Z = Z_int.to_bytes(384, byteorder = 'big') #Big endian byte string

hasher = hashes.Hash(hashes.SHA256())
hasher.update(b"CSCE465-KDF-v1" + Z + TH)
K_master = hasher.finalize() #master key

#Session Keys
h1 = hmac.HMAC(K_master, hashes.SHA256())
h1.update(b"gateway-to-node encryption" + TH)
K_g2n_enc = h1.finalize()

h2 = hmac.HMAC(K_master, hashes.SHA256())
h2.update(b"gateway-to-node MAC" + TH)
K_g2n_mac = h2.finalize()

h3 = hmac.HMAC(K_master, hashes.SHA256())
h3.update(b"node-to-gateway encryption" + TH)
K_n2g_enc = h3.finalize()

h4 = hmac.HMAC(K_master, hashes.SHA256())
h4.update(b"node-to-gateway MAC" + TH)
K_g2n_mac = h4.finalize()

h5 = hmac.HMAC(K_master, hashes.SHA256())
h5.update(b"session identifier" + TH)
session_id = h5.finalize()[:8] #first 8 bytes

hex_session_id = session_id.hex()
print(f"Handshake complete - SessionID: {hex_session_id}")
