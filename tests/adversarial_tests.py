from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
import secure_record

#dummy variables
K_g2n_enc = b"dummygtonencryptionkey0123456789"
K_n2g_enc = b"dummyntogencryptionkey0123456789"
K_g2n_mac = b"dummygtonmackey01234567890123456"
K_n2g_mac = b"dummyntogmackey01234567890123456"
session_id = b"01234567"

print("Starting Tests...\n")

#Test 1 - Valid Handshake & Bidirectional Messages
plaintext = b'{"action":"READ","path":"notes.txt"}'
record = secure_record.seal(2, 0, 0, 1, session_id, plaintext, K_g2n_enc, K_g2n_mac)
decrypted = secure_record.open_record(record, 0, 0, session_id, K_g2n_enc, K_g2n_mac)
assert decrypted == plaintext, "Test 1 Failed: Message decryption failed" 

reply_plaintext = b'{"status":"SUCCESS"}'
reply_record = secure_record.seal(2, 1, 0, 1, session_id, reply_plaintext, K_n2g_enc, K_n2g_mac) #make sure to change direction to 1
reply_decrypted = secure_record.open_record(reply_record, 1, 0, session_id, K_n2g_enc, K_n2g_mac)
assert reply_decrypted == reply_plaintext, "Test 1 Failed: Reply decryption failed"

print("Test 1 - Valid Handshake & Bidrectional Messages Passed: Valid bidrectional messages worked succesfully")

#Test 2 - Modified Ciphertext
plaintext = b'{"action":"READ","path":"notes.txt"}'
record = secure_record.seal(2, 0, 0, 1, session_id, plaintext, K_g2n_enc, K_g2n_mac)
new_record = bytearray(record) #cahnge to bytearray so we can edit
new_record[32] = new_record[32] ^ 0x01 #xor one of the bits from ciphertext 

try:
    secure_record.open_record(new_record, 0, 0, session_id, K_g2n_enc, K_g2n_mac)
    assert False, "Test 2 Failed: Decrypted modified ciphertext without failure"
except Exception:
    print("Test 2 - Modified Ciphertext Passed: Successfully detected & blocked modified ciphertext")

#Test 3 - Modified Authentication Header
plaintext = b'{"action":"READ","path":"notes.txt"}'
record = secure_record.seal(2, 0, 0, 1, session_id, plaintext, K_g2n_enc, K_g2n_mac)
new_record = bytearray(record) #cahnge to bytearray so we can edit
new_record[0] = 1 #change somethin in header - like version

try:
    secure_record.open_record(new_record, 0, 0, session_id, K_g2n_enc, K_g2n_mac)
    assert False, "Test 3 Failed: Accepted modified header without failure"
except Exception:
    print("Test 3 - Modified Authentication Header Passed: Successfully detected & blocked modified header")

#Test 4 - Replayed Record
plaintext = b'{"action":"READ","path":"notes.txt"}'
record = secure_record.seal(2, 0, 0, 1, session_id, plaintext, K_g2n_enc, K_g2n_mac)
decrypted = secure_record.open_record(record, 0, 0, session_id, K_g2n_enc, K_g2n_mac)

try:
    secure_record.open_record(record, 0, 1, session_id, K_g2n_enc, K_g2n_mac) #try to open again with the next expected sequence counter to replay
    assert False, "Test 4 Failed: Accepted replayed record without failure"
except Exception:
    print("Test 4 - Replayed Record Passed: Successfully detected & blocked replayed record")

#Test 5 - Record Refelcted into the Opposite Direction
plaintext = b'{"action":"READ","path":"notes.txt"}'
record = secure_record.seal(2, 0, 0, 1, session_id, plaintext, K_g2n_enc, K_g2n_mac)

try:
    secure_record.open_record(record, 1, 0, session_id, K_g2n_enc, K_g2n_mac) #try to open with direction reflected as 1 instead of the expexted 0
    assert False, "Test 5 Failed: Accepted reflected record without failure"
except Exception:
    print("Test 5 - Replayed Record Passed: Successfully detected & blocked redlected record")

#Test 6 - Handshake Failures (incorrect RSA public key, incorrect RSA-PSS transcript signature, or refelcetd handshake message
private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 3072
)
public_key = private_key.public_key()
evil_private_key = rsa.generate_private_key(
    public_exponent = 65537,
    key_size = 3072
)

evil_message = b"gateway" 
evil_signature = evil_private_key.sign(
    evil_message,
    padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

try:
    public_key.verify( #verify will throw errors for any of the instances we are trying to avoid in this case
        evil_signature,
        evil_message,
        padding.PSS(
        mgf = padding.MGF1(hashes.SHA256()),
        salt_length = padding.PSS.MAX_LENGTH
    	),
    	hashes.SHA256()
    )
    assert False, "Test 6 Failed: Verified an invalid handshake"
except Exception:
    print("Test 6 - Handshake Failures Passed: Successfully caught invalid handshake")

print("\nAll tests passed!")

