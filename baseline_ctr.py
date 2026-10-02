import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

plaintext = b'{"action":"READ","path":"notes.txt"}'
key = os.urandom(32)
nonce = os.urandom(16)
cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
encryptor = cipher.encryptor()
ciphertext = encryptor.update(plaintext) + encryptor.finalize()

print(f"Original Plaintext: {plaintext}")
print(f"Original Ciphertext: {ciphertext}\n")

index = plaintext.find(b"READ")
new_action = b"EDIT"

new_ciphertext = bytearray(ciphertext) #change ciphertext to bytes
print("XOR Relation")
for i in range(len(new_action)):
    j = index + i
    og_char = plaintext[j]
    new_char = new_action[i]
    xor = og_char ^ new_char
    print(f"Index {j}: {og_char} XOR {new_char} = {xor}")
    new_ciphertext[j] = new_ciphertext[j] ^ xor #this does plaintext xor keystream xor plaintext xor new_action, giving new_action xor keystream

cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(new_ciphertext) + decryptor.finalize()
print(f"\nFirst Run with New Ciphertext - Processed Payload: {decrypted_message}") 

cipher = Cipher(algorithms.AES(key), modes.CTR(nonce))
decryptor = cipher.decryptor()
decrypted_message = decryptor.update(new_ciphertext) + decryptor.finalize()
print(f"Second Run with Same Ciphertext - Processed Payload: {decrypted_message}") 
