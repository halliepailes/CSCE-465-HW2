import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

def seal (version, direction, sequence, message_type, session_id, plaintext, K_enc, K_mac):
    #plaintext, session_id, K_enc, & K_mac are in byte form already from Task 2
    sequence_bytes = sequence.to_bytes(8, byteorder = 'big')
    iv = session_id + sequence_bytes

    #AES-256-CTR
    cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()

    version_bytes = version.to_bytes(1, byteorder = 'big')
    direction_bytes = direction.to_bytes(1, byteorder = 'big')
    message_type_bytes = message_type.to_bytes(1, byteorder = 'big')
    ct_len_bytes = len(ciphertext).to_bytes(4, byteorder = 'big')

    header = version_bytes + direction_bytes + sequence_bytes + message_type_bytes + ct_len_bytes

    h = hmac.HMAC(K_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    tag = h.finalize()

    #return everything
    return header + iv + ciphertext + tag

def open_record(record, expected_direction, expected_sequence, session_id, K_enc, K_mac) :

    #header = 15 bytes, iv = 16 bytes
    header = record[:15]
    iv = record[15:31]
    direction = int.from_bytes(header[1:2], byteorder = 'big')
    sequence = int.from_bytes(header[2:10], byteorder = 'big')
    ct_len = int.from_bytes(header[11:15], byteorder = 'big')

    #ciphertext starts at 31 bytes
    ciphertext = record[31:31+ct_len]
    tag = record[31+ct_len:]

    if direction != expected_direction:
        raise ValueError("Wrong direction")
    if sequence != expected_sequence:
        raise ValueError("Wrong sequence")

    #verify header , iv, and ciphertext werent tampered with
    h = hmac.HMAC(K_mac, hashes.SHA256())
    h.update(header + iv + ciphertext)
    h.verify(tag)

    cipher = Cipher(algorithms.AES(K_enc), modes.CTR(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    return plaintext
