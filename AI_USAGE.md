# AI Usage

## Tool/Model & Date:
* Google Gemini / AI Overviews
* October 1, 2026 & October 2, 2026

## Purpose:
To assist with Python implementation details for data type conversions (strings, bytes, hex) and cryptographic operations (Diffie-Hellman key serialization and AES-CTR encryption setup).

## AI Conversation Log Files:
* Provided via screenshots (also available within the `AI Logs.pdf` in the root directory):
<img width="622" height="406" alt="image" src="https://github.com/user-attachments/assets/9ba67696-1000-4cad-928a-c12d25e7d62d" />
<img width="629" height="617" alt="image" src="https://github.com/user-attachments/assets/80ca6919-a02c-403e-9321-56f387208e7d" />
<img width="582" height="656" alt="image" src="https://github.com/user-attachments/assets/9f35f888-6d4e-4f67-8b39-76c540eced34" />
<img width="615" height="624" alt="image" src="https://github.com/user-attachments/assets/c1f6fb4a-3750-48a7-9f03-3383d337e901" />
<img width="617" height="494" alt="image" src="https://github.com/user-attachments/assets/3f4a26eb-a037-4868-bc54-d9c02db30e0b" />


## What I used:
* **String to Bytes Conversion:** Used the `bytearray()` method example to cleanly convert standard Python strings into byte objects.
* **AES-CTR Imports:** Followed the import layout to correctly bring in `Cipher`, `algorithms`, and `modes` from the `cryptography.hazmat.primitives.ciphers` library.
* **Diffie-Hellman Serialization:** Used the pattern for extracting the raw integer public value `y` via `public_numbers().y` and encoding it into a 384-byte big-endian byte string using `.to_bytes(384, byteorder='big')`.
* **Bytes to Hex Conversion:** Used the built-in `.hex()` method to convert output byte strings into clean hexadecimal strings.

## What I changed:
* I used the examples and information as an outline, but changed the generalized variable names from the screenshots (like `my_string` or `public_bytes`) to align directly with the context of my code and the specific variable names I had.

## How I tested it:
* Executed the script locally to verify that data types transitioned correctly without throwing `TypeError` or `AttributeError`.
* Printed out lengths of the serialized Diffie-Hellman public keys to ensure they measured exactly 384 bytes as required.

## One error, limitation, or rejected suggestion:
* The documentation snippet recommended me using the `string.encode()` method or `bytes()`, however I rejected using either of these in favor of `bytearray()`, as I needed an array that was mutable so I could modify the command within Task 1 using the XOR operation.
