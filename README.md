# Encryption CLI Tool

## Overview
This tool provides encryption and decryption using various ciphers including:
- Additive Cipher
- Multiplicative Cipher
- Affine Cipher
- Monoalphabetic Substitution Cipher
- Autokey Cipher
- Playfair Cipher
- Vigenère Cipher
- Keyless Transposition Cipher
- Keyed Transposition Cipher
- Combination of Keyless and Keyed Transposition
- Double Transposition Cipher

## How to Run the Tool
1. Clone the repository or download the Python script.
2. Run the script using `python cipher_cli.py`.
3. Follow the prompts to select a cipher, input text, keys, and choose encryption or decryption.

## Example Inputs and Expected Outputs
PS C:\Users\abc\Desktop\cipher tool> python cipher_cli.py


Welcome to the Encryption/Decryption CLI Tool
Select a cipher:
1. Additive Cipher
2. Multiplicative Cipher
3. Affine Cipher
4. Monoalphabetic Substitution Cipher
5. Autokey Cipher
6. Playfair Cipher
7. Vigenère Cipher
8. Keyless Transposition Cipher
9. Keyed Transposition Cipher
10. Combined Keyless and Keyed Approach
11. Double Transposition Cipher
0. Exit

Enter the number of the cipher you want to use (0 to exit): 5

Enter the plaintext (only alphabets allowed): hello

Enter the first key (non-empty, unique characters): run

Type 'e' for encryption or 'd' for decryption: e

Ciphertext: yyyss

## Handeling exceptional situations
Enter the number of the cipher you want to use (0 to exit): 1
Enter the plaintext (only alphabets allowed): hello23
Error: Plaintext should contain only alphabets.
