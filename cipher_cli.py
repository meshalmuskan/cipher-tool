from math import gcd
import string

# --- Additive Cipher ---
def additive_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts the text using the Additive Cipher.
    Shifts each alphabetic character by 'key' positions for encryption.
    For decryption, shifts backwards by 'key' positions.
    Handles non-alphabetic characters and ensures key is an integer.
    """
    if not isinstance(key, int):
        raise ValueError("Key must be an integer.")
    
    shift = key if mode == 'encrypt' else -key
    encrypted_text = ''
    
    for char in text:
        if char.isalpha():
            shifted_char = chr((ord(char.lower()) - 97 + shift) % 26 + 97)
            encrypted_text += shifted_char.upper() if char.isupper() else shifted_char
        else:
            encrypted_text += char  # Non-alphabetic characters are unchanged
    return encrypted_text

def additive_cipher_decrypt(text, key):
    """
    Decrypts the text using Additive Cipher.
    Handles non-alphabetic characters and ensures key is an integer.
    """
    return additive_cipher(text, key, mode='decrypt')


# --- Multiplicative Cipher ---
def multiplicative_cipher(text, key, mode='encrypt'):
    """
    Encrypts or decrypts text using the Multiplicative Cipher.
    Each character's position is multiplied by 'key' for encryption.
    Decryption reverses this using the modular inverse of 'key'.
    Handles invalid keys (not coprime with 26) and non-alphabetic characters.
    """
    from math import gcd

    if gcd(key, 26) != 1:
        raise ValueError("Key must be coprime with 26.")
    if not isinstance(key, int):
        raise ValueError("Key must be an integer.")

    encrypted_text = ''
    
    for char in text:
        if char.isalpha():
            pos = (ord(char.lower()) - 97)
            new_pos = (key * pos) % 26 if mode == 'encrypt' else (pow(key, -1, 26) * pos) % 26
            encrypted_char = chr(new_pos + 97)
            encrypted_text += encrypted_char.upper() if char.isupper() else encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def multiplicative_cipher_decrypt(text, key):
    """
    Decrypts text using the Multiplicative Cipher.
    Handles invalid keys (not coprime with 26) and non-alphabetic characters.
    """
    return multiplicative_cipher(text, key, mode='decrypt')


# --- Affine Cipher ---
def affine_cipher(text, a, b, mode='encrypt'):
    """
    Encrypts or decrypts text using the Affine Cipher.
    Uses two keys: 'a' (multiplicative) and 'b' (additive).
    Validates keys to ensure 'a' is coprime with 26.
    """
    if not isinstance(a, int) or not isinstance(b, int):
        raise ValueError("Both keys must be integers.")
    if gcd(a, 26) != 1:
        raise ValueError("1st Key  must be coprime with 26.")

    encrypted_text = ''
    
    for char in text:
        if char.isalpha():
            pos = ord(char.lower()) - 97
            new_pos = (a * pos + b) % 26 if mode == 'encrypt' else (pow(a, -1, 26) * (pos - b)) % 26
            encrypted_char = chr(new_pos + 97)
            encrypted_text += encrypted_char.upper() if char.isupper() else encrypted_char
        else:
            encrypted_text += char
    return encrypted_text

def affine_cipher_decrypt(text, a, b):
    """
    Decrypts text using the Affine Cipher.
    Validates keys to ensure 'a' is coprime with 26.
    """
    return affine_cipher(text, a, b, mode='decrypt')


# --- Monoalphabetic Substitution Cipher ---
def monoalphabetic_cipher(text, substitution_key, mode='encrypt'):
    """
    Encrypts or decrypts text using a Monoalphabetic Substitution Cipher.
    The substitution key must contain exactly 26 characters.
    Decryption uses the reverse mapping.
    Handles non-alphabetic characters.
    """
    if len(substitution_key) != 26 or not substitution_key.isalpha():
        raise ValueError("Substitution key must be a string of 26 alphabetic characters.")

    alphabet = string.ascii_lowercase
    
    if mode == 'decrypt':
        substitution_key = ''.join(sorted(substitution_key, key=substitution_key.index))

    encrypted_text = ''
    
    for char in text:
        if char.isalpha():
            index = alphabet.index(char.lower())
            new_char = substitution_key[index]
            encrypted_text += new_char.upper() if char.isupper() else new_char
        else:
            encrypted_text += char
    return encrypted_text

def monoalphabetic_cipher_decrypt(text, substitution_key):
    """
    Decrypts text using the Monoalphabetic Substitution Cipher.
    Validates substitution key.
    """
    return monoalphabetic_cipher(text, substitution_key, mode='decrypt')


# --- Autokey Cipher ---
def autokey_cipher(text, keyword, mode='encrypt'):
    """
    Encrypts or decrypts text using the Autokey Cipher.
    For encryption, extends the keyword with the plaintext.
    Decryption reconstructs the key from the ciphertext.
    """
    if not keyword.isalpha():
        raise ValueError("Keyword must be alphabetic.")

    keyword = keyword.lower()
    
    if mode == 'decrypt':
        extended_key = keyword
        decrypted_text = ''
        
        for i, char in enumerate(text):
            if char.isalpha():
                pos = (ord(char.lower()) - ord(extended_key[i])) % 26
                decrypted_char = chr(pos + 97)
                extended_key += decrypted_char
                decrypted_text += decrypted_char.upper() if char.isupper() else decrypted_char
            else:
                decrypted_text += char
        return decrypted_text

    extended_key = (keyword + text).lower()[:len(text)]
    encrypted_text = ''
    
    for i in range(len(text)):
        if text[i].isalpha():
            pos = (ord(text[i].lower()) - 97 + ord(extended_key[i]) - 97) % 26
            encrypted_char = chr(pos + 97)
            encrypted_text += encrypted_char.upper() if text[i].isupper() else encrypted_char
        else:
            encrypted_text += text[i]
    return encrypted_text

def autokey_cipher_decrypt(text, keyword):
    """
    Decrypts text using the Autokey Cipher.
    Validates keyword.
    """
    return autokey_cipher(text, keyword, mode='decrypt')


# --- Vigenère Cipher ---
def vigenere_cipher(text, keyword, mode='encrypt'):
    """
    Encrypts or decrypts text using the Vigenère Cipher.
    A keyword is repeated to match the length of the text.
    Validates keyword and handles non-alphabetic characters.
    """
    if not keyword.isalpha():
        raise ValueError("Keyword must be alphabetic.")
        
    keyword = keyword.lower()
    keyword_repeated = (keyword * (len(text) // len(keyword) + 1))[:len(text)]
    encrypted_text = ''
    
    for i in range(len(text)):
        if text[i].isalpha():
            pos = (ord(text[i].lower()) - 97 + ord(keyword_repeated[i]) - 97) % 26 if mode == 'encrypt' else (ord(text[i].lower()) - ord(keyword_repeated[i])) % 26
            encrypted_char = chr(pos + 97)
            encrypted_text += encrypted_char.upper() if text[i].isupper() else encrypted_char
        else:
            encrypted_text += text[i]
    return encrypted_text

def vigenere_cipher_decrypt(text, keyword):
    """
    Decrypts text using the Vigenère Cipher.
    Validates keyword.
    """
    return vigenere_cipher(text, keyword, mode='decrypt')


# --- Keyless Transposition Cipher ---
def keyless_transposition_cipher(text):
    """
    Encrypts text using a simple Keyless Transposition Cipher.
    Rearranges the text by dividing it into two halves and swapping them.
    Handles empty strings gracefully.
    """
    if not text:
        return text  # Return empty string as is
    mid = len(text) // 2
    return text[mid:] + text[:mid]

def keyless_transposition_cipher_decrypt(text):
    """
    Decrypts text using Keyless Transposition by reversing the swap.
    Handles empty strings gracefully.
    """
    if not text:
        return text  # Return empty string as is
    mid = len(text) // 2
    return text[-mid:] + text[:-mid]


# --- Keyed Transposition Cipher ---
def keyed_transposition_cipher(text, key):
    """
    Encrypts text using a Keyed Transposition Cipher.
    Rearranges characters based on the key order.
    Validates key and handles non-alphabetic characters.
    """
    if not key or len(set(key)) != len(key):
        raise ValueError("Key must be a non-empty string of unique characters.")
    
    # Create a list of the positions of the sorted key
    key_length = len(key)
    key_order = sorted(range(key_length), key=lambda k: key[k])
    
    # Prepare a grid to store characters
    grid = [''] * key_length
    index = 0

    # Fill the grid with characters from the text
    for char in text:
        grid[index % key_length] += char
        index += 1

    # Rearrange the grid based on the order of the key
    encrypted_text = ''.join(grid[i] for i in key_order)
    return encrypted_text


def keyed_transposition_cipher_decrypt(text, key):
    """
    Decrypts text using a Keyed Transposition Cipher.
    Rearranges characters based on the key order.
    Validates key.
    """
    if not key or len(set(key)) != len(key):
        raise ValueError("Key must be a non-empty string of unique characters.")
    
    # Create a list of the positions of the sorted key
    key_length = len(key)
    key_order = sorted(range(key_length), key=lambda k: key[k])
    
    # Calculate how many characters will go in each column
    num_full_columns = len(text) // key_length
    num_short_columns = len(text) % key_length
    
    # Calculate the number of characters in each column
    column_lengths = [num_full_columns + (1 if i < num_short_columns else 0) for i in range(key_length)]
    
    # Create the grid for decryption
    grid = [''] * key_length
    index = 0
    
    # Fill the grid according to the column lengths
    for col in key_order:
        for _ in range(column_lengths[col]):
            grid[col] += text[index]
            index += 1
            
    # Read the grid column-wise to get the decrypted text
    decrypted_text = ''.join(''.join(grid[i]) for i in range(key_length))
    return decrypted_text
def combined_keyless_keyed_transposition_cipher(text, key):
    """
    Encrypts text using a combination of Keyless and Keyed Transposition.
    First rearranges the text using Keyless Transposition, then applies Keyed Transposition.
    Validates key.
    """
    if not key or len(set(key)) != len(key):
        raise ValueError("Key must be a non-empty string of unique characters.")

    # Keyless Transposition: Rearrange text by swapping halves
    mid = len(text) // 2
    keyless_transposed_text = text[mid:] + text[:mid]
    
    # Keyed Transposition: Rearranging using the key
    key_length = len(key)
    key_order = sorted(range(key_length), key=lambda k: key[k])
    
    grid = [''] * key_length
    index = 0

    for char in keyless_transposed_text:
        grid[index % key_length] += char
        index += 1

    # Rearranging the grid based on the key order
    encrypted_text = ''.join(grid[i] for i in key_order)
    return encrypted_text


def combined_keyless_keyed_transposition_cipher_decrypt(text, key):
    """
    Decrypts text using a combination of Keyless and Keyed Transposition.
    Reverses the process of the combined Keyless and Keyed Transposition Cipher.
    Validates key.
    """
    if not key or len(set(key)) != len(key):
        raise ValueError("Key must be a non-empty string of unique characters.")

    # Keyed Transposition: Reconstruct the grid
    key_length = len(key)
    key_order = sorted(range(key_length), key=lambda k: key[k])
    
    num_full_columns = len(text) // key_length
    num_short_columns = len(text) % key_length
    column_lengths = [num_full_columns + (1 if i < num_short_columns else 0) for i in range(key_length)]
    
    grid = [''] * key_length
    index = 0

    # Fill the grid according to the column lengths
    for col in key_order:
        for _ in range(column_lengths[col]):
            grid[col] += text[index]
            index += 1
            
    # Read the grid column-wise to get the intermediate text
    intermediate_text = ''.join(''.join(grid[i]) for i in range(key_length))
    
    # Keyless Transposition: Reverse the swapping of halves
    mid = len(intermediate_text) // 2
    decrypted_text = intermediate_text[mid:] + intermediate_text[:mid]
    
    return decrypted_text

def double_transposition_cipher(text, key1, key2):
    """
    Encrypts text using the Double Transposition Cipher.
    Applies two rounds of transposition using two different keys.
    Validates both keys.
    """
    if not key1 or len(set(key1)) != len(key1):
        raise ValueError("First key must be a non-empty string of unique characters.")
    if not key2 or len(set(key2)) != len(key2):
        raise ValueError("Second key must be a non-empty string of unique characters.")

    # First Transposition using key1
    first_encrypted_text = keyed_transposition_cipher(text, key1)

    # Second Transposition using key2
    second_encrypted_text = keyed_transposition_cipher(first_encrypted_text, key2)

    return second_encrypted_text


def double_transposition_cipher_decrypt(text, key1, key2):
    """
    Decrypts text using the Double Transposition Cipher.
    Reverses the process by applying two rounds of decryption.
    Validates both keys.
    """
    if not key1 or len(set(key1)) != len(key1):
        raise ValueError("First key must be a non-empty string of unique characters.")
    if not key2 or len(set(key2)) != len(key2):
        raise ValueError("Second key must be a non-empty string of unique characters.")

    # First Decryption using key2
    first_decrypted_text = keyed_transposition_cipher_decrypt(text, key2)

    # Second Decryption using key1
    original_text = keyed_transposition_cipher_decrypt(first_decrypted_text, key1)

    return original_text

def create_playfair_matrix(key):
    """
    Create a 5x5 matrix for Playfair Cipher based on the provided key.
    The key is processed to remove duplicates and fill the matrix with remaining letters.
    'J' is typically combined with 'I'.
    """
    key = key.upper().replace('J', 'I')
    matrix = []
    seen = set()

    # Add unique letters from the key to the matrix
    for char in key:
        if char not in seen and char.isalpha():
            seen.add(char)
            matrix.append(char)

    # Fill the matrix with remaining letters of the alphabet
    for char in range(65, 91):  # ASCII values for A-Z
        letter = chr(char)
        if letter not in seen and letter != 'J':
            seen.add(letter)
            matrix.append(letter)

    # Create a 5x5 matrix
    return [matrix[i:i + 5] for i in range(0, 25, 5)]


def format_plaintext(plaintext):
    """
    Prepare the plaintext for Playfair Cipher encryption.
    It removes non-alphabetic characters and formats it by inserting 'X' between identical letters.
    If the length is odd, adds an 'X' at the end.
    """
    plaintext = plaintext.upper().replace('J', 'I')
    formatted = ""

    # Create digraphs
    i = 0
    while i < len(plaintext):
        char1 = plaintext[i]
        if i + 1 < len(plaintext):
            char2 = plaintext[i + 1]
            if char1 == char2:  # If identical letters, insert 'X'
                formatted += char1 + 'X'
                i += 1
            else:
                formatted += char1 + char2
                i += 2
        else:
            formatted += char1 + 'X'  # Add 'X' if last character is alone
            i += 1

    return formatted


def playfair_encrypt(plaintext, key):
    """
    Encrypts plaintext using the Playfair Cipher.
    The plaintext is processed and then encrypted using the generated matrix.
    """
    matrix = create_playfair_matrix(key)
    formatted_text = format_plaintext(plaintext)
    ciphertext = ""

    for i in range(0, len(formatted_text), 2):
        char1 = formatted_text[i]
        char2 = formatted_text[i + 1]
        row1, col1 = divmod(matrix.index(char1), 5)
        row2, col2 = divmod(matrix.index(char2), 5)

        if row1 == row2:  # Same row
            ciphertext += matrix[row1][(col1 + 1) % 5]
            ciphertext += matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:  # Same column
            ciphertext += matrix[(row1 + 1) % 5][col1]
            ciphertext += matrix[(row2 + 1) % 5][col2]
        else:  # Rectangle swap
            ciphertext += matrix[row1][col2]
            ciphertext += matrix[row2][col1]

    return ciphertext


def playfair_decrypt(ciphertext, key):
    """
    Decrypts ciphertext using the Playfair Cipher.
    The ciphertext is processed and then decrypted using the generated matrix.
    """
    matrix = create_playfair_matrix(key)
    formatted_text = ciphertext
    plaintext = ""

    for i in range(0, len(formatted_text), 2):
        char1 = formatted_text[i]
        char2 = formatted_text[i + 1]
        row1, col1 = divmod(matrix.index(char1), 5)
        row2, col2 = divmod(matrix.index(char2), 5)

        if row1 == row2:  # Same row
            plaintext += matrix[row1][(col1 - 1) % 5]
            plaintext += matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:  # Same column
            plaintext += matrix[(row1 - 1) % 5][col1]
            plaintext += matrix[(row2 - 1) % 5][col2]
        else:  # Rectangle swap
            plaintext += matrix[row1][col2]
            plaintext += matrix[row2][col1]

    return plaintext

def display_menu():
    """
    Displays the main menu of available ciphers.
    """
    print("\n\n\n\nWelcome to the Encryption/Decryption CLI Tool")
    print("Select a cipher:")
    print("1. Additive Cipher")
    print("2. Multiplicative Cipher")
    print("3. Affine Cipher")
    print("4. Monoalphabetic Substitution Cipher")
    print("5. Autokey Cipher")
    print("6. Playfair Cipher")
    print("7. Vigenère Cipher")
    print("8. Keyless Transposition Cipher")
    print("9. Keyed Transposition Cipher")
    print("10. Combined Keyless and Keyed Approach")
    print("11. Double Transposition Cipher")
    print("0. Exit")


def main():
    while True:
        display_menu()
        choice = input("Enter the number of the cipher you want to use (0 to exit): ")

        if choice == "0":
            print("Exiting the program. Goodbye!")
            break

        # Get plaintext and keys as necessary
        plaintext = input("Enter the plaintext (only alphabets allowed): ").strip()

        # Handle edge case: Check for non-alphabetic characters
        if not plaintext.isalpha():
            print("Error: Plaintext should contain only alphabets.")
            continue

        if choice in ["1", "2", "3", "4", "5", "6", "7", "10", "11"]:  # Requires a key or keys
            key1 = input("Enter the first key (non-empty, unique characters): ").strip()

            # Handle edge case: Validate keys
            if not key1 or len(set(key1)) != len(key1):
                print("Error: Key must be a non-empty string of unique characters.")
                continue

            # For the Affine Cipher, require a second key
            if choice == "3":
                key2 = input("Enter the second key (integer): ").strip()
                try:
                    key2 = int(key2)
                except ValueError:
                    print("Error: Second key must be an integer.")
                    continue

            if choice == "11":  # For Double Transposition Cipher
                key2 = input("Enter the second key (non-empty, unique characters): ").strip()
                if not key2 or len(set(key2)) != len(key2):
                    print("Error: Second key must be a non-empty string of unique characters.")
                    continue

        # Choose encryption or decryption
        action = input("Type 'e' for encryption or 'd' for decryption: ").strip().lower()

        if action == 'e':
            if choice == "1":
                result = additive_cipher(plaintext, int(key1))
                print(f"Ciphertext: {result}")
            elif choice == "2":
                result = multiplicative_cipher(plaintext, int(key1))
                print(f"Ciphertext: {result}")
            elif choice == "3":
                result = affine_cipher(plaintext, int(key1), key2)
                print(f"Ciphertext: {result}")
            elif choice == "4":
                result = monoalphabetic_cipher(plaintext, key1)
                print(f"Ciphertext: {result}")
            elif choice == "5":
                result = autokey_cipher(plaintext, key1)
                print(f"Ciphertext: {result}")
            elif choice == "6":
                result = playfair_encrypt(plaintext, key1)
                print(f"Ciphertext: {result}")
            elif choice == "7":
                result = vigenere_cipher(plaintext, key1)
                print(f"Ciphertext: {result}")
            elif choice == "8":
                result = keyless_transposition_cipher(plaintext)
                print(f"Ciphertext: {result}")
            elif choice == "9":
                result = keyed_transposition_cipher(plaintext, key1)
                print(f"Ciphertext: {result}")
            elif choice == "10":
                result = combined_keyless_keyed_transposition_cipher(plaintext, key1)
                print(f"Ciphertext: {result}")
            elif choice == "11":
                result = double_transposition_cipher(plaintext, key1, key2)
                print(f"Ciphertext: {result}")

        elif action == 'd':
            if choice == "1":
                result = additive_cipher_decrypt(plaintext, int(key1))
                print(f"Plaintext: {result}")
            elif choice == "2":
                result = multiplicative_cipher_decrypt(plaintext, int(key1))
                print(f"Plaintext: {result}")
            elif choice == "3":
                result = affine_cipher_decrypt(plaintext, int(key1), key2)
                print(f"Plaintext: {result}")
            elif choice == "4":
                result = monoalphabetic_cipher_decrypt(plaintext, key1)
                print(f"Plaintext: {result}")
            elif choice == "5":
                result = autokey_cipher_decrypt(plaintext, key1)
                print(f"Plaintext: {result}")
            elif choice == "6":
                result = playfair_decrypt(plaintext, key1)
                print(f"Plaintext: {result}")
            elif choice == "7":
                result = vigenere_cipher_decrypt(plaintext, key1)
                print(f"Plaintext: {result}")
            elif choice == "8":
                result = keyless_transposition_cipher_decrypt(plaintext)
                print(f"Plaintext: {result}")
            elif choice == "9":
                result = keyed_transposition_cipher_decrypt(plaintext, key1)
                print(f"Plaintext: {result}")
            elif choice == "10":
                result = combined_keyless_keyed_transposition_cipher_decrypt(plaintext, key1)
                print(f"Plaintext: {result}")
            elif choice == "11":
                result = double_transposition_cipher_decrypt(plaintext, key1, key2)
                print(f"Plaintext: {result}")

        else:
            print("Invalid action. Please type 'e' for encryption or 'd' for decryption.")


if __name__ == "__main__":
    main()

       
