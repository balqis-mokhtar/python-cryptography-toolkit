from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from base64 import b64encode, b64decode
import os

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Derives a cryptographic key from a given password and salt using PBKDF2 HMAC.
    
    Parameters:
    - password (bytes): The password used to generate the key.
    - salt (bytes): A salt used to derive the key. 
    
    Returns:
    - bytes: The derived 256-bit (32 bytes) cryptographic key.
    """
    # Use a default salt if no salt is provided
    if len(salt) == 0:
        salt = bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000
    )
    return kdf.derive(password)

def check_iv_length(iv: bytes):
    """
    Ensures that the IV (Initialization Vector) is 16 bytes long for AES encryption.
    
    Parameters:
    - iv (bytes): The IV for AES encryption.
    
    Raises:
    - ValueError: If the IV is not 16 bytes long.
    """
    if len(iv) != 16:
        raise ValueError("IV must be 16 bytes (128 bits) long.")
    
    return iv

def add_padding(plaintext: bytes, block_size: int) -> bytes:
    """
    Adds padding to the plaintext to make its length a multiple of the block size.
    Padding should follow PKCS#7 padding scheme. This scheme adds padding bytes where each byte's value is equal to the number of padding bytes added. For example, if 3 bytes of padding are needed, the padding would be 03 03 03.
    
    Parameters:
    - plaintext (bytes): The data to be encrypted.
    - block_size (int): The block size required by the encryption algorithm.
    
    Returns:
    - bytes: The padded plaintext.
    """
    padding_size = block_size - len(plaintext) % block_size
    padding = bytes([padding_size] * padding_size)
    return plaintext + padding

def remove_padding(padded_plaintext: bytes) -> bytes:
    """
    Removes padding from the decrypted plaintext.
    
    Parameters:
    - padded_plaintext (bytes): The decrypted data with padding.
    
    Returns:
    - bytes: The plaintext without padding.
    """
    padding_size = padded_plaintext[-1]
    return padded_plaintext[:-padding_size]

def encrypt_aes(mode: str, key: bytes, plaintext: bytes, iv: bytes) -> tuple:
    """
    Encrypts the plaintext using AES in the specified mode with the given key and IV.
    
    Parameters:
    - mode (str): The AES encryption mode (e.g., ECB, CBC, CFB, OFB, CTR, GCM).
    - key (bytes): The encryption key.
    - plaintext (bytes): The data to encrypt.
    - iv (bytes): The initialization vector (IV) for certain AES modes.
    
    Returns:
    - Tuple (encrypted_data, tag): The encrypted data and the authentication tag (for GCM mode). Set the tag to None if not in GCM mode.

    Reference:
    [1] OpenAI, "AES Encryption and Decryption in Python," ChatGPT, 2024. [Online]. Available: https://chat.openai.com/
    """
    # Use a default IV if none is provided
    if len(iv) == 0:
        iv = bytes.fromhex("5e8f16368792149f036e937dccd7c95b")
    else:
        iv = check_iv_length(iv)

    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        padded_plaintext = add_padding(plaintext, 16)
        encrypted = encryptor.update(padded_plaintext) + encryptor.finalize()
        return encrypted, None
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padded_plaintext = add_padding(plaintext, 16)
        encrypted = encryptor.update(padded_plaintext) + encryptor.finalize()
        return encrypted, None
    elif mode == "CFB":
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        return encrypted, None
    elif mode == "OFB":
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        return encrypted, None
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        return encrypted, None
    elif mode == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
        encryptor = cipher.encryptor()
        encrypted = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag
        return encrypted, tag
    else:
        raise ValueError("Unsupported mode")

def decrypt_aes(mode: str, key: bytes, ciphertext: bytes, iv: bytes, tag: bytes = None) -> bytes:
    """
    Decrypts the ciphertext using AES in the specified mode with the given key, IV, and tag (if GCM mode).
    
    Parameters:
    - mode (str): The AES decryption mode (e.g., ECB, CBC, CFB, OFB, CTR, GCM).
    - key (bytes): The decryption key.
    - ciphertext (bytes): The encrypted data to decrypt.
    - iv (bytes): The initialization vector (IV).
    - tag (bytes): The authentication tag (for GCM mode).
    
    Returns:
    - bytes: The decrypted plaintext.

    Reference:
    [1] OpenAI, "AES Encryption and Decryption in Python," ChatGPT, 2024. [Online]. Available: https://chat.openai.com/
    """
    # Use a default IV if none is provided
    if len(iv) == 0:
        iv = bytes.fromhex("5e8f16368792149f036e937dccd7c95b")
    else:
        iv = check_iv_length(iv)

    if mode == "ECB":
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted = remove_padding(decrypted_padded)
        return decrypted
    elif mode == "CBC":
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        decrypted = remove_padding(decrypted_padded)
        return decrypted
    elif mode == "CFB":
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted
    elif mode == "OFB":
        cipher = Cipher(algorithms.AES(key), modes.OFB(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted
    elif mode == "CTR":
        cipher = Cipher(algorithms.AES(key), modes.CTR(iv))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted
    elif mode == "GCM":
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
        decryptor = cipher.decryptor()
        decrypted = decryptor.update(ciphertext) + decryptor.finalize()
        return decrypted
    else:
        raise ValueError("Unsupported mode")



def main():
    """
    Main function to execute the encryption and decryption routine.
    
    This function handles user inputs, including password, salt, IV, and AES mode.
    It performs encryption and decryption, then displays the results.
    """
    try:
        # Check if password is provided
        password = input("Enter password: ")
        if not password:
            raise ValueError("Password cannot be empty.")
        password = password.encode()

        # Validate salt and IV inputs
        try:
            salt_input = input("Enter salt (leave blank for default): ")
            iv_input = input("Enter IV (leave blank for default): ")
            salt = bytes.fromhex(salt_input) if salt_input else b""
            iv = bytes.fromhex(iv_input) if iv_input else b""
        except ValueError:
            raise ValueError("Invalid hex string.")

        # Check if plaintext is provided
        plaintext = input("Enter plaintext: ")
        if not plaintext:
            raise ValueError("Plaintext cannot be empty.")
        plaintext = plaintext.encode()

        # Check if mode is valid
        mode = input("Enter AES mode (ECB, CBC, CFB, OFB, CTR, GCM): ")
        if mode not in ["ECB", "CBC", "CFB", "OFB", "CTR", "GCM"]:
            raise ValueError("Unsupported mode.")

        # Derive encryption key from password and salt
        key = derive_key(password, salt)

        # Encrypt the plaintext
        encrypted, tag = encrypt_aes(mode, key, plaintext, iv)
        encrypted_b64 = b64encode(encrypted).decode()
        print(f"Encrypted: {encrypted_b64}")

        # Decrypt the ciphertext
        decrypted = decrypt_aes(mode, key, b64decode(encrypted_b64), iv, tag)
        print(f"Decrypted: {decrypted.decode()}")

    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
