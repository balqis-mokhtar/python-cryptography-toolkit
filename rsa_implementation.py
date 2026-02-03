import random
import sys

def check_prime(num):
    """
    Checks if a number is prime.
    
    Parameters:
    - num (int): The number to check for primality.
    
    Raises:
    - ValueError: If num is not a prime number.
    """
    if num < 2:
        raise ValueError("Both p and q need to be prime numbers.")
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            raise ValueError("Both p and q need to be prime numbers.")
    return True

def gcd(a, b):
    """
    Compute the greatest common divisor using Euclid's algorithm.
    
    Parameters:
    - a (int): First integer
    - b (int): Second integer
    
    Returns:
    - int: The greatest common divisor of a and b.
    """
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    """
    Compute the modular inverse of e modulo phi using the Extended Euclidean Algorithm.
    
    Parameters:
    - e (int): The exponent to find the inverse of.
    - phi (int): The modulus.
    
    Returns:
    - int: The modular inverse of e modulo phi.

    [1] OpenAI, "Extended Euclidean Algorithm for Modular Inverse Calculation in Python," ChatGPT, 2024. [Online]. Available: https://chat.openai.com/
    """
    def egcd(a, b):
        if a == 0:
            return b, 0, 1
        g, x, y = egcd(b % a, a)
        return g, y - (b // a) * x, x
    
    g, x, y = egcd(e, phi)
    if g != 1:
        raise ValueError("No modular inverse exists.")
    return x % phi

def generate_keypair(p, q):
    """
    Generate a public and private keypair using two prime numbers.
    Select the smallest possible e that is coprime with phi.
    
    Parameters:
    - p (int): A prime number.
    - q (int): Another prime number.
    
    Returns:
    - tuple: Tuple containing the public and private keys. e.g. ((e, n), (d, n))
    """
    if p == q:
        raise ValueError("p and q cannot be the same number.")

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 2
    while e < phi:
        if gcd(e, phi) == 1:
            break
        e += 1
    
    d = mod_inverse(e, phi)
    
    return (e, n), (d, n)

def encrypt(pk, plaintext):
    """
    Encrypt a plaintext string using a public key.
    
    Parameters:
    - pk (tuple): The public key.
    - plaintext (str): The text to encrypt.
    
    Returns:
    - list: A list of integers representing the encrypted message.
    """
    key, n = pk
    return [(ord(char) ** key) % n for char in plaintext]

def decrypt(pk, ciphertext):
    """
    Decrypt a list of integers back into a string using a private key.
    
    Parameters:
    - pk (tuple): The private key.
    - ciphertext (list): The encrypted message as a list of integers.
    
    Returns:
    - str: The decrypted message.
    """
    key, n = pk
    return ''.join([chr((char ** key) % n) for char in ciphertext])
    
def validate_input_args(args):
    """
    Validates the command-line input arguments.
    """
    if len(args) != 4:
        raise ValueError("Usage: python Q3.py <prime_p> <prime_q> <message>")
    
    p = int(args[1])
    q = int(args[2])
    message = args[3]

    if p <= 10 or q <= 10:
        raise ValueError("Both p and q need to be greater than 10.")

    check_prime(p)
    check_prime(q)

    if p == q:
        raise ValueError("p and q cannot be equal.")
    
    return p, q, message

def main():
    """
    Main function to execute RSA-like encryption and decryption based on command line inputs.
    """
    try:
        p, q, message = validate_input_args(sys.argv)

        public, private = generate_keypair(p, q)
        print("Public key is", public)
        print("Private key is", private)

        encrypted_msg = encrypt(public, message)
        print("Encrypted message is:")
        print(''.join(map(lambda x: str(x), encrypted_msg)))
        print("Decrypted message is:")
        print(decrypt(private, encrypted_msg))
    except ValueError as e:
        print("Error:", e)

if __name__ == '__main__':
    main()
