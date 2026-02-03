def check_prime(num):
    """
    Validates if a given number is a prime.
    
    Parameters:
    - num (int): The number to check for primality.
    
    Raises:
    - ValueError: If num is not a prime number.

    Reference:
    [1] OpenAI, "Prime Number Validation in Python," ChatGPT, 2024. [Online]. Available: https://chat.openai.com/
    """
    if num < 2:
        raise ValueError("Not a prime number.")
    for i in range(2, int(num**0.5) + 1):
        if num % i == 0:
            raise ValueError("Not a prime number.")
    return True

def generate_public_key(p, g, private_key):
    """
    Generates a public key for Diffie-Hellman key exchange.
    
    Parameters:
    - p (int): The prime modulus.
    - g (int): The base generator.
    - private_key (int): The private key.
    
    Returns:
    - int: The generated public key.
    """
    return pow(g, private_key, p)  # g^private_key % p

def compute_shared_secret(other_public, private_key, p):
    """
    Computes the shared secret using Diffie-Hellman key exchange.
    
    Parameters:
    - other_public (int): The other party's public key.
    - private_key (int): The private key of the current user.
    - p (int): The prime modulus.
    
    Returns:
    - int: The computed shared secret.
    """
    return pow(other_public, private_key, p)  # other_public^private_key % p

def main():
    """
    Main function to handle user input and execute Diffie-Hellman key exchange.
    """
    try:
        # Input for prime number p
        p = input("Enter prime number p: ")
        p = int(p)
        check_prime(p)
        
        # Input for generator g
        g = input("Enter generator g: ")
        g = int(g)

        # Input for Alice's private key
        alice_private = input("Enter Alice's private key: ")
        alice_private = int(alice_private)

        # Input and validation for Bob's private key
        bob_private = input("Enter Bob's private key: ")
        bob_private = int(bob_private)
        
        # Generating public keys
        alice_public = generate_public_key(p, g, alice_private)
        bob_public = generate_public_key(p, g, bob_private)

        # Computing shared secrets
        alice_secret = compute_shared_secret(bob_public, alice_private, p)
        bob_secret = compute_shared_secret(alice_public, bob_private, p)

        # Printing all keys and shared secrets
        print(f"Alice's private key: {alice_private}")
        print(f"Bob's private key: {bob_private}")
        print(f"Alice's public key: {alice_public}")
        print(f"Bob's public key: {bob_public}")
        print(f"Shared secret: {alice_secret} (Alice) | {bob_secret} (Bob)")
    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
