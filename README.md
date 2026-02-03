# Python Cryptography Toolkit

A collection of cryptographic algorithms and security protocols implemented in Python, including AES encryption, RSA, Diffie-Hellman key exchange, digital certificates, and IPsec ESP.

**Built for**: CYBR3000 - Information Security, University of Queensland (2024)

## What's Inside

### AES Encryption (`aes_encryption.py`)
- Multiple modes: ECB, CBC, CFB, OFB, CTR, GCM
- PBKDF2 key derivation
- PKCS#7 padding implementation

**Usage:**
```bash
python3 aes_encryption.py
```

### Diffie-Hellman Key Exchange (`diffie_hellman.py`)
- Manual implementation of DH protocol
- Prime number validation
- Shared secret computation

**Usage:**
```bash
python3 diffie_hellman.py
```

### RSA Encryption (`rsa_implementation.py`)
- Custom RSA key generation
- Manual modular arithmetic
- Encrypt/decrypt text messages

**Usage:**
```bash
python3 rsa_implementation.py <prime_p> <prime_q> <message>
```

**Example:**
```bash
python3 rsa_implementation.py 61 53 "Hello"
```

### Digital Certificate Generator (`digital_certificate.py`)
- Creates X.509 certificates
- RSA key pair generation
- PEM format serialization

**Usage:**
```bash
python3 digital_certificate.py
```

### IPsec ESP Protocol (`ipsec_esp.py`)
- Implements IPsec Encapsulating Security Payload
- Supports tunnel and transport modes
- AES-CBC encryption with HMAC authentication

**Usage:**
```bash
python3 ipsec_esp.py <path_to_pcap> <mode>
```

**Example:**
```bash
python3 ipsec_esp.py /path/to/packet.pcap tunnel
python3 ipsec_esp.py /path/to/packet.pcap transport
```

## Requirements
Python 3.9
cryptography
pycryptodome
scapy
hashlib (built-in)

**Install dependencies:**
```bash
pip install cryptography pycryptodome scapy
```

## Key Features

- ✅ Multiple AES encryption modes with custom padding
- ✅ Manual cryptographic implementations (RSA, DH)
- ✅ PKI simulation with certificate generation
- ✅ Network security protocols (IPsec ESP)
- ✅ Comprehensive error handling
- ✅ Educational code with detailed comments

## Technologies

- **Python 3.9** - Core implementation
- **cryptography** - Certificate and RSA operations
- **pycryptodome** - AES encryption for ESP
- **Scapy** - Packet manipulation

## Academic Context

Created for CYBR3000 Information Security coursework at UQ. This project demonstrates:
- Symmetric and asymmetric encryption
- Key exchange protocols
- Public Key Infrastructure (PKI)
- Secure network protocols

## License

MIT License - see LICENSE file

## Note

This is educational code from a 2024 university assignment. If you're a student in a similar course, ensure you follow your institution's academic integrity policies.

---
