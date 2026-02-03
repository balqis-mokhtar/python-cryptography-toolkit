import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from scapy.all import IP, rdpcap, Ether, TCP, UDP, Raw
from Crypto.Hash import HMAC, SHA256
import hashlib

def encrypt_data(data, key, iv):
    """
    Initialize an AES cipher object using CBC mode and encrypt data.

    :param data: The plaintext data to be encrypted (byte string).
    :param key: The encryption key (byte string).
    :param iv: The initialization vector (byte string).
    :return: Encrypted data (byte string).
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def compute_hmac(data, key):
    """
    Compute HMAC for the given data using SHA-256.

    :param data: Data to be authenticated (byte string).
    :param key: HMAC key (byte string).
    :return: HMAC value (byte string).
    """
    hmac = HMAC.new(key, digestmod=SHA256)
    hmac.update(data)
    return hmac.digest()

def calculate_packet_hash(packet):
    """
    Calculate a SHA-256 hash of the given packet for integrity checking.

    :param packet: The Scapy packet object.
    :return: SHA-256 hash as a hexadecimal string.
    """
    hash_obj = hashlib.sha256()
    hash_obj.update(bytes(packet))
    return hash_obj.hexdigest()

def create_esp_packet(original_packet, mode, key, iv, hmac_key):
    """
    Create an ESP packet in either transport or tunnel mode.

    :param original_packet: Scapy packet object to be encrypted.
    :param mode: 'transport' or 'tunnel'.
    :param key: AES encryption key (byte string).
    :param iv: Initialization vector for AES (byte string).
    :param hmac_key: HMAC key (byte string).
    :return: Modified ESP packet.

    Reference:
    [1] OpenAI, "Implementing ESP Packets with AES and HMAC in Python," ChatGPT, 2024. [Online]. Available: https://chat.openai.com/
    """
    spi = bytes([1]) * 4  # SPI: 4 bytes of 1s
    seq_num = b'\x00\x00\x00\x01'  # Sequence number: 1

    if mode == 'transport':
        if TCP in original_packet:
            payload_data = bytes(original_packet[IP].payload)  # Includes TCP header + payload
            next_header = bytes([6])  # TCP protocol number
        elif UDP in original_packet:
            payload_data = bytes(original_packet[IP].payload)  # Includes UDP header + payload
            next_header = bytes([17])  # UDP protocol number
        else:
            raise ValueError("Unsupported protocol. Only TCP and UDP are supported.")

        original_packet[IP].remove_payload()

    elif mode == 'tunnel':
        payload_data = bytes(original_packet)
        next_header = bytes([original_packet.proto])

    else:
        raise ValueError("Invalid mode. Choose 'tunnel' or 'transport'.")

    padding_length = AES.block_size - (len(payload_data) % AES.block_size)
    padded_data = pad(payload_data, AES.block_size)

    padding_length_bytes = bytes([padding_length])
    esp_trailer = padding_length_bytes + next_header

    encrypted_payload = encrypt_data(padded_data + esp_trailer, key, iv)

    esp_payload = spi + seq_num + iv + encrypted_payload

    esp_auth = compute_hmac(esp_payload, hmac_key)

    if mode == 'transport':
        original_packet /= Raw(load=esp_payload + esp_auth)
        return original_packet

    elif mode == 'tunnel':
        new_ip_packet = IP(src="192.168.99.99", dst=original_packet[IP].dst)
        new_ip_packet.add_payload(esp_payload + esp_auth)
        return new_ip_packet

def main():
    """
    Main function to process command line arguments, read pcap file, encrypt payload,
    construct ESP packet, and display results.
    """
    try:
        if len(sys.argv) != 3:
            raise ValueError("Usage: python3 Q5.py [path_to_pcap_file] [mode]")

        packet_file = sys.argv[1]
        mode = sys.argv[2].strip().lower()

        if mode not in ['transport', 'tunnel']:
            raise ValueError("Invalid mode. Choose 'tunnel' or 'transport'.")

        packets = rdpcap(packet_file)
        original_packet = packets[0]

        if Ether in original_packet:
            original_packet = original_packet[IP]

        key = hashlib.sha256(b"secret_key").digest()[:16]
        iv = hashlib.sha256(b"initialization_vector").digest()[:16]
        hmac_key = hashlib.sha256(b"hmac_key").digest()

        esp_packet = create_esp_packet(original_packet, mode, key, iv, hmac_key)

        packet_hash = calculate_packet_hash(esp_packet)
        print("SHA-256 Hash of the encrypted ESP packet:", packet_hash)

    except ValueError as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
