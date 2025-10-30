# CS 351001
# Project 2: Mini Applied Cryptography Project
# Fall 2025
# Group A Members: Bassil Saleh, Ethan Bunagan, Adonis Pujols, Amulya Prasad, Jonathan Metry


import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# ============================================================================
# RSA FUNCTIONS 
# ============================================================================


def generate_key_pair():
    """Generate an RSA private/public key pair"""
    # public_exponent (int) – The public exponent of the new key. Either 65537 or 3 (for legacy purposes). Almost everyone should use 65537.
    # key_size (int) – The length of the modulus in bits. For keys generated in 2015 it is strongly recommended to be at least 2048

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key


def serialize_private_key(private_key):
    """Serialize private key to PEM format"""
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_pem


def serialize_public_key(public_key):
    """Serialize public key to PEM format"""
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return public_pem


def encrypt_with_public_key(public_key, data):
    """Encrypt data using RSA public key (for encrypting AES key)"""
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


def decrypt_with_private_key(private_key, ciphertext):
    """Decrypt data using RSA private key (for decrypting AES key)"""
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext


def sign_message(private_key, message):
    """Sign a message using RSA private key"""
    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(public_key, signature, message):
    """Verify a signature using RSA public key"""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# ============================================================================
# AES FUNCTIONS 
# ============================================================================

def generate_aes_key(bit_length=256):
    """
    Generate an AES key for AES-GCM
    Returns: key bytes (32 bytes for 256-bits)
    """
    if bit_length not in (128, 192, 256):
        raise ValueError("bit length must be one of 128, 192, 256")
    return AESGCM.generate_key(bit_length=bit_length)

def encrypt_message_aes(message, aes_key):
    """
    Encrypt a message (bytes) using AES-GCM
    Returns: bytes = nonce (12) || ciphertext (contains tag)
    """
    if not isinstance(message, (bytes, bytearray)):
        raise TypeError("message must be bytes")
    if not isinstance(aes_key, (bytes, bytearray)):
        raise TypeError("aes_key must be bytes")
    
    aesgcm = AESGCM(aes_key)
    #12-byte nonce
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, message, associated_data=None)
    return nonce + ciphertext

def decrypt_message_aes(encrypted_message, aes_key):
    """
    Decrypt bytes produced by encrypt_message_aes.
    encrypted_message = nonce (12) || ciphertext_with_tag
    Returns: plaintext bytes
    """
    if not isinstance(encrypted_message, (bytes, bytearray)):
        raise TypeError("encrypted_message must by bytes")
    if not isinstance(aes_key, (bytes, bytearray)):
        raise TypeError("aes_key must be bytes")
    
    if len(encrypted_message) < 13:
        raise ValueError("encrypted data is too short to contain a nonce + tag")
    
    nonce = encrypted_message[:12]
    ciphertext = encrypted_message[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    return plaintext


# ============================================================================
# DIGITAL ENVELOPE DEMONSTRATION
# ============================================================================

def main():
    print("=" * 80)
    print("DIGITAL ENVELOPE IMPLEMENTATION")
    print("=" * 80)
    
    # Step 1: Generate sender's key pair
    print("STEP 1: Generating sender's RSA key pair:")
    print("-" * 80)
    sender_private_key, sender_public_key = generate_key_pair()
    print("Sender's private key (PEM format):")
    sender_private_pem = serialize_private_key(sender_private_key)
    print(sender_private_pem.decode())
    sender_public_pem = serialize_public_key(sender_public_key)
    print("Sender's public key (PEM format):")
    print(sender_public_pem.decode())
    print()
    
    # Step 2: Generate receiver's key pair
    print("STEP 2: Generating receiver's RSA key pair:")
    print("-" * 80)
    receiver_private_key, receiver_public_key = generate_key_pair()
    receiver_private_pem = serialize_private_key(receiver_private_key)
    print("Receiver's private key (PEM format):")
    print(receiver_private_pem.decode())
    receiver_public_pem = serialize_public_key(receiver_public_key)
    print("Receiver's public key (PEM format):")
    print(receiver_public_pem.decode())
    print()
    
    # Step 3: Sender generates AES secret key
    print("STEP 3: Sender generates AES secret key:")
    print("-" * 80)
    aes_secret_key = generate_aes_key()
    print(f"AES Secret Key: {aes_secret_key}")
    print()
    
    # Step 4: Sender encrypts the message with AES
    print("STEP 4: Sender encrypts the message with AES:")
    print("-" * 80)
    original_message = b"I loveeee apples"
    print(f"Original message: {original_message.decode()}")
    encrypted_message = encrypt_message_aes(original_message, aes_secret_key)
    print(f"Encrypted message: {encrypted_message}")
    print()
    
    # Step 5: Sender encrypts the AES key with receiver's public key
    print("STEP 5: Sender encrypts the AES secret key with receiver's public key:")
    print("-" * 80)
    encrypted_aes_key = encrypt_with_public_key(receiver_public_key, aes_secret_key)
    print("Encrypted AES key:")
    print(encrypted_aes_key)
    print()
    
    # Step 6: Sender creates the digital envelope (encrypted message + encrypted key)
    print("STEP 6: Sender creates the digital envelope:")
    print("-" * 80)
    digital_envelope = encrypted_message + encrypted_aes_key
    print("Digital envelope (encrypted message + encrypted AES key):")
    print(f"Length: {len(digital_envelope)} bytes")
    print(digital_envelope)
    print()
    
    # Step 7: Sender signs the digital envelope with their private key
    print("STEP 7: Sender signs the digital envelope with their private key...")
    print("-" * 80)
    signature = sign_message(sender_private_key, digital_envelope)
    print("Signature:")
    print(signature)
    print()
    
    # Step 8: Sender sends the digital envelope and signature to receiver
    print("STEP 8: Sender transmits digital envelope and signature to receiver:")
    print("-" * 80)
    print("Transmitted data:")
    print(f"  - Digital envelope: {len(digital_envelope)} bytes")
    print(f"  - Signature: {len(signature)} bytes")
    print()
    
    # Step 9: Receiver verifies the signature using sender's public key
    print("STEP 9: Receiver verifies signature using sender's public key:")
    print("-" * 80)
    is_valid = verify_signature(sender_public_key, signature, digital_envelope)
    print(f"Signature valid: {is_valid}")
    if not is_valid:
        print("ERROR: Signature verification failed! Message may be tampered.")
        return
    print("Signature verified successfully! Message is authentic.")
    print()
    
    # Step 10: Receiver extracts encrypted message and encrypted AES key
    print("STEP 10: Receiver extracts encrypted message and encrypted AES key:")
    print("-" * 80)
    # In real implementation, you'd need to know the size of encrypted_aes_key
    # For RSA 2048-bit, encrypted data is 256 bytes
    # TODO if you change the key size indicate it here
    encrypted_aes_key_size = 256
    received_encrypted_message = digital_envelope[:-encrypted_aes_key_size]
    received_encrypted_aes_key = digital_envelope[-encrypted_aes_key_size:]
    print(f"Extracted encrypted message: {received_encrypted_message}")
    print(f"Extracted encrypted AES key: {received_encrypted_aes_key}")
    print()
    
    # Step 11: Receiver decrypts the AES key with their private key
    print("STEP 11: Receiver decrypts the AES key with their private key:")
    print("-" * 80)
    decrypted_aes_key = decrypt_with_private_key(receiver_private_key, received_encrypted_aes_key)
    print(f"Decrypted AES key: {decrypted_aes_key}")
    print()
    
    # Step 12: Receiver decrypts the message with the decrypted AES key
    print("STEP 12: Receiver decrypts the message with the decrypted AES key:")
    print("-" * 80)
    decrypted_message = decrypt_message_aes(received_encrypted_message, decrypted_aes_key)
    print(f"Decrypted message: {decrypted_message.decode()}")
    print(f"Message matches original: {decrypted_message == original_message}")
    print()
    
    print("=" * 80)
    print("DIGITAL ENVELOPE SUCCESSFUL!")
    print("=" * 80)


if __name__ == "__main__":
    main()
