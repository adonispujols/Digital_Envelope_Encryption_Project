# CS 351001
# Project 2: Mini Applied Cryptography Project
# Fall 2025
# Group A Members: Bassil Saleh, Ethan Bunagan, Adonis Pujols, Amulya Prasad, Jonathan Metry

import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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
# AES FUNCTIONS (TO BE IMPLEMENTED BY GROUPMATES)
# ============================================================================

# def generate_aes_key():
#     """
#     TODO:Implement AES key generation. Generate a random AES secret key, then return it in bytes form
#     """
#     # Placeholder
#     return b"This is a 32-byte secret key!!"

# def encrypt_message_aes(message, aes_key):
#     """
#     TODO: Encrypt a message using AES encryption, return it in bytes
#     """
#     # Placeholder
#     return b"[AES_ENCRYPTED_MESSAGE_PLACEHOLDER]"

# def decrypt_message_aes(encrypted_message, aes_key):
#     """
#     TODO: Decrypt a message using AES decryption, return in bytes
#     """
#     # Placeholder
#     return b"I loveeee apples"
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