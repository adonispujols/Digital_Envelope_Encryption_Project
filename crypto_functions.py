# CS 351001
# Project 2: Mini Applied Cryptography Project
# Fall 2025
# Group A Members: Bassil Saleh, Ethan Bunagan, Adonis Pujols, Amulya Prasad, Jonathan Metry

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

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