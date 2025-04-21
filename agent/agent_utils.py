import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp
import logging
import hashlib

logger = logging.getLogger(__name__)

def generate_otp(otp_secret):
    totp = pyotp.TOTP(otp_secret)
    return totp.now()

def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_keys(username, private_key, public_key):
    user_dir = f"client_users/{username}"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)

    private_key_path = os.path.join(user_dir, "private_key.pem")
    with open(private_key_path, "wb") as private_file:
        private_file.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    public_key_path = os.path.join(user_dir, "public_key.pem")
    with open(public_key_path, "wb") as public_file:
        public_file.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

def sign_challenge(private_key, challenge):
    signature = private_key.sign(
        challenge.encode(),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    return base64.b64encode(signature).decode()