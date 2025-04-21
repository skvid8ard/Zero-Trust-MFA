import os
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp
import logging
import hashlib
import requests
from datetime import datetime

logger = logging.getLogger(__name__)

def generate_otp(otp_secret):
    totp = pyotp.TOTP(otp_secret)
    return totp.now()

def load_public_key(username):
    public_key_path = f"server_users/{username}/public_key.pem"
    with open(public_key_path, "rb") as f:
        public_key_pem = f.read()
    return serialization.load_pem_public_key(public_key_pem)

def create_user_directory(username):
    user_dir = f"server_users/{username}"
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
    return user_dir

def verify_signature(public_key, signature, challenge):
    try:
        public_key.verify(
            base64.b64decode(signature),
            challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        logger.info(f"Подпись действительна для challenge: {challenge}")
        return True
    except Exception as e:
        logger.error(f"Ошибка подписи: {e}")
        return False

def check_working_hours(username, current_time_str):
    with open(f"server_users/{username}/working_hours.txt", "r") as f:
        start_str, end_str = f.read().strip().split("-")
    
    start = datetime.strptime(start_str, "%H:%M").time()
    end = datetime.strptime(end_str, "%H:%M").time()
    current_time = datetime.strptime(current_time_str, "%H:%M").time()
    
    return start <= current_time <= end

def get_geolocation(ip: str) -> str:
    try:
        response = requests.get(f"https://ipapi.co/{ip}/json/", timeout=3)
        data = response.json()
        return f"{data.get('city', 'Unknown')}, {data.get('country', 'Unknown')}"
    except Exception as e:
        logger.error(f"Ошибка геолокации: {str(e)}")
        return "Unknown"