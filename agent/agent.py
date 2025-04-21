import requests
import socket
import json
import os
import time
from cryptography.hazmat.primitives import serialization
from agent_utils import generate_rsa_keys, save_keys, sign_challenge, generate_otp
import logging
import bcrypt

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def get_client_ip():
    services = [
        'https://api.ipify.org',
        'https://ipinfo.io/ip',
        'https://ifconfig.me/ip',
        'https://ident.me'
    ]
    for service in services:
        try:
            ip = requests.get(service, timeout=3).text.strip()
            if ip and not ip.startswith(('127.', '10.', '192.168.')):
                return ip
        except:
            continue
    return socket.gethostbyname(socket.gethostname())

def get_geolocation(ip):
    try:
        response = requests.get(f'https://ipapi.co/{ip}/json/')
        return f"{response.json().get('city')}, {response.json().get('country')}"
    except:
        return "Unknown"

def register_user(username, password, start_time, end_time):
    try:
        private_key, public_key = generate_rsa_keys()
        
        # Логирование ключей в PEM-формате
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        logger.debug(f"[AGENT] Приватный ключ:\n{private_pem.strip()}")
        logger.debug(f"[AGENT] Публичный ключ:\n{public_pem.strip()}")
        
        save_keys(username, private_key, public_key)
        ip = get_client_ip()
        geolocation = get_geolocation(ip)

        os.makedirs(f"client_users/{username}", exist_ok=True)

        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()

        hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

        response = requests.post(
            "https://127.0.0.1:5000/register",
            json={
                "username": username,
                "public_key": public_key_pem,
                "password": password,
                "start_time": start_time,
                "end_time": end_time
            },
            verify=False
        )
        
        # Обработка OTP-секрета
        if response.status_code == 200:
            response_data = response.json()
            otp_secret = response_data.get("otp_secret")
            
            # Сохранение секрета
            with open(f"client_users/{username}/otp_secret.txt", "w") as f:
                f.write(otp_secret)
                
            # Безопасное логирование
            logger.debug(
                f"[AGENT] Получен OTP-секрет: "
                f"{otp_secret[:3]}...{otp_secret[-3:]}"
            )
            
        logger.info(f"Ответ регистрации: {response.text}")
        
    except Exception as e:
        logger.error(f"Ошибка регистрации: {str(e)}")

def login_user(username, password):
    try:
        current_ip = get_client_ip()
        current_geo = get_geolocation(current_ip)

        response = requests.post(
            "https://127.0.0.1:5000/login",
            data={"username": username},
            verify=False
        )
        challenge = response.json().get('challenge')
        logger.debug(f"[CLIENT] Получен challenge: {challenge}")

        with open(f"client_users/{username}/private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), None)
        signed_challenge = sign_challenge(private_key, challenge)
        logger.debug(f"[CLIENT] Подписанный challenge (b64): {signed_challenge}")

        response = requests.post(
            "https://127.0.0.1:5000/verify-signature",
            data={
                "username": username,
                "signature": signed_challenge,
                "password": password,
                "geolocation": current_geo
            },
            verify=False
        )

        if response.status_code != 200:
            logger.error(f"Ошибка аутентификации: {response.text}")
            return

        response_data = response.json()
        session_id = response_data.get('session_id')

        if response_data.get('otp_required'):
            reason = response_data.get('reason', 'Требуется дополнительная проверка')
            logger.info(f"Требуется OTP. Причина: {reason}")
            otp_secret = response_data.get('otp_secret')
            generated_otp = generate_otp(otp_secret)
            logger.info(f"Сгенерированный OTP: {generated_otp}")
            otp = input("Введите OTP: ")
            otp_response = requests.post(
                "https://127.0.0.1:5000/verify-otp",
                json={"session_id": session_id, "otp": otp},
                verify=False
            )
            if otp_response.status_code != 200:
                logger.error("Ошибка проверки OTP")
                return

        logger.info(f"ID сессии: {session_id}")
        while True:
            time.sleep(10)
            current_ip = get_client_ip()
            current_geo = get_geolocation(current_ip)
            update_response = requests.post(
                "https://127.0.0.1:5000/update-location",
                json={"session_id": session_id},
                verify=False
            )
            if update_response.status_code != 200:
                logger.error("Ошибка обновления локации")
            
            status_response = requests.post(
                "https://127.0.0.1:5000/session-status",
                json={"session_id": session_id},
                verify=False
            )
            status_data = status_response.json()
            
            if status_data.get('status') == "otp_required":
                user_response = requests.post(
                    "https://127.0.0.1:5000/get-user",
                    data={"username": username},
                    verify=False
                )
                if user_response.status_code != 200:
                    logger.error("Ошибка получения данных пользователя")
                    break
                user_data = user_response.json()
                otp_secret = user_data.get('otp_secret')
                generated_otp = generate_otp(otp_secret)
                logger.info(f"Новый OTP: {generated_otp}")
                otp = input("Требуется OTP: ")
                otp_response = requests.post(
                    "https://127.0.0.1:5000/verify-otp",
                    json={"session_id": session_id, "otp": otp},
                    verify=False
                )
                if otp_response.status_code != 200:
                    break
            elif status_data.get('status') == "terminated":
                logger.info("Сессия прервана сервером")
                break

    except Exception as e:
        logger.error(f"Ошибка входа: {str(e)}")

if __name__ == "__main__":
    while True:
        print("1. Register\n2. Login\n3. Exit")
        choice = input("Select option: ")
        if choice == "1":
            username = input("Username: ")
            password = input("Password: ")
            start_time = input("Start time (HH:MM): ")
            end_time = input("End time (HH:MM): ")
            register_user(username, password, start_time, end_time)
        elif choice == "2":
            username = input("Username: ")
            password = input("Password: ")
            login_user(username, password)
        elif choice == "3":
            break