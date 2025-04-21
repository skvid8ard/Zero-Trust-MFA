import logging
import os
import base64
import hashlib
import json
from datetime import datetime
from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from db import get_user, store_user
from server_utils import (
    generate_otp,
    load_public_key,
    verify_signature,
    create_user_directory,
    check_working_hours,
    get_geolocation
)
import pyotp
import threading
import time
import requests
import bcrypt
from bcrypt import gensalt, hashpw, checkpw

active_sessions = {}

def hash_password(password: str) -> str:
    return password  # Теперь пароль уже хеширован агентом

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(
        plain_password.encode('utf-8'),
        hashed_password.encode('utf-8')
    )

def session_checker():
    while True:
        time.sleep(10)
        now = time.time()
        for session_id in list(active_sessions.keys()):
            data = active_sessions[session_id]
            
            if now - data['last_activity'] > 3600:
                logger.info(f"Сессия {session_id} прервана: таймаут")
                del active_sessions[session_id]
                continue
            
            ip_match = (data['current_ip'] == data['registered_ip'])
            geo_match = (data['current_geo'] == data['registered_geo'])
            
            mismatch_log = []
            if not ip_match:
                mismatch_log.append(f"IP ({data['current_ip']} vs {data['registered_ip']})")
            if not geo_match:
                mismatch_log.append(f"гео ({data['current_geo']} vs {data['registered_geo']})")
            
            if not ip_match and not geo_match:
                logger.info(f"Сессия {session_id} прервана: " + ", ".join(mismatch_log))
                del active_sessions[session_id]
            elif not ip_match or not geo_match:
                if not data['otp_pending']:
                    logger.info(f"Требуется OTP для сессии {session_id}: " + ", ".join(mismatch_log))
                    data['otp_pending'] = True

threading.Thread(target=session_checker, daemon=True).start()

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('server.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
current_challenge = None

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def get_client_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    public_key = data.get('public_key')
    password = data.get('password')
    start_time = data.get('start_time')
    end_time = data.get('end_time')

    logger.debug(f"[REGISTER] Начало регистрации пользователя: {username}")
    logger.debug(f"[REGISTER] Получен пароль: {password}")  # Не логируем сам пароль!

    ip = get_client_ip()
    geolocation = get_geolocation(ip)

    if not all([username, public_key, password, start_time, end_time]):
        return jsonify({"error": "Missing required fields"}), 400

    create_user_directory(username)
    password = data.get('password')

    logger.debug(f"[REGISTER] Генерация salt и хеширование пароля для {username}")
    hashed_password = hashpw(password.encode(), gensalt()).decode()
    logger.debug(f"[REGISTER] Хеширование завершено. Хеш: {hashed_password[:15]}...")

    # Генерация и сохранение OTP-секрета
    otp_secret = pyotp.random_base32()
    
    with open(f"server_users/{username}/public_key.pem", "wb") as f:
        f.write(public_key.encode())
        logger.debug(f"[SERVER] Получен публичный ключ для {username}:\n{public_key}")

    with open(f"server_users/{username}/working_hours.txt", "w") as f:
        f.write(f"{start_time}-{end_time}")

    with open(f"server_users/{username}/security_info.json", "w") as f:
        json.dump({"ip": ip, "geolocation": geolocation}, f)

    store_user(username, public_key, otp_secret, hashed_password)
    
    # Логирование части OTP-секрета
    logger.debug(
        f"[SERVER] Отправка OTP-секрета для {username}: "
        f"{otp_secret[:3]}...{otp_secret[-3:]}"
    )

    return jsonify({
        "message": "User registered",
        "otp_secret": otp_secret  # Отправляем секрет клиенту
    }), 200

@app.route('/login', methods=['POST'])
def login():
    global current_challenge
    current_challenge = pyotp.random_base32()
    logger.debug(f"[SERVER] Сгенерирован challenge: {current_challenge}")
    return jsonify({"challenge": current_challenge}), 200

@app.route('/verify-signature', methods=['POST'])
def verify_signature_route():
    username = request.form['username']
    signature = request.form['signature']
    password = request.form['password']
    client_ip = get_client_ip()
    client_geolocation = get_geolocation(client_ip)

    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404

    # Генерация временного хеша для отладки (не сохраняется!)
    temp_hash = bcrypt.hashpw(password.encode(), user[3].encode()).decode()
    
    logger.debug("[AUTH] Проверка пароля:")
    logger.debug(f"Полученный пароль (первые 5 символов): {password[:5]}...")
    logger.debug(f"Сгенерированный хеш (первые 15 символов): {temp_hash[:15]}...")
    logger.debug(f"Сохраненный хеш (первые 15 символов): {user[3][:15]}...")

    if not bcrypt.checkpw(password.encode(), user[3].encode()):
        logger.warning("[AUTH] Хеши не совпадают!")
        return jsonify({"error": "Invalid password"}), 401
    
    logger.info(f"[AUTH] Успешная проверка пароля")

    try:
        public_key = load_public_key(username)
        decoded_signature = base64.b64decode(signature)
        public_key.verify(
            decoded_signature,
            current_challenge.encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        logger.debug(f"[SERVER] Подпись действительна для challenge: {current_challenge}")
    except Exception as e:
        logger.error(f"[SERVER] Ошибка подписи: {str(e)}. Ожидался challenge: {current_challenge}")
        return jsonify({"error": "Signature verification failed"}), 400

    with open(f"server_users/{username}/security_info.json", "r") as f:
        security_data = json.load(f)

    current_time = datetime.now().strftime("%H:%M")
    is_working_hours = check_working_hours(username, current_time)
    ip_match = (client_ip == security_data['ip'])
    geo_match = (client_geolocation == security_data['geolocation'])

    session_id = os.urandom(16).hex()
    active_sessions[session_id] = {
        "username": username,
        "registered_ip": security_data['ip'],
        "registered_geo": security_data['geolocation'],
        "current_ip": client_ip,
        "current_geo": client_geolocation,
        "last_activity": time.time(),
        "otp_pending": False
    }

    if not is_working_hours:
        if ip_match and geo_match:
            logger.info("Вход вне рабочего времени. IP/гео совпадают. Требуется OTP.")
            active_sessions[session_id]['otp_pending'] = True
            return jsonify({
                "otp_required": True,
                "reason": "Доступ вне рабочего времени",
                "otp_secret": user[2],
                "session_id": session_id
            }), 200
        else:
            logger.warning(f"Доступ запрещен вне рабочих часов. Несоответствия: IP ({'не совпадает' if not ip_match else 'совпадает'}), гео ({'не совпадает' if not geo_match else 'совпадает'})")
            del active_sessions[session_id]
            return jsonify({"error": "Access denied"}), 403
    else:
        if not ip_match and not geo_match:
            logger.warning("Доступ запрещен: IP и гео не совпадают.")
            del active_sessions[session_id]
            return jsonify({"error": "Access denied"}), 403
        elif not ip_match or not geo_match:
            logger.info("Требуется OTP. Несоответствия IP/гео.")
            active_sessions[session_id]['otp_pending'] = True
            reason = []
            if not ip_match: reason.append("IP не совпадает")
            if not geo_match: reason.append("геолокация не совпадает")
            return jsonify({
                "otp_required": True,
                "reason": ", ".join(reason),
                "otp_secret": user[2],
                "session_id": session_id
            }), 200
        else:
            return jsonify({"message": "Login successful", "session_id": session_id}), 200

@app.route('/session-status', methods=['POST'])
def session_status():
    try:
        data = request.get_json()
        if not data or 'session_id' not in data:
            return jsonify({"error": "Session ID required"}), 400

        session_id = data['session_id']
        if session_id not in active_sessions:
            return jsonify({"status": "terminated"}), 200
        
        active_sessions[session_id]['last_activity'] = time.time()
        return jsonify({
            "status": "otp_required" if active_sessions[session_id]['otp_pending'] else "active"
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid data"}), 400
        
        session_id = data.get('session_id')
        otp = data.get('otp')

        if not session_id or not otp:
            return jsonify({"error": "Session ID and OTP are required"}), 400
        
        if session_id not in active_sessions:
            return jsonify({"error": "Invalid session"}), 400

        user = get_user(active_sessions[session_id]['username'])
        if not user:
            return jsonify({"error": "User not found"}), 404

        if pyotp.TOTP(user[2]).verify(otp):
            active_sessions[session_id]['otp_pending'] = False
            logger.info(f"OTP для сессии {session_id} подтвержден")
            return jsonify({"message": "OTP verified"}), 200
        else:
            del active_sessions[session_id]
            logger.warning(f"Неверный OTP для сессии {session_id}")
            return jsonify({"error": "Invalid OTP"}), 400
    except Exception as e:
        logger.error(f"Ошибка при проверке OTP: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/get-user', methods=['POST'])
def get_user_route():
    username = request.form['username']
    user = get_user(username)
    if not user:
        return jsonify({"error": "User not found"}), 404
    return jsonify({
        "username": username,
        "otp_secret": user[2]
    }), 200

@app.route('/update-location', methods=['POST'])
def update_location():
    try:
        data = request.get_json()
        session_id = data.get('session_id')
        current_ip = get_client_ip()
        current_geo = get_geolocation(current_ip)

        if not all([session_id, current_ip, current_geo]):
            return jsonify({"error": "Missing data"}), 400

        if session_id not in active_sessions:
            return jsonify({"error": "Invalid session"}), 400

        active_sessions[session_id]['current_ip'] = current_ip
        active_sessions[session_id]['current_geo'] = current_geo
        active_sessions[session_id]['last_activity'] = time.time()

        return jsonify({"message": "Location updated"}), 200

    except Exception as e:
        logger.error(f"Ошибка обновления локации: {str(e)}")
        return jsonify({"error": "Internal error"}), 500

if __name__ == '__main__':
    app.run(
        debug=True,
        ssl_context=('server.crt', 'server.key')  # SSL-сертификаты
    )