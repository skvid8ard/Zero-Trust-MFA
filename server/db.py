import sqlite3

DATABASE = 'users.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def create_table():
    db = get_db()
    c = db.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    public_key TEXT NOT NULL,
                    otp_secret TEXT NOT NULL,
                    password TEXT NOT NULL
                 )''')
    db.commit()
    db.close()

def store_user(username, public_key, otp_secret, password):
    db = get_db()
    c = db.cursor()
    c.execute(
        "INSERT INTO users (username, public_key, otp_secret, password) "
        "VALUES (?, ?, ?, ?)",
        (username, public_key, otp_secret, password)
    )
    db.commit()
    db.close()

def get_user(username):
    db = get_db()
    c = db.cursor()
    c.execute("SELECT username, public_key, otp_secret, password FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    db.close()
    return user if user else None

create_table()