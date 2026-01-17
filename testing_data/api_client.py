import requests
import os

# Ключи API в переменных
STRIPE_API_KEY = "sk_live_51Hzyxwvutsrqponmlkjihgfedcba098765"
GOOGLE_API_KEY = "AIzaSyBzyxwvutsrqponmlkjihgfedcba0987654321"
SENDGRID_API_KEY = "SG.zyxwvutsrqponmlkjihgfedcba.1234567890123456"

# Ключи в словарях
CONFIG = {
    'api_keys': {
        'weather': '1234567890abcdefghijklmnopqrstuvw',
        'maps': 'AIzaSyCabcdefghijklmnopqrstuvwxyz-987654',
        'payment': 'sk_test_51Hzyxwvutsrqponmlkjihgfedcba'
    },
    'secrets': {
        'encryption_key': 'my-32-char-encryption-key-right-here!!',
        'jwt_secret': 'jwt-super-secret-2025-very-long-string'
    }
}

# URL с учетными данными
DATABASE_URL = "postgresql://dbuser:dbpassword123@localhost:5432/mydb"
REDIS_URL = "redis://default:redis_password@localhost:6379"
MONGODB_URL = "mongodb+srv://admin:mongo_pass_2025@cluster0.mongodb.net/mydb"

class APIClient:
    def __init__(self):
        # Пароль в конструкторе
        self.password = "ClientPass2025!"
        self.api_key = "client_api_key_abcdef1234567890"
        
    def connect_to_database(self):
        # Пароль в вызове функции
        connection = {
            'host': 'localhost',
            'user': 'app_user',
            'password': 'app_db_password_secure',
            'database': 'app_db'
        }
        return connection
    
    def get_sensitive_config(self):
        return {
            'private_key': '-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhki...',
            'certificate': '-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAg...',
            'passphrase': 'cert_passphrase_2025'
        }

# Пример функции с паролем в аргументах
def create_connection(host, port, username, password, database):
    conn_string = f"host={host} port={port} user={username} password={password} dbname={database}"
    return conn_string

# Вызов функции с хардкодированным паролем
connection = create_connection(
    host="localhost",
    port=5432,
    username="test_user",
    password="test_pass_2025", 
    database="test_db"
)

# Подключение с использованием строки подключения
sqlalchemy_url = "mysql://root:mysql_root_pass@localhost:3306/app_db"