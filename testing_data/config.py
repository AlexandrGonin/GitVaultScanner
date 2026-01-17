# API ключи 
API_KEY = "sk_live_51Habcdefghijklmnopqrstuvwxyz123456"
SECRET_KEY = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Настройки приложения
APP_NAME = "Test Application"
DEBUG = True
PORT = 8000

# Пароль администратора 
ADMIN_PASSWORD = "SuperSecret123!"
DB_PASSWORD = "mysql_password_2025"

# Токены
GITHUB_TOKEN = "ghp_abcdefghijklmnopqrstuvwxyz1234567890"
SLACK_TOKEN = "xoxb-1234567890-123456789012-abcdefghijklmnopqrstuvw"

# JWT секрет
JWT_SECRET = "my_super_secret_jwt_key_that_is_very_long_and_secure_2025"

def get_database_config():
    """Возвращает конфигурацию базы данных"""
    return {
        'host': 'localhost',
        'port': 5432,
        'database': 'production_db',
        'username': 'admin_user',
        'password': 'db_admin_pass_secure'  # Должен обнаружиться
    }