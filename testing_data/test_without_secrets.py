def calculate_sum(a, b):
    return a + b

class Calculator:
    def __init__(self):
        self.result = 0
    
    def add(self, x, y):
        self.result = x + y
        return self.result
    
    def multiply(self, x, y):
        self.result = x * y
        return self.result

# Пример использования
if __name__ == "__main__":
    calc = Calculator()
    print(f"2 + 3 = {calc.add(2, 3)}")
    print(f"4 * 5 = {calc.multiply(4, 5)}")
    
    # Переменные без секретов
    username = "user123"
    email = "user@example.com"
    age = 25
    
    # Словарь без секретов
    config = {
        'debug': True,
        'version': '1.0.0',
        'features': ['auth', 'payment']
    }
    
    # URL без учетных данных
    public_api_url = "https://api.example.com/v1/data"
    website_url = "https://www.example.com"