import unittest
import requests
import time

def generate_signature_v4(token, request_data=None):
    current_time = str(int(time.time()))
    return {"Authorization": f"{token}:{current_time}"}


TEST_LOGIN = "TestUser1233"
TEST_PASSWORD = "Password1233..."
TEST_EMAIL = "testuser123@example.com"
NEW_PASSWORD = "NewPassword123.."


class Test1(unittest.TestCase): # тест регистрации
    def test_register(self):
        self.login = TEST_LOGIN
        self.password = TEST_PASSWORD
        self.email = TEST_EMAIL
        
        user_data = {
            "login": self.login,
            "email": self.email,
            "password": self.password
        }
        
        try:
            response = requests.post("http://127.0.0.1:8000/register", json=user_data)
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        if response.status_code == 200:
            response_json = response.json()
            self.token = response_json.get("token")
            print("\nРегистрация: успешно")
            print(f"Токен: {self.token[:20]}...")
        elif response.status_code == 400 and "Логин уже занят" in response.text:
            print("\nРегистрация: пользователь уже существует")
        else:
            print(f"\nРегистрация: ошибка {response.status_code}")
            print(f"Ответ: {response.text}")


class Test2(unittest.TestCase): # тест авторизации
    def test_auth(self):
        self.login = TEST_LOGIN
        self.password = TEST_PASSWORD
        
        auth_data = {
            "login": self.login,
            "password": self.password
        }
        
        try:
            response = requests.post("http://127.0.0.1:8000/auth", json=auth_data)
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        if response.status_code == 200:
            response_json = response.json()
            self.token = response_json.get("token")
            print("\nАвторизация: успешно")
            print(f"Токен: {self.token[:20]}...")
        else:
            print(f"\nАвторизация: ошибка {response.status_code}")
            print(f"Ответ: {response.text}")


class Test3(unittest.TestCase): # тест шифрования текста
    def test_encrypt_text(self):
        # сначала авторизуемся
        auth_data = {
            "login": TEST_LOGIN,
            "password": TEST_PASSWORD
        }
        
        response = requests.post("http://127.0.0.1:8000/auth", json=auth_data)
        if response.status_code != 200:
            print("\nНе удалось авторизоваться для теста шифрования")
            return
            
        token = response.json().get("token")
        
        cipher_data = {
            "text": "Привет мир! Hello world!",
            "key": [1, 2, 3, 4]
        }
        
        headers = generate_signature_v4(token, cipher_data)
        
        try:
            response = requests.post(
                "http://127.0.0.1:8000/cipher_encrypt",
                json=cipher_data,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        if response.status_code == 200:
            response_json = response.json()
            print("\nШифрование текста: успешно")
            encrypted_text = response_json.get("message", "")
            print(f"Зашифрованный текст: {encrypted_text[:50]}...")
        else:
            print(f"\nШифрование текста: ошибка {response.status_code}")
            print(f"Ответ: {response.text}")


class Test4(unittest.TestCase): # тест дешифрования текста
    def test_decrypt_text(self):
        # Сначала авторизуемся
        auth_data = {
            "login": TEST_LOGIN,
            "password": TEST_PASSWORD
        }
        
        response = requests.post("http://127.0.0.1:8000/auth", json=auth_data)
        if response.status_code != 200:
            print("\nНе удалось авторизоваться для теста дешифрования")
            return
            
        token = response.json().get("token")
        
        cipher_data = {
            "text": "Ртлёёф рйт! Igopp zssng!",  # Пример
            "key": [1, 2, 3, 4]
        }
        
        headers = generate_signature_v4(token, cipher_data)
        
        try:
            response = requests.post(
                "http://127.0.0.1:8000/cipher_decrypt",
                json=cipher_data,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        if response.status_code == 200:
            response_json = response.json()
            print("\nДешифрование текста: успешно")
            decrypted_text = response_json.get("message", "")
            print(f"Расшифрованный текст: {decrypted_text}")
        else:
            print(f"\nДешифрование текста: ошибка {response.status_code}")
            print(f"Ответ: {response.text}")


class Test5(unittest.TestCase): # тест смены пароля
    def test_change_password(self):
        # сначала авторизуемся
        auth_data = {
            "login": TEST_LOGIN,
            "password": TEST_PASSWORD
        }
        
        response = requests.post("http://127.0.0.1:8000/auth", json=auth_data)
        if response.status_code != 200:
            print("\nНе удалось авторизоваться для теста смены пароля")
            return
            
        token = response.json().get("token")
        
        # Меняем пароль
        password_data = {
            "old_password": TEST_PASSWORD,
            "new_password": NEW_PASSWORD
        }
        
        headers = generate_signature_v4(token, password_data)
        
        try:
            response = requests.patch(
                "http://127.0.0.1:8000/change_password",
                json=password_data,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            self.fail(f"Ошибка при отправке запроса: {e}")
        
        if response.status_code == 200:
            response_json = response.json()
            print("\nСмена пароля: успешно")
            print(f"Сообщение: {response_json.get('message', '')}")
            print(f"Новый токен: {response_json.get('token', '')[:20]}...")
        else:
            print(f"\nСмена пароля: ошибка {response.status_code}")
            print(f"Ответ: {response.text}")

if __name__ == "__main__":
    unittest.main()