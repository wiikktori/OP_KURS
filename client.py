import requests
import re
import hashlib
import time
import json

API_URL = "http://localhost:8000"

current_token = None
session_token = None

def handle_error(response):
    print(f"\nОшибка (код {response.status_code}):")

    try:
        data = response.json()
        if "detail" in data:
            print(data["detail"])
        else:
            print(data)
    except ValueError:
        print(response.text)

def is_password_strong(password: str) -> bool:
    if len(password) < 10:
        print("Пароль должен содержать не менее 10 символов.")
        return False
    if not re.search(r"[A-Z]", password):
        print("Пароль должен содержать хотя бы одну заглавную букву (A-Z).")
        return False
    if not re.search(r"[a-z]", password):
        print("Пароль должен содержать хотя бы одну строчную букву (a-z).")
        return False
    if not re.search(r"[0-9]", password):
        print("Пароль должен содержать хотя бы одну цифру.")
        return False
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:,./?]", password):
        print("Пароль должен содержать хотя бы один спецсимвол.")
        return False
    return True

# Создание сессионного токена на основе технического по заданию
def create_session_token(token):
    timestamp = str(int(time.time()))
    session_hash = hashlib.sha256(f"{token}:{timestamp}".encode()).hexdigest()
    return f"session_{session_hash}"

# Вариант 1: только токен
def signature_variant_1(token):
    return {"Authorization": token}

# Вариант 2: хэш от токена и времени
def signature_variant_2(token):
    current_time = str(int(time.time()))
    signature_hash = hashlib.sha256(f"{token}{current_time}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}:{current_time}"}

# Вариант 3: хэш от токена и тела запроса
def signature_variant_3(token, request_body=None):
    if request_body is None:
        request_body = {}
    
    sorted_body = json.dumps(request_body, sort_keys=True) if request_body else ""
    signature_hash = hashlib.sha256(f"{token}{sorted_body}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}"}

# Вариант 4: хэш от токена,тела запроса и время
def signature_variant_4(token, request_body=None):
    if request_body is None:
        request_body = {}
    
    current_time = str(int(time.time()))
    sorted_body = json.dumps(request_body, sort_keys=True) if request_body else ""
    
    signature_hash = hashlib.sha256(f"{token}{sorted_body}{current_time}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}:{current_time}"}

def print_texts_list(texts, text_type="текстов"):
    """Вывод списка текстов"""
    if not texts:
        print(f"\nУ вас нет {text_type}.")
        return False
    
    print(f"\nВаши {text_type} (всего: {len(texts)}):")
    print("=" * 70)
    
    for i, text_item in enumerate(texts, 1):
        if isinstance(text_item, dict):
            if 'content' in text_item:
                preview = text_item['content']
                if isinstance(preview, dict):
                    preview = str(preview)
                if len(preview) > 100:
                    preview = preview[:97] + "..."
                print(f"{i}. {preview}")
            elif 'preview' in text_item:
                preview = text_item['preview']
                if isinstance(preview, dict):
                    preview = str(preview)
                if len(preview) > 100:
                    preview = preview[:97] + "..."
                print(f"{i}. {preview}")
        else:
            print(f"{i}. {str(text_item)[:100]}...")
        print("-" * 70)
    
    return True

def make_request(user_id, params):
    global session_token
    
    headers = signature_variant_4(session_token, params)
    response = requests.get(f"{API_URL}/users/{user_id}", params=params, headers=headers)
   
    return response 

def register():
    global current_token, session_token
    print("\n=== Регистрация ===")
    login = input("Логин: ")
    email = input("Email: ")

    while True:
        password = input("Пароль: ")
        if not is_password_strong(password):
            continue

        password2 = input("Повторите пароль: ")
        if password != password2:
            print("Пароли не совпадают. Попробуйте снова.")
            continue
        break

    user = {"login": login, "email": email, "password": password}

    try:
        response = requests.post(f"{API_URL}/users/regist", json=user)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return

    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]  
        session_token = create_session_token(current_token) 
        print("Регистрация успешна.")
        print(f"Технический токен: {current_token[:20]}...")
        print(f"Сессионный токен: {session_token[:30]}...")
    else:
        handle_error(response)


def auth():
    global current_token, session_token
    print("\n=== Авторизация ===")
    login = input("Логин: ")
    password = input("Пароль: ")

    params = {
        "login": login,
        "password": password
    }

    try:
        response = requests.post(f"{API_URL}/users/auth", json=params)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return

    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]
        session_token = create_session_token(current_token) 
        print("Авторизация успешна.")
        print(f"Технический токен: {current_token[:20]}...")
        print(f"Сессионный токен: {session_token[:30]}...")
    else:
        handle_error(response)


def protected_request():
    global session_token
    
    if not session_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\nЗащищенный запрос (вариант 4 подписи)")
    try:
        user_id = int(input("ID пользователя: "))
    except ValueError:
        print("Некорректный ID")
        return
    
    q = input()
    a = input()

    q = input("Параметр q:")
    a = input("Параметр a:")
    
    params = {}
    if q:
        params["q"] = int(q)
    if a:
        params["a"] = int(a)
    
    headers = signature_variant_1(current_token)
    
    try:
        response = make_request(user_id, params)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\nРезультат запроса:")
        print(f"ID: {data['user_id']}")
        print(f"q: {data['q']}")
        print(f"a: {data['a']}")
        print(f"Сумма: {data['sum']}")
    else:
        handle_error(response)

def add_text(): #добавление текста
    global session_token
    
    if not session_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Добавление текста ===")
    
    text = input("Введите текст: ")
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return
    
    text_data = {
        "text": text
    }
    
    headers = signature_variant_4(session_token, text_data)
    
    try:
        response = requests.post(
            f"{API_URL}/texts/add",
            json=text_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        print(f"№ текста: {data['text_id']}")
        return True
    else:
        handle_error(response)
        return False
    
def view_all_texts(): # просмотр всех текстов
    global session_token
    
    if not session_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Просмотр всех текстов ===")
    
    headers = signature_variant_4(session_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/texts",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        
        if data["texts_count"] == 0:
            print("\n У вас пока нет сохраненных текстов")
            return True
        
        print(f"\n Найдено текстов: {data['texts_count']}")
        print("=" * 70)
        
        return True
    else:
        handle_error(response)
        return False

def view_text(): # просмотр конкретного текста
    global session_token
    
    if not session_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Просмотр текста ===")
    
    try:
        text_id = int(input("Введите ID текста: "))
    except ValueError:
        print("Некорректный ID текста")
        return
    
    headers = signature_variant_4(session_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/texts/{text_id}",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\nТекст (ID: {data['text_id']}, Файл: {data['filename']}):")
        print("=" * 60)
        print(data['content'])
        print("=" * 60)
        return True
    elif response.status_code == 404:
        print("\nТекст не найден")
        return False
    else:
        handle_error(response)
        return False

def delete_text(): # удаление текста
    global session_token
    
    if not session_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Удаление текста ===")
    
    try:
        text_id = int(input("Введите ID текста для удаления: "))
    except ValueError:
        print("Некорректный ID текста")
        return
    
    # Подтверждение удаления
    confirm = input(f"Вы уверены, что хотите удалить текст с ID {text_id}? (да/нет): ").lower()
    if confirm != 'да':
        print("Удаление отменено.")
        return
    
    headers = signature_variant_4(session_token, {})
    
    try:
        response = requests.delete(
            f"{API_URL}/texts/{text_id}",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        print(f"ID текста: {data['text_id']}")
        print(f"Удаленный файл: {data['filename']}")
        return True
    elif response.status_code == 404:
        print("\nТекст не найден")
        return False
    else:
        handle_error(response)
        return False

def update_text(): # изменение текста
    global session_token
    
    if not session_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Изменение текста ===")
    
    try:
        text_id = int(input("Введите номер текста для изменения: "))
    except ValueError:
        print("Некорректный номер текста")
        return
    
    print("\nВведите новый текст:")
    text = input()
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return
    
    text_data = {
        "text": text
    }
    
    headers = signature_variant_4(session_token, text_data)
    
    try:
        response = requests.patch(
            f"{API_URL}/texts/{text_id}",
            json=text_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        print(f"№ текста: {data['text_id']}")
        print(f"Файл: {data['filename']}")
        return True
    elif response.status_code == 404:
        print("\nТекст не найден")
        return False
    else:
        handle_error(response)
        return False

def encrypt_text(): # функция шифрования текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Шифрование текста ===")
    
    print("\nВыберите источник текста:")
    print("1 - Использовать сохраненный текст")
    print("2 - Ввести текст вручную")
    
    source_choice = input("Ваш выбор (1 или 2): ").strip()
    
    text = ""
    
    if source_choice == "1":
        headers = signature_variant_4(session_token, {})
        
        try:
            response = requests.get(
                f"{API_URL}/texts",
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return
        
        if response.status_code != 200:
            handle_error(response)
            return
        
        data = response.json()
        texts = data.get("texts", [])
        
        if not texts:
            print("\nУ вас нет сохраненных текстов для шифрования.")
            return True
        
        print("\nВаши тексты (всего: {len(texts)}):")
        for i, text_item in enumerate(texts, 1):
            preview = text_item.get('preview', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        
        while True:
            try:
                text_number = int(input(f"\nВыберите номер текста для шифрования (1-{len(texts)}): ").strip())
                if 1 <= text_number <= len(texts):
                    break
                else:
                    print(f"Введите число от 1 до {len(texts)}")
            except ValueError:
                print("Пожалуйста, введите число")
        
        text_id = texts[text_number - 1]["text_id"]
        
        try:
            response = requests.get(
                f"{API_URL}/texts/{text_id}",
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return
        
        if response.status_code != 200:
            handle_error(response)
            return
        
        text_data = response.json()
        text = text_data.get("text", "")
        
    elif source_choice == "2":
        print("\nВведите текст для шифрования:")
        text = input()
    else:
        print("Неверный выбор.")
        return False
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return False
    
    while True:
        key = input("\nВведите ключ для шифрования (только цифры): ").strip()
        if key.isdigit():
            break
        else:
            print("Ключ должен содержать только цифры!")
    
    cipher_data = {
        "token": current_token,
        "text": text,
        "key": key
    }
    
    headers = signature_variant_4(session_token, cipher_data)
    
    try:
        response = requests.post(
            f"{API_URL}/cipher_encrypt",
            json=cipher_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        encrypted_text = data.get("message", "")
        
        print(f"\nЗашифрованный текст:")
        print("=" * 70)
        print(encrypted_text)
        print("=" * 70)
        print(f"\nТекст сохранен в вашей папке зашифрованных текстов.")
        return True
    else:
        handle_error(response)
        return False

def decrypt_text(): # функция дешифрования текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Дешифрование текста ===")
    
    print("\nВыберите источник текста:")
    print("1 - Использовать сохраненный зашифрованный текст")
    print("2 - Ввести текст вручную")
    
    source_choice = input("Ваш выбор (1 или 2): ").strip()
    
    text = ""
    
    if source_choice == "1":
        try:
            response = requests.get(
                f"{API_URL}/view_encrypted_texts",
                params={"token": current_token}
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return
        
        if response.status_code != 200:
            handle_error(response)
            return
        
        data = response.json()
        texts = data.get("texts", [])
        
        if not texts:
            print("\nУ вас нет зашифрованных текстов для дешифрования.")
            return True
        
        print("\nВаши зашифрованные тексты (всего: {len(texts)}):")
        for i, text_item in enumerate(texts, 1):
            preview = text_item.get('content', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        
        while True:
            try:
                text_number = int(input(f"\nВыберите номер текста для дешифрования (1-{len(texts)}): ").strip())
                if 1 <= text_number <= len(texts):
                    break
                else:
                    print(f"Введите число от 1 до {len(texts)}")
            except ValueError:
                print("Пожалуйста, введите число")
        
        text_id_data = {
            "token": current_token,
            "text_number": text_number,
            "type": "encrypted_text"
        }
        
        try:
            response = requests.post(
                f"{API_URL}/view_one_text",
                json=text_id_data
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return
        
        if response.status_code != 200:
            handle_error(response)
            return
        
        text_data = response.json()
        text = text_data.get("text", "")
        
    elif source_choice == "2":
        print("\nВведите текст для дешифрования:")
        text = input()
    else:
        print("Неверный выбор.")
        return False
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return False
    
    while True:
        key = input("\nВведите ключ для дешифрования (только цифры): ").strip()
        if key.isdigit():
            break
        else:
            print("Ключ должен содержать только цифры!")
    
    cipher_data = {
        "token": current_token,
        "text": text,
        "key": key
    }
    
    headers = signature_variant_4(session_token, cipher_data)
    
    try:
        response = requests.post(
            f"{API_URL}/cipher_decrypt",
            json=cipher_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        decrypted_text = data.get("message", "")
        
        print(f"\nРасшифрованный текст:")
        print("=" * 70)
        print(decrypted_text)
        print("=" * 70)
        print(f"\nТекст сохранен в вашей папке расшифрованных текстов.")
        return True
    else:
        handle_error(response)
        return False

def view_encrypted_texts(): # просмотр зашифрованных текстов
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Просмотр зашифрованных текстов ===")
    
    try:
        response = requests.get(
            f"{API_URL}/view_encrypted_texts",
            params={"token": current_token}
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        if "texts" in data and data["texts"]:
            print_texts_list(data["texts"], "зашифрованных текстов")
        else:
            print("\nУ вас нет зашифрованных текстов.")
        return True
    else:
        handle_error(response)
        return False
    
def view_decrypted_texts(): # просмотр расшифрованных текстов
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Просмотр расшифрованных текстов ===")
    
    try:
        response = requests.get(
            f"{API_URL}/view_decrypted_texts",
            params={"token": current_token}
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        if "texts" in data and data["texts"]:
            print_texts_list(data["texts"], "расшифрованных текстов")
        else:
            print("\nУ вас нет расшифрованных текстов.")
        return True
    else:
        handle_error(response)
        return False

def view_one_text_special(): # просмотр одного текста пользователя
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Просмотр одного текста ===")
    
    print("\nВыберите тип текста:")
    print("1 - Обычные тексты")
    print("2 - Зашифрованные тексты")
    print("3 - Расшифрованные тексты")
    
    type_choice = input("Ваш выбор (1-3): ").strip()
    
    if type_choice == "1":
        text_type = "user_text"
    elif type_choice == "2":
        text_type = "encrypted_text"
    elif type_choice == "3":
        text_type = "decrypted_text"
    else:
        print("Неверный выбор.")
        return False
    
    try:
        text_number = int(input(f"Введите номер текста: "))
    except ValueError:
        print("Некорректный номер текста")
        return
    
    text_data = {
        "token": current_token,
        "text_number": text_number,
        "type": text_type
    }
    
    try:
        response = requests.post(
            f"{API_URL}/view_one_text",
            json=text_data
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return
    
    if response.status_code == 200:
        data = response.json()
        text_content = data.get("text", "")
        
        print(f"\nТекст:")
        print("=" * 70)
        print(text_content)
        print("=" * 70)
        return True
    else:
        handle_error(response)
        return False

def main_menu():
    while True:
        print("\n" + "=" * 50)
        print("ПРИЛОЖЕНИЕ ДЛЯ ШИФРОВАНИЯ ГРОНСФЕЛЬДА")
        print("=" * 50)
        
        if current_token:
            print(f"Технический токен: {current_token[:20]}...")
        if session_token:
            print(f"Сессионный токен: {session_token[:30]}...")
        
        print("\n=== Управление аккаунтом ===")
        print("1 - Регистрация")
        print("2 - Авторизация")
        print("3 - Защищенный запрос (тест)")
        
        print("\n=== Работа с текстами ===")
        print("4 - Добавить текст")
        print("5 - Просмотреть все тексты")
        print("6 - Просмотреть один текст")
        print("7 - Изменить текст")
        print("8 - Удалить текст")
        
        print("\n=== Шифрование/Дешифрование ===")
        print("9 - Шифровать текст")
        print("10 - Дешифровать текст")
        print("11 - Просмотреть зашифрованные тексты")
        print("12 - Просмотреть расшифрованные тексты")
        print("13 - Просмотреть один текст (по типу)")
        
        print("\n0 - Выход")
        print("-" * 50)
        
        choice = input("Ваш выбор: ")

        if choice == "1":
            register()
        elif choice == "2":
            auth()
        elif choice == "3":
            protected_request()
        elif choice == "4":
            add_text()
        elif choice == "5":
            view_all_texts()
        elif choice == "6":
            view_text()
        elif choice == "7":
            update_text()
        elif choice == "8":
            delete_text()
        elif choice == "9":
            encrypt_text()
        elif choice == "10":
            decrypt_text()
        elif choice == "11":
            view_encrypted_texts()
        elif choice == "12":
            view_decrypted_texts()
        elif choice == "13":
            view_one_text_special()
        elif choice == "0":
            print("\nВыход из программы...")
            break
        else:
            print("\nНеверный выбор. Попробуйте снова.")


if __name__ == "__main__":
    main_menu()