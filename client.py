import requests
import re
import hashlib
import time
import json
import getpass
from datetime import datetime

API_URL = "http://localhost:8000"

current_token = None

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

def is_password_strong(password: str) -> bool: # сложность пароля - проверка
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



def get_password(): # получение пароля и его строгость
    while True:
        password = getpass.getpass("Введите пароль: ")
        if is_password_strong(password):
            password2 = getpass.getpass("Повторите пароль: ")
            if password == password2:
                return password
            else:
                print("Пароли не совпадают. Попробуйте снова.")
        else:
            print("Пожалуйста, исправьте пароль согласно требованиям.")


def signature_variant_4(token, request_data=None):
    current_time = str(int(time.time()))
    return {"Authorization": f"{token}:{current_time}"}


def print_texts_list(texts, text_type="текстов"): # вывод списка текстов
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

def print_history_list(history): # вывод списка истории
    if not history:
        print("\nИстория пуста.")
        return False
    
    print(f"\nИстория запросов (всего: {len(history)}):")
    print("=" * 80)
    
    for i, entry in enumerate(history, 1):
        print(f"{i}. Время: {entry.get('timestamp', 'Неизвестно')}")
        print(f"   Метод: {entry.get('method', 'Неизвестно')}")
        print(f"   Эндпоинт: {entry.get('endpoint', 'Неизвестно')}")
        
        if entry.get('data'):
            data_summary = str(entry['data'])
            if len(data_summary) > 50:
                data_summary = data_summary[:47] + "..."
            print(f"   Данные: {data_summary}")
        
        if entry.get('result'):
            result_summary = str(entry['result'])
            if len(result_summary) > 50:
                result_summary = result_summary[:47] + "..."
            print(f"   Результат: {result_summary}")
        
        print("-" * 80)
    
    return True


def register(): # регистрация нового пользователя
    global current_token
    
    print("\n=== Регистрация ===")
    login = input("Логин: ")
    email = input("Email: ")

    password = get_password()

    user = {
        "login": login, 
        "email": email, 
        "password": password
    }

    try:
        response = requests.post(f"{API_URL}/register", json=user)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False

    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]
        print("Регистрация успешна!")
        print(f"Ваш токен: {current_token[:20]}...")
        return True
    else:
        handle_error(response)
        return False


def auth(): # авторизация пользователя
    global current_token
    
    print("\n=== Авторизация ===")
    login = input("Логин: ")
    password = getpass.getpass("Пароль: ")

    user = {
        "login": login,
        "password": password
    }

    try:
        response = requests.post(f"{API_URL}/auth", json=user)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False

    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]
        print("Авторизация успешна!")
        print(f"Ваш токен: {current_token[:20]}...")
        return True
    else:
        handle_error(response)
        return False

def change_password(): # изменение пароля пользователя
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Изменение пароля ===")
    
    old_password = getpass.getpass("Текущий пароль: ")
    new_password = get_password()
    
    password_data = {
        "old_password": old_password,
        "new_password": new_password
    }
    
    headers = signature_variant_4(current_token, password_data)
    
    try:
        response = requests.patch(
            f"{API_URL}/change_password",
            json=password_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        current_token = data["token"]
        print("Пароль успешно изменен!")
        print(f"Новый токен: {current_token[:20]}...")
        return True
    else:
        handle_error(response)
        return False

def add_text(): # добавление текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Добавление текста ===")
    
    text = input("Введите текст: ")
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return False
    
    text_data = {
        "token": current_token,
        "text": text
    }
    
    headers = signature_variant_4(current_token, text_data)
    
    try:
        response = requests.post(
            f"{API_URL}/add_text",
            json=text_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        return True
    else:
        handle_error(response)
        return False

def view_all_texts(): # просмотр всех текстов пользователя
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Просмотр всех текстов ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/view_all_texts",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        if "texts" in data:
            print_texts_list(data["texts"], "текстов")
        else:
            print("\nУ вас нет добавленных текстов.")
        return True
    else:
        handle_error(response)
        return False


def view_encrypted_texts(): # просмотр зашифрованных текстов
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Просмотр зашифрованных текстов ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/view_encrypted_texts",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        if "texts" in data:
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
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Просмотр расшифрованных текстов ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/view_decrypted_texts",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        if "texts" in data:
            print_texts_list(data["texts"], "расшифрованных текстов")
        else:
            print("\nУ вас нет расшифрованных текстов.")
        return True
    else:
        handle_error(response)
        return False


def view_one_text(): # просмотр одного текста пользователя
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Просмотр одного текста ===")
    
    # Сначала показываем доступные типы текстов
    print("\nВыберите тип текста:")
    print("1 - Обычные тексты")
    print("2 - Зашифрованные тексты")
    print("3 - Расшифрованные тексты")
    
    type_choice = input("Ваш выбор (1-3): ").strip()
    
    if type_choice == "1":
        text_type = "user_text"
        list_url = f"{API_URL}/view_all_texts"
        type_name = "обычных текстов"
    elif type_choice == "2":
        text_type = "encrypted_text"
        list_url = f"{API_URL}/view_encrypted_texts"
        type_name = "зашифрованных текстов"
    elif type_choice == "3":
        text_type = "decrypted_text"
        list_url = f"{API_URL}/view_decrypted_texts"
        type_name = "расшифрованных текстов"
    else:
        print("Неверный выбор.")
        return False
    
    # Получаем список текстов выбранного типа
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(list_url, headers=headers)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code != 200:
        handle_error(response)
        return False
    
    data = response.json()
    texts = data.get("texts", [])
    
    if not texts:
        print(f"\nУ вас нет {type_name}.")
        return True
    
    # Показываем список для выбора
    print(f"\nВаши {type_name} (всего: {len(texts)}):")
    for i, text_item in enumerate(texts, 1):
        if isinstance(text_item, dict):
            preview = text_item.get('content', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        else:
            print(f"{i}. {str(text_item)[:50]}...")
    
    # Выбор текста
    while True:
        try:
            text_number = int(input(f"\nВыберите номер текста (1-{len(texts)}): ").strip())
            if 1 <= text_number <= len(texts):
                break
            else:
                print(f"Введите число от 1 до {len(texts)}")
        except ValueError:
            print("Пожалуйста, введите число")
    
    # Запрос конкретного текста через запрашиваемые параметры
    params = {
        "text_number": text_number,
        "type": text_type
    }
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/view_one_text",
            params=params,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        text_content = data.get("text", "")
        filename = data.get("filename", "Неизвестно")
        
        print(f"\nТекст (файл: {filename}):")
        print("=" * 70)
        print(text_content)
        print("=" * 70)
        return True
    else:
        handle_error(response)
        return False


def delete_text(): # удаление текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Удаление текста ===")
    
    # Сначала показываем доступные типы текстов
    print("\nВыберите тип текста для удаления:")
    print("1 - Обычные тексты")
    print("2 - Зашифрованные тексты")
    print("3 - Расшифрованные тексты")
    
    type_choice = input("Ваш выбор (1-3): ").strip()
    
    if type_choice == "1":
        text_type = "user_text"
        list_url = f"{API_URL}/view_all_texts"
        type_name = "обычных текстов"
    elif type_choice == "2":
        text_type = "encrypted_text"
        list_url = f"{API_URL}/view_encrypted_texts"
        type_name = "зашифрованных текстов"
    elif type_choice == "3":
        text_type = "decrypted_text"
        list_url = f"{API_URL}/view_decrypted_texts"
        type_name = "расшифрованных текстов"
    else:
        print("Неверный выбор.")
        return False
    
    # Получаем список текстов выбранного типа
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(list_url, headers=headers)
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code != 200:
        handle_error(response)
        return False
    
    data = response.json()
    texts = data.get("texts", [])
    
    if not texts:
        print(f"\nУ вас нет {type_name} для удаления.")
        return True
    
    # Показываем список для выбора
    print(f"\nВаши {type_name} (всего: {len(texts)}):")
    for i, text_item in enumerate(texts, 1):
        if isinstance(text_item, dict):
            preview = text_item.get('content', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        else:
            print(f"{i}. {str(text_item)[:50]}...")
    
    # Подтверждение удаления
    confirm = input("\nВы уверены, что хотите удалить текст? (да/нет): ").lower()
    if confirm != 'да':
        print("Удаление отменено.")
        return True
    
    # Выбор текста для удаления
    while True:
        try:
            text_number = int(input(f"\nВыберите номер текста для удаления (1-{len(texts)}): ").strip())
            if 1 <= text_number <= len(texts):
                break
            else:
                print(f"Введите число от 1 до {len(texts)}")
        except ValueError:
            print("Пожалуйста, введите число")
    
    # Удаление текста через query параметры
    params = {
        "text_number": text_number,
        "type": text_type
    }
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.delete(
            f"{API_URL}/delete_text",
            params=params,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        return True
    else:
        handle_error(response)
        return False


def change_text(): # изменение текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Изменение текста ===")
    
    # Получаем список обычных текстов (только их можно изменять)
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/view_all_texts",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code != 200:
        handle_error(response)
        return False
    
    data = response.json()
    texts = data.get("texts", [])
    
    if not texts:
        print("\nУ вас нет текстов для изменения.")
        return True
    
    # Показываем список для выбора
    print(f"\nВаши тексты (всего: {len(texts)}):")
    for i, text_item in enumerate(texts, 1):
        if isinstance(text_item, dict):
            preview = text_item.get('content', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        else:
            print(f"{i}. {str(text_item)[:50]}...")
    
    # Выбор текста для изменения
    while True:
        try:
            text_number = int(input(f"\nВыберите номер текста для изменения (1-{len(texts)}): ").strip())
            if 1 <= text_number <= len(texts):
                break
            else:
                print(f"Введите число от 1 до {len(texts)}")
        except ValueError:
            print("Пожалуйста, введите число")
    
    # Ввод нового текста
    print("\nВведите новый текст (для завершения введите пустую строку):")
    lines = []
    while True:
        line = input()
        if line == "":
            break
        lines.append(line)
    
    if not lines:
        print("Ошибка: новый текст не может быть пустым!")
        return False
    
    new_text = "\n".join(lines)
    
    # Изменение текста через запрашиваемые параметры и тело запроса
    params = {
        "text_number": text_number
    }
    
    text_data = {
        "new_text": new_text
    }
    
    headers = signature_variant_4(current_token, text_data)
    
    try:
        response = requests.patch(
            f"{API_URL}/change_the_text",
            params=params,
            json=text_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        return True
    else:
        handle_error(response)
        return False


def encrypt_text(): # шифрование текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Шифрование текста ===")
    
    # Выбор источника текста
    print("\nВыберите источник текста:")
    print("1 - Использовать сохраненный текст")
    print("2 - Ввести текст вручную")
    
    source_choice = input("Ваш выбор (1 или 2): ").strip()
    
    text = ""
    
    if source_choice == "1":
        headers = signature_variant_4(current_token, {})
        
        try:
            response = requests.get(
                f"{API_URL}/view_all_texts",
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return False
        
        if response.status_code != 200:
            handle_error(response)
            return False
        
        data = response.json()
        texts = data.get("texts", [])
        
        if not texts:
            print("\nУ вас нет сохраненных текстов для шифрования.")
            return True
        
        print(f"\nВаши тексты (всего: {len(texts)}):")
        for i, text_item in enumerate(texts, 1):
            preview = text_item.get('content', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        
        # Выбор текста
        while True:
            try:
                text_number = int(input(f"\nВыберите номер текста для шифрования, где 1-последний добавленный текст (1-{len(texts)}): ").strip())
                if 1 <= text_number <= len(texts):
                    break
                else:
                    print(f"Введите число от 1 до {len(texts)}")
            except ValueError:
                print("Пожалуйста, введите число")
        
        # Получаем полный текст
        params = {
            "text_number": text_number,
            "type": "user_text"
        }
        
        headers = signature_variant_4(current_token, {})
        
        try:
            response = requests.get(
                f"{API_URL}/view_one_text",
                params=params,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return False
        
        if response.status_code != 200:
            handle_error(response)
            return False
        
        text_data = response.json()
        text = text_data.get("text", "")
        
    elif source_choice == "2":
        print("\nВведите текст для шифрования (для завершения введите пустую строку):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        
        if not lines:
            print("Ошибка: текст не может быть пустым!")
            return False
        
        text = "\n".join(lines)
    else:
        print("Неверный выбор.")
        return False
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return False
    
    while True:
        key_str = input("\nВведите ключ для шифрования (только цифры): ").strip()
        if key_str.isdigit():
            # Преобразуем строку в список чисел
            key = [int(digit) for digit in key_str]
            break
        else:
            print("Ключ должен содержать только цифры!")
    
    # Шифрование
    cipher_data = {
        "text": text,
        "key": key
    }
    
    headers = signature_variant_4(current_token, cipher_data)
    
    try:
        response = requests.post(
            f"{API_URL}/cipher_encrypt",
            json=cipher_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
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


def decrypt_text(): # дешифрование текста
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Дешифрование текста ===")
    
    # Выбор источника текста
    print("\nВыберите источник текста:")
    print("1 - Использовать сохраненный зашифрованный текст")
    print("2 - Ввести текст вручную")
    
    source_choice = input("Ваш выбор (1 или 2): ").strip()
    
    text = ""
    
    if source_choice == "1":
        headers = signature_variant_4(current_token, {})
        
        try:
            response = requests.get(
                f"{API_URL}/view_encrypted_texts",
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return False
        
        if response.status_code != 200:
            handle_error(response)
            return False
        
        data = response.json()
        texts = data.get("texts", [])
        
        if not texts:
            print("\nУ вас нет зашифрованных текстов для дешифрования.")
            return True
        
        print(f"\nВаши зашифрованные тексты (всего: {len(texts)}):")
        for i, text_item in enumerate(texts, 1):
            preview = text_item.get('content', '')
            if isinstance(preview, dict):
                preview = str(preview)
            if len(preview) > 50:
                preview = preview[:47] + "..."
            print(f"{i}. {preview}")
        
        # Выбор текста
        while True:
            try:
                text_number = int(input(f"\nВыберите номер текста для дешифрования, где 1-последний добавленный текст (1-{len(texts)}): ").strip())
                if 1 <= text_number <= len(texts):
                    break
                else:
                    print(f"Введите число от 1 до {len(texts)}")
            except ValueError:
                print("Пожалуйста, введите число")
        
        # Получаем полный зашифрованный текст
        params = {
            "text_number": text_number,
            "type": "encrypted_text"
        }
        
        headers = signature_variant_4(current_token, {})
        
        try:
            response = requests.get(
                f"{API_URL}/view_one_text",
                params=params,
                headers=headers
            )
        except requests.exceptions.RequestException as e:
            print("Ошибка подключения:", e)
            return False
        
        if response.status_code != 200:
            handle_error(response)
            return False
        
        text_data = response.json()
        text = text_data.get("text", "")
        
    elif source_choice == "2":
        print("\nВведите текст для дешифрования (для завершения введите пустую строку):")
        lines = []
        while True:
            line = input()
            if line == "":
                break
            lines.append(line)
        
        if not lines:
            print("Ошибка: текст не может быть пустым!")
            return False
        
        text = "\n".join(lines)
    else:
        print("Неверный выбор.")
        return False
    
    if not text.strip():
        print("Ошибка: текст не может быть пустым!")
        return False
    
    while True:
        key_str = input("\nВведите ключ для дешифрования (только цифры): ").strip()
        if key_str.isdigit():
            # Преобразуем строку в список чисел
            key = [int(digit) for digit in key_str]
            break
        else:
            print("Ключ должен содержать только цифры!")
    
    # Дешифрование
    cipher_data = {
        "text": text,
        "key": key
    }
    
    headers = signature_variant_4(current_token, cipher_data)
    
    try:
        response = requests.post(
            f"{API_URL}/cipher_decrypt",
            json=cipher_data,
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
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


def view_query_history(): # просмотр истории запросов
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== История запросов ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.get(
            f"{API_URL}/query_history",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        history = data.get("history", [])
        print_history_list(history)
        return True
    else:
        handle_error(response)
        return False


def delete_query_history(): # удаление истории запросов
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию!")
        return False
    
    print("\n=== Удаление истории запросов ===")
    
    confirm = input("Вы уверены, что хотите удалить историю запросов? (да/нет): ").lower()
    if confirm != 'да':
        print("Операция отменена.")
        return True
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.delete(
            f"{API_URL}/delete_query_history",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        return False
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
        return True
    else:
        handle_error(response)
        return False


def exit_app(): # выход
    global current_token
    
    if not current_token:
        print("Выход из программы.")
        return True
    
    print("\n=== Выход ===")
    
    headers = signature_variant_4(current_token, {})
    
    try:
        response = requests.delete(
            f"{API_URL}/exit",
            headers=headers
        )
    except requests.exceptions.RequestException as e:
        print("Ошибка подключения:", e)
        print("Выход из программы.")
        return True
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n{data['message']}")
    else:
        handle_error(response)
    
    print("Выход из программы.")
    return True


def main_menu(): # главная менюшка 
    global current_token
    authenticated = False
    
    while True:
        print("\n" + "=" * 50)
        print("Добро пожаловать в приложение 'Шифр Гросфельда!'")
        print("=" * 50)
        
        if not authenticated:
            print("\n=== Главное меню: Авторизация/Регистрация ===")
            print("1 - Регистрация")
            print("2 - Авторизация")
            print("3 - Выход")
            
            if current_token:
                print(f"\nТокен: {current_token[:20]}...")
        else:
            print("\n=== Главное меню ===")
            print("1 - Шифрование текста")
            print("2 - Дешифрование текста")
            print("3 - Добавить текст")
            print("4 - Просмотреть все тексты")
            print("5 - Просмотреть зашифрованные тексты")
            print("6 - Просмотреть расшифрованные тексты")
            print("7 - Просмотреть один текст")
            print("8 - Изменить текст")
            print("9 - Удалить текст")
            print("10 - Изменить пароль")
            print("11 - История запросов")
            print("12 - Удалить историю запросов")
            print("13 - Выход")
            
            print(f"\nТокен: {current_token[:20]}...")
        
        print("\n" + "-" * 50)
        choice = input("Ваш выбор: ").strip()
        
        if not authenticated:
            if choice == "1":
                if register():
                    authenticated = True
            elif choice == "2":
                if auth():
                    authenticated = True
            elif choice == "3":
                print("Выход из программы.")
                break
            else:
                print("Неверный выбор. Пожалуйста, выберите 1, 2 или 3.")
        else:
            if choice == "1":
                encrypt_text()
            elif choice == "2":
                decrypt_text()
            elif choice == "3":
                add_text()
            elif choice == "4":
                view_all_texts()
            elif choice == "5":
                view_encrypted_texts()
            elif choice == "6":
                view_decrypted_texts()
            elif choice == "7":
                view_one_text()
            elif choice == "8":
                change_text()
            elif choice == "9":
                delete_text()
            elif choice == "10":
                if change_password():
                    # После смены пароля токен обновляется
                    print("Пароль успешно изменен.")
            elif choice == "11":
                view_query_history()
            elif choice == "12":
                delete_query_history()
            elif choice == "13":
                if exit_app():
                    authenticated = False
                    current_token = None  # Сбрасываем токен при выходе
            else:
                print("Неверный выбор. Пожалуйста, выберите от 1 до 13.")
                
if __name__ == "__main__":
    main_menu()