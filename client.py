import requests
import re
import hashlib
import time

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

def signature_variant_1(token):
    return {"Authorization": token}


def signature_variant_2(token):
    current_time = str(int(time.time()))
    signature_hash = hashlib.sha256(f"{token}{current_time}".encode()).hexdigest()
    return {"Authorization": f"{signature_hash}:{current_time}"}


def make_request_with_retry(user_id, params):
    global current_token
    
    # Первая попытка
    headers = signature_variant_2(current_token)
    response = requests.get(f"{API_URL}/users/{user_id}", params=params, headers=headers)
    
    # Если подпись устарела, пробуем еще раз с новым временем
    if response.status_code == 401:
        try:
            error_detail = response.json().get("detail", "")
            if "Время подписи устарело" in error_detail.lower() or "time" in error_detail.lower():
                print("Подпись устарела, создаем новую...")
                # Создаем новую подпись с актуальным временем
                headers = signature_variant_2(current_token)
                response = requests.get(f"{API_URL}/users/{user_id}", params=params, headers=headers)
        except:
            pass
    
    return response 

def register():
    global current_token
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
        print("Регистрация успешна.")
        print("Токен:", current_token)
    else:
        handle_error(response)


def auth():
    global current_token
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
        print("Авторизация успешна.")
        print("Токен:", current_token)
    else:
        handle_error(response)


def protected_request():
    global current_token
    
    if not current_token:
        print("Сначала выполните авторизацию или регистрацию!")
        return
    
    print("\n=== Защищенный запрос ===")
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
        response = make_request_with_retry(user_id, params)
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


def main_menu():
    while True:
        print("\n=== Главное меню ===")
        print("1 - Регистрация")
        print("2 - Авторизация")
        print("3 - Защищенный запрос")
        print("0 - Выход")

        if current_token:
            print(f"Текущий токен: {current_token[:20]}...")

        choice = input("Ваш выбор: ")

        if choice == "1":
            register()
        elif choice == "2":
            auth()
        elif choice == "3":
            protected_request()
        elif choice == "0":
            break
        else:
            print("Неверный ввод")


if __name__ == "__main__":
    main_menu()
