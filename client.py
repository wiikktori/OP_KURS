import requests
import re


API_URL = "http://localhost:8000"

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

def register():
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
        print("Регистрация успешна.")
        print("Токен:", data["token"])
    else:
        handle_error(response)


def auth():
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
        print("Авторизация успешна.")
        print("Токен:", data["token"])
    else:
        handle_error(response)


def main_menu():
    while True:
        print("\n=== Главное меню ===")
        print("1 - Регистрация")
        print("2 - Авторизация")
        print("0 - Выход")

        choice = input("Ваш выбор: ")

        if choice == "1":
            register()
        elif choice == "2":
            auth()
        elif choice == "0":
            break
        else:
            print("Неверный ввод")


if __name__ == "__main__":
    main_menu()
