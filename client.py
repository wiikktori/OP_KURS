import requests
import re

API_URL = "http://localhost:8000"

def register():
    print("\n=== Регистрация ===")
    login = input("Логин: ")
    email = input("Email: ")
    password = input("Пароль: ")

    user = {
        "login": login,
        "email": email,
        "password": password
    }

    response = requests.post(f"{API_URL}/users/regist", json=user)

    if response.status_code == 200:
        data = response.json()
        print("Регистрация успешна.")
        print("Токен:", data["token"])
    else:
        print("Ошибка:", response.text)


def auth():
    print("\n=== Авторизация ===")
    login = input("Логин: ")
    password = input("Пароль: ")

    params = {
        "login": login,
        "password": password
    }

    response = requests.post(f"{API_URL}/users/auth", json=params)

    if response.status_code == 200:
        data = response.json()
        print("Авторизация успешна.")
        print("Токен:", data["token"])
    else:
        print("Ошибка:", response.text)


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
