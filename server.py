from fastapi import FastAPI, HTTPException, Request
from typing import List, Dict
import json
import time
import random
import os
import hashlib
import re
from datetime import datetime
from collections import defaultdict
from models import (User, AuthUser, AuthResponse, ChangePasswordRequest, ChangePasswordResponse, TextRequest, CipherRequest, HistoryEntry, HistoryResponse)

app = FastAPI()

# Директории для хранения данных
USERS_DIR = "users"
HISTORY_DIR = "user_history"
TEXTS_DIR = "user_text"  
ENCRYPTED_TEXTS_DIR = "encrypted_text"
DECRYPTED_TEXTS_DIR = "decrypted_text"

# Хранилище истории (для быстрого доступа)
user_history: Dict[int, List[Dict]] = defaultdict(list)

# Вариант 4
def signature_variant_4(request: Request):
    try:
        auth_header = request.headers.get("Authorization")
        if not auth_header:
            auth_header = request.headers.get("authorization")
        
        token_param = request.query_params.get("token")
        
        # Извлекаем токен
        token = None
        
        if auth_header:
            if auth_header.startswith("Bearer "):
                auth_header = auth_header[7:]
            
            if ":" in auth_header:
                token = auth_header.split(":")[0].strip()
            else:
                token = auth_header.strip()
        elif token_param:
            token = token_param
        
        if not token:
            raise HTTPException(status_code=401, detail="Отсутствует токен")
        
        os.makedirs("users", exist_ok=True)
        
        for file in os.listdir("users"):
            if file.endswith(".json"):
                try:
                    with open(f"users/{file}", "r", encoding="utf-8") as f:
                        data = json.load(f)
                        file_token = data.get("token")
                        
                        if file_token == token:
                            return data
                except Exception:
                    continue
        
        raise HTTPException(status_code=401, detail="Неверный токен")
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка сервера: {str(e)}")

def gronsfeld_encrypt(text: str, key: List[int]) -> str: # шифрование
    if not all(isinstance(k, int) and k >= 0 for k in key):
        raise HTTPException(status_code=400, detail="Ключ должен содержать только неотрицательные целые числа")
    
    alphabets = [
        'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ',  
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',  
        'abcdefghijklmnopqrstuvwxyz',  
    ]
    
    key_len = len(key)
    result = []  # для хранения зашифрованных символов
    
    for i, char in enumerate(text):
        for alphabet in alphabets:
            if char in alphabet:
                shift = key[i % key_len]  # определение сдвига
                index_char = alphabet.index(char)
                new_char = alphabet[(index_char + shift) % len(alphabet)]
                result.append(new_char)
                break
        else:
            result.append(char)  # если символ не в алфавитах, добавляем как есть

    return ''.join(result)  # преобразование в строку

def gronsfeld_decrypt(text: str, key: List[int]) -> str: # дешифрование
    if not all(isinstance(k, int) and k >= 0 for k in key):
        raise HTTPException(status_code=400, detail="Ключ должен содержать только неотрицательные целые числа")
    
    alphabets = [
        'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ', 
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz', 
    ]
    
    key_len = len(key)
    result = []  # для хранения расшифрованных символов
    
    for i, char in enumerate(text):
        for alphabet in alphabets:
            if char in alphabet:
                shift = key[i % key_len]  # определение сдвига
                index_char = alphabet.index(char)
                new_char = alphabet[(index_char - shift) % len(alphabet)]
                result.append(new_char)
                break
        else:
            result.append(char)  # если символ не в алфавитах, добавляем как есть

    return ''.join(result)  # преобразование в строку


def validate_password(password: str): # сложность пароля
    if len(password) < 10:
        raise HTTPException(status_code=400, detail="Пароль должен содержать не менее 10 символов")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну заглавную букву")
    if not re.search(r"[a-z]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну строчную букву")
    if not re.search(r"[0-9]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы одну цифру")
    if not re.search(r"[!@#$%^&*()\-_=+\[\]{};:,./?]", password):
        raise HTTPException(status_code=400, detail="Пароль должен содержать хотя бы один спецсимвол")
    return True


def token_search(token: str): # поиск пользователя по токену
    os.makedirs(USERS_DIR, exist_ok=True)
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("token") == token:
                        return data.get("id"), data.get("login")
            except json.JSONDecodeError:
                continue
    return None, None


def login_search(login: str, folder_path: str): # поиск пользователя по логину
    if not os.path.exists(folder_path):
        return None
    
    for file in os.listdir(folder_path):
        if file.endswith(".json"):
            try:
                with open(f"{folder_path}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("login") == login:
                        return data
            except json.JSONDecodeError:
                continue
    return None


def add_to_history(user_id: int, endpoint: str, method: str, data: dict = None, result: dict = None): # добавление записи в историю
    history_entry = {
        "timestamp": datetime.now().isoformat(),
        "endpoint": endpoint,
        "method": method,
        "data": data,
        "result": result
    }

    user_history[user_id].append(history_entry)

    if len(user_history[user_id]) > 100:
        user_history[user_id] = user_history[user_id][-100:]
    
    os.makedirs(HISTORY_DIR, exist_ok=True)
    history_file = f"{HISTORY_DIR}/history_{user_id}.json"
    
    file_history = []
    if os.path.exists(history_file):
        try:
            with open(history_file, "r", encoding="utf-8") as f:
                file_history = json.load(f)
        except:
            file_history = []
    
    file_history.append(history_entry)

    if len(file_history) > 100:
        file_history = file_history[-100:]
    
    with open(history_file, "w", encoding="utf-8") as f:
        json.dump(file_history, f, ensure_ascii=False, indent=2)
    
    return history_entry

def get_user_history(user_id: int): # получение истории пользователя
    if user_id in user_history and user_history[user_id]:
        return user_history[user_id]
    
    history_file = f"{HISTORY_DIR}/history_{user_id}.json"
    
    if not os.path.exists(history_file):
        return []
    
    try:
        with open(history_file, "r", encoding="utf-8") as f:
            file_history = json.load(f)
            if isinstance(file_history, list):
                user_history[user_id] = file_history
                return file_history
            else:
                return []
    except Exception:
        return []


def clear_user_history(user_id: int): # очитка истории пользователя
    if user_id in user_history:
        user_history[user_id] = []
    
    history_file = f"{HISTORY_DIR}/history_{user_id}.json"
    
    if os.path.exists(history_file):
        os.remove(history_file)
        return True
    return False


def get_user_texts(user_id: int, text_type: str): # получение списка текстов пользователя по определенному типу
    texts = []
    
    dir_path = ""
    if text_type == "user_text":
        dir_path = TEXTS_DIR
    elif text_type == "encrypted_text":
        dir_path = ENCRYPTED_TEXTS_DIR
    elif text_type == "decrypted_text":
        dir_path = DECRYPTED_TEXTS_DIR
    else:
        return texts
    
    if not os.path.exists(dir_path):
        return texts
    
    user_folder = os.path.join(dir_path, str(user_id))
    if not os.path.exists(user_folder):
        return texts
    
    try:
        for filename in os.listdir(user_folder):
            if filename.endswith(".txt"):
                try:
                    file_path = os.path.join(user_folder, filename)
                    with open(file_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        texts.append({
                            "filename": filename,
                            "content": content,
                            "path": file_path,
                            "type": text_type
                        })
                except:
                    continue
    except Exception:
        pass
    
    # Сортируем по имени файла
    texts.sort(key=lambda x: x.get("filename", ""), reverse=True)
    return texts

@app.post("/register") #регистрация пользователя
def create_user(user: User):
    os.makedirs(USERS_DIR, exist_ok=True)

    # Проверка уникальности логина
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data["login"] == user.login:
                        raise HTTPException(
                            status_code=400,
                            detail="Логин уже занят"
                        )
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=500,
                    detail="Ошибка чтения базы пользователей"
                )

    # Проверка пароля
    try:
        validate_password(user.password)
    except HTTPException as e:
        raise e

    # Создание пользователя
    user.id = int(time.time())
    user.token = hashlib.sha256(f"{user.login}{time.time()}{random.getrandbits(128)}".encode()).hexdigest()    
    user.password = hashlib.sha256(user.password.encode()).hexdigest()

    with open(f"{USERS_DIR}/user_{user.id}.json", "w", encoding="utf-8") as f:
        json.dump(user.dict(), f, ensure_ascii=False)

    add_to_history(user.id, "/register", "POST", 
                   data={"login": user.login, "email": user.email},
                   result={"status": "success", "token_created": True})

    return AuthResponse(login=user.login, token=user.token)


@app.post("/auth") # авторизация пользователя
def auth_user(params: AuthUser):
    os.makedirs(USERS_DIR, exist_ok=True)
    
    user_found = None
    
    # Ищем пользователя
    for file in os.listdir(USERS_DIR):
        if file.endswith(".json"):
            try:
                with open(f"{USERS_DIR}/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data["login"] == params.login:
                        user_found = data
                        break
            except json.JSONDecodeError:
                continue
    
    if not user_found:
        raise HTTPException(status_code=401, detail="Пользователь не найден. Сначала зарегистрируйтесь.")
    
    # Проверка пароля
    hashed_password = hashlib.sha256(params.password.encode()).hexdigest()
    if user_found["password"] != hashed_password:
        raise HTTPException(status_code=401, detail="Неверный пароль")
    
    # ВАЖНО: возвращаем существующий токен, а не создаем новый!
    if "token" not in user_found or not user_found["token"]:
        # Если вдруг токена нет (старые записи), создаем
        user_found["token"] = hashlib.sha256(
            f"{user_found['login']}{time.time()}{random.getrandbits(256)}".encode()
        ).hexdigest()
        # Сохраняем обновленный токен
        with open(f"{USERS_DIR}/user_{user_found['id']}.json", "w", encoding="utf-8") as f:
            json.dump(user_found, f, ensure_ascii=False)
    
    add_to_history(user_found["id"], "/auth", "POST",
                   data={"login": params.login},
                   result={"status": "success", "auth": True})
    
    return AuthResponse(login=user_found["login"], token=user_found["token"])


@app.patch("/change_password") # изменение пароля
def change_password(data: ChangePasswordRequest, request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Неверный токен")
    
    user_id = user_data.get("id")
    
    if not user_id:
        raise HTTPException(status_code=401, detail="ID пользователя не найден в токене")
    
    # Поиск файла пользователя
    user_file = f"{USERS_DIR}/user_{user_id}.json"
    if not os.path.exists(user_file):
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    try:
        # Открываем файл для получения текущих данных
        with open(user_file, "r", encoding="utf-8") as f:
            user_data_from_file = json.load(f)  # переименовываем, чтобы не было путаницы
    except Exception:
        raise HTTPException(status_code=500, detail="Ошибка чтения данных пользователя")
    
    # Проверка старого пароля
    old_hashed_password = hashlib.sha256(data.old_password.encode()).hexdigest()
    if user_data_from_file.get("password") != old_hashed_password:
        raise HTTPException(status_code=400, detail="Неверный текущий пароль")
    
    # Проверка нового пароля
    if data.old_password == data.new_password:
        raise HTTPException(status_code=400, detail="Новый пароль должен отличаться от старого")
    
    try:
        validate_password(data.new_password)
    except HTTPException as e:
        raise e

    new_token = hashlib.sha256(f"{user_data_from_file['login']}{time.time()}{random.getrandbits(128)}".encode()).hexdigest()[:16]
    
    # Обновление данных
    user_data_from_file["password"] = hashlib.sha256(data.new_password.encode()).hexdigest()
    user_data_from_file["token"] = new_token
    
    # Сохранение
    try:
        with open(user_file, "w", encoding="utf-8") as f:
            json.dump(user_data_from_file, f, ensure_ascii=False, indent=2)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения данных: {str(e)}")
    
    add_to_history(user_id, "/change_password", "PATCH",
                   data={"password_changed": True},
                   result={"status": "success", "new_token_created": True})
    
    return ChangePasswordResponse(
        message="Пароль успешно изменен",
        token=new_token
    )


@app.post("/add_text")  # добавление текста
async def add_text(text: TextRequest, request: Request):
    user_data = signature_variant_4(request)

    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if not text.text or not text.text.strip():
        raise HTTPException(status_code=400, detail="Текст не может быть пустой строкой")
    
    # Создание директории для текстов пользователя
    user_folder = os.path.join(TEXTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    
    # Создание файла с текстом
    text_id = int(time.time())
    filename = f"text_{text_id}.txt"
    filepath = os.path.join(user_folder, filename)
    
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(text.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения текста: {str(e)}")
    
    add_to_history(user_id, "/add_text", "POST",
                   data={"text_length": len(text.text)},
                   result={"status": "success", "text_id": text_id})
    
    return {"message": "Текст успешно добавлен!"}


@app.get("/view_all_texts") # просмотр всех текстов пользователя
def view_all_texts(request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    user_folder = os.path.join(TEXTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    
    if not os.path.exists(user_folder) or not os.listdir(user_folder):
        add_to_history(user_id, "/view_all_texts", "GET", 
                      data={}, 
                      result={"status": "no_texts"})
        return {"message": "У вас нет добавленных текстов."}
    
    all_texts = []
    for filename in os.listdir(user_folder):
        if filename.endswith(".txt"):
            filepath = os.path.join(user_folder, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    all_texts.append({
                        "filename": filename,
                        "content": content[:100] + "..." if len(content) > 100 else content,
                        "full_length": len(content)
                    })
            except Exception:
                continue
    
    add_to_history(user_id, "/view_all_texts", "GET",
                   data={},
                   result={"texts_count": len(all_texts)})
    
    return {"texts": all_texts}


@app.get("/view_encrypted_texts") # просмотр зашифрованных текстов
def view_encrypted_text(request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    user_folder = os.path.join(ENCRYPTED_TEXTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    
    if not os.path.exists(user_folder) or not os.listdir(user_folder):
        add_to_history(user_id, "/view_encrypted_texts", "GET",
                      data={},
                      result={"status": "no_texts"})
        return {"message": "У вас нет зашифрованных текстов."}
    
    encrypted_texts = []
    for filename in os.listdir(user_folder):
        if filename.endswith(".txt"):
            filepath = os.path.join(user_folder, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    encrypted_texts.append({
                        "filename": filename,
                        "content": content[:100] + "..." if len(content) > 100 else content,
                        "full_length": len(content)
                    })
            except Exception:
                continue
    
    add_to_history(user_id, "/view_encrypted_texts", "GET",
                   data={},
                   result={"texts_count": len(encrypted_texts)})
    
    return {"texts": encrypted_texts}


@app.get("/view_decrypted_texts") # просмотр расшифрованных текстов 
def view_decrypted_text(request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    user_folder = os.path.join(DECRYPTED_TEXTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    
    if not os.path.exists(user_folder) or not os.listdir(user_folder):
        add_to_history(user_id, "/view_decrypted_texts", "GET",
                      data={},
                      result={"status": "no_texts"})
        return {"message": "У вас нет расшифрованных текстов."}
    
    decrypted_texts = []
    for filename in os.listdir(user_folder):
        if filename.endswith(".txt"):
            filepath = os.path.join(user_folder, filename)
            try:
                with open(filepath, "r", encoding="utf-8") as f:
                    content = f.read()
                    decrypted_texts.append({
                        "filename": filename,
                        "content": content[:100] + "..." if len(content) > 100 else content,
                        "full_length": len(content)
                    })
            except Exception:
                continue
    
    add_to_history(user_id, "/view_decrypted_texts", "GET",
                   data={},
                   result={"texts_count": len(decrypted_texts)})
    
    return {"texts": decrypted_texts}


@app.get("/view_one_text") # просмотр одного текста 
def view_one_text(request: Request, text_number: int, type: str):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if type == "user_text":
        base_dir = TEXTS_DIR
    elif type == "encrypted_text":
        base_dir = ENCRYPTED_TEXTS_DIR
    elif type == "decrypted_text":
        base_dir = DECRYPTED_TEXTS_DIR
    else:
        raise HTTPException(status_code=400, detail="Неверный тип текста")
    
    user_folder = os.path.join(base_dir, str(user_id))
    
    if not os.path.exists(user_folder):
        add_to_history(user_id, "/view_one_text", "GET",
                      data={"type": type, "text_number": text_number},
                      result={"status": "no_folder"})
        raise HTTPException(status_code=404, detail="Нет текстов для пользователя")
    
    # Получаем список файлов
    text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
    text_files.sort(reverse=True)  # Сортируем новые сначала
    
    if not text_files:
        add_to_history(user_id, "/view_one_text", "GET",
                      data={"type": type, "text_number": text_number},
                      result={"status": "no_files"})
        return {"message": f"У вас нет текстов типа '{type}'."}
    
    # Проверяем номер текста
    if text_number < 1 or text_number > len(text_files):
        add_to_history(user_id, "/view_one_text", "GET",
                      data={"type": type, "text_number": text_number},
                      result={"status": "invalid_number", "max_number": len(text_files)})
        raise HTTPException(status_code=400, detail=f"Выберите номер от 1 до {len(text_files)}")
    
    # Читаем выбранный файл
    selected_file = text_files[text_number - 1]
    file_path = os.path.join(user_folder, selected_file)
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения файла: {str(e)}")
    
    add_to_history(user_id, "/view_one_text", "GET",
                   data={"type": type, "text_number": text_number},
                   result={"status": "success", "filename": selected_file, "length": len(content)})
    
    return {"text": content, "filename": selected_file}


@app.delete("/delete_text") # удаление текста
def delete_text(request: Request, text_number: int, type: str):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if type == "user_text":
        base_dir = TEXTS_DIR
    elif type == "encrypted_text":
        base_dir = ENCRYPTED_TEXTS_DIR
    elif type == "decrypted_text":
        base_dir = DECRYPTED_TEXTS_DIR
    else:
        raise HTTPException(status_code=400, detail="Неверный тип текста")
    
    user_folder = os.path.join(base_dir, str(user_id))
    
    if not os.path.exists(user_folder):
        add_to_history(user_id, "/delete_text", "DELETE",
                      data={"type": type, "text_number": text_number},
                      result={"status": "no_folder"})
        raise HTTPException(status_code=404, detail="Нет текстов для пользователя")
    
    # Получаем список файлов
    text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
    text_files.sort(reverse=True)  # Сортируем новые сначала
    
    if not text_files:
        add_to_history(user_id, "/delete_text", "DELETE",
                      data={"type": type, "text_number": text_number},
                      result={"status": "no_files"})
        return {"message": f"У вас нет текстов типа '{type}' для удаления."}
    
    # Проверяем номер текста
    if text_number < 1 or text_number > len(text_files):
        add_to_history(user_id, "/delete_text", "DELETE",
                      data={"type": type, "text_number": text_number},
                      result={"status": "invalid_number", "max_number": len(text_files)})
        raise HTTPException(status_code=404, detail="Текст с указанным номером не найден")
    
    # Удаляем выбранный файл
    file_to_delete = os.path.join(user_folder, text_files[text_number - 1])
    
    try:
        os.remove(file_to_delete)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка удаления файла: {str(e)}")
    
    add_to_history(user_id, "/delete_text", "DELETE",
                   data={"type": type, "text_number": text_number},
                   result={"status": "success", "deleted_file": text_files[text_number - 1]})
    
    return {"message": "Текст успешно удалён"}


@app.patch("/change_the_text") # изменение текста
def change_the_text(request: Request, text_number: int, new_text: str):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if not new_text.strip():
        raise HTTPException(status_code=400, detail="Новый текст не может быть пустым")
    
    user_folder = os.path.join(TEXTS_DIR, str(user_id))
    
    if not os.path.exists(user_folder) or not os.listdir(user_folder):
        add_to_history(user_id, "/change_the_text", "PATCH",
                      data={"text_number": text_number},
                      result={"status": "no_texts"})
        raise HTTPException(status_code=404, detail="Нет доступных текстов для изменения")
    
    # Получаем список файлов
    text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
    text_files.sort(reverse=True)  # Сортируем по убыванию (новые сначала)
    
    if text_number < 1 or text_number > len(text_files):
        add_to_history(user_id, "/change_the_text", "PATCH",
                      data={"text_number": text_number},
                      result={"status": "invalid_number", "max_number": len(text_files)})
        raise HTTPException(status_code=404, detail="Текст с указанным номером не найден")
    
    # Обновляем файл
    file_to_update = os.path.join(user_folder, text_files[text_number - 1])
    
    try:
        with open(file_to_update, "w", encoding="utf-8") as f:
            f.write(new_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка обновления файла: {str(e)}")
    
    add_to_history(user_id, "/change_the_text", "PATCH",
                   data={"text_number": text_number, "new_length": len(new_text)},
                   result={"status": "success", "updated_file": text_files[text_number - 1]})
    
    return {"message": "Текст успешно обновлён"}


@app.post("/cipher_encrypt") # шифрование текста 
def encrypt(data: CipherRequest, request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if not data.text.strip():
        # Если текст не передан, проверяем наличие текстов у пользователя
        user_folder = os.path.join(TEXTS_DIR, str(user_id))
        if not os.path.exists(user_folder) or not os.listdir(user_folder):
            add_to_history(user_id, "/cipher_encrypt", "POST",
                          data={"key": data.key},
                          result={"status": "no_texts"})
            raise HTTPException(status_code=404, detail="Нет доступных текстов для пользователя")
        
        # Берем последний добавленный текст
        text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
        text_files.sort(reverse=True)
        last_text_file = text_files[0]
        file_path = os.path.join(user_folder, last_text_file)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data.text = f.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка чтения текста: {str(e)}")
    
    # Шифруем текст
    try:
        encrypted_text = gronsfeld_encrypt(data.text, data.key)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка шифрования: {str(e)}")
    
    # Сохраняем зашифрованный текст
    user_folder = os.path.join(ENCRYPTED_TEXTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    
    text_id = int(time.time())
    file_path = os.path.join(user_folder, f"text_{text_id}.txt")
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(encrypted_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения зашифрованного текста: {str(e)}")
    
    add_to_history(user_id, "/cipher_encrypt", "POST",
                   data={"key": data.key, "original_length": len(data.text)},
                  result={"status": "success", "encrypted_length": len(encrypted_text), "text_id": text_id})
    
    return {"message": encrypted_text}


@app.post("/cipher_decrypt") # дешифрование текста 
def decrypt(data: CipherRequest, request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if not data.text.strip():
        # Если текст не передан, проверяем наличие зашифрованных текстов
        user_folder = os.path.join(ENCRYPTED_TEXTS_DIR, str(user_id))
        if not os.path.exists(user_folder) or not os.listdir(user_folder):
            add_to_history(user_id, "/cipher_decrypt", "POST",
                          data={"key": data.key},
                          result={"status": "no_encrypted_texts"})
            raise HTTPException(status_code=404, detail="Нет доступных зашифрованных текстов")
        
        # Берем последний зашифрованный текст
        text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
        text_files.sort(reverse=True)
        last_text_file = text_files[0]
        file_path = os.path.join(user_folder, last_text_file)
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data.text = f.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка чтения зашифрованного текста: {str(e)}")
    
    # Дешифруем текст
    try:
        decrypted_text = gronsfeld_decrypt(data.text, data.key)
    except HTTPException as e:
        raise e
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка дешифрования: {str(e)}")
    
    # Сохраняем расшифрованный текст
    user_folder = os.path.join(DECRYPTED_TEXTS_DIR, str(user_id))
    os.makedirs(user_folder, exist_ok=True)
    
    text_id = int(time.time())
    file_path = os.path.join(user_folder, f"text_{text_id}.txt")
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(decrypted_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения расшифрованного текста: {str(e)}")
    
    add_to_history(user_id, "/cipher_decrypt", "POST",
                   data={"key": data.key, "encrypted_length": len(data.text)},
                   result={"status": "success", "decrypted_length": len(decrypted_text), "text_id": text_id})
    
    return {"message": decrypted_text}


@app.get("/query_history") # просмотр истории запросов пользователя
def view_query_history(request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    history = get_user_history(user_id)
    
    if not history:
        add_to_history(user_id, "/query_history", "GET",
                      data={},
                      result={"status": "no_history"})
        return {"message": "У вас нет истории запросов."}
    
    add_to_history(user_id, "/query_history", "GET",
                   data={},
                   result={"history_entries": len(history)})
    
    return HistoryResponse(
        user_id=user_id,
        login=user_data.get("login"),
        history=history,
        count=len(history)
    )


@app.delete("/delete_query_history") # удаление истории запросов
def delete_query_history(request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    cleared = clear_user_history(user_id)
    
    if cleared:
        # Добавляем запись об очистке истории
        history_entry = {
            "timestamp": datetime.now().isoformat(),
            "endpoint": "/delete_query_history",
            "method": "DELETE",
            "data": {"action": "clear_history"},
            "result": {"status": "success", "history_cleared": True}
        }
        
        # Сохраняем эту единственную запись
        history_file = f"{HISTORY_DIR}/history_{user_id}.json"
        os.makedirs(HISTORY_DIR, exist_ok=True)
        
        with open(history_file, "w", encoding="utf-8") as f:
            json.dump([history_entry], f, ensure_ascii=False, indent=2)
        
        user_history[user_id] = [history_entry]
        
        return {"message": "История запросов успешно удалена.", "cleared": True}
    
    return {"message": "История запросов уже пуста.", "cleared": False}


@app.delete("/exit") # выход
def exit(request: Request):
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    add_to_history(user_id, "/exit", "DELETE",
                   data={},
                   result={"status": "exit"})
    
    return {"message": "До новых встреч!\n"}