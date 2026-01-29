from fastapi import FastAPI, HTTPException, Request
from typing import Union, Optional
from pydantic import BaseModel
import json
import time
import random
import os
import hashlib

app = FastAPI()

class User(BaseModel):
    login: str
    email: str
    password: str
    role: Optional[str] = "basic role"
    token: Optional[str] = None
    id: Optional[int] = -1


class AuthUser(BaseModel):
    login: str
    password: str


class AuthResponse(BaseModel):
    login: str
    token: str

class TextRequest(BaseModel):
    text: str

class CipherRequest(BaseModel):
    token: str
    text: str
    key: str

class OneTextRequest(BaseModel):
    token: str
    text_number: int
    type: str  # 'user_text', 'encrypted_text', 'decrypted_text'

# Вариант 4
def signature_variant_4(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Отсутствует заголовок Authorization")
    
    if ":" not in auth_header:
        raise HTTPException(status_code=401, detail="Неверный формат подписи вариант 4")

    signature_hash, sent_timestamp = auth_header.split(":", 1)

    try:
        sent_time = int(sent_timestamp)
        current_time = int(time.time())
        
        if abs(current_time - sent_time) > 300:
            raise HTTPException(status_code=401, detail="Время подписи устарело")
            
    except ValueError:
        raise HTTPException(status_code=401, detail="Неверный формат времени")
    
    query_params = {}
    if request.query_params:
        for key, value in request.query_params.items():
            try:
                query_params[key] = int(value) if value.isdigit() else value
            except:
                query_params[key] = value
    
    params_str = json.dumps(query_params, sort_keys=True) if query_params else ""

    os.makedirs("users", exist_ok=True)
    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    user_token = data.get("token")
                    if user_token:
                        current_time = int(time.time())
                        for hours_ago in range(0, 25):  # 0-24 часа назад
                            timestamp = current_time - (hours_ago * 3600)
                            
                            possible_session_token = f"session_{hashlib.sha256(f'{user_token}:{timestamp}'.encode()).hexdigest()}"
                            expected_hash = hashlib.sha256(
                                f"{possible_session_token}{params_str}{sent_timestamp}".encode()
                            ).hexdigest()
                            
                            if expected_hash == signature_hash:
                                return True
                            return True  
            except json.JSONDecodeError:
                continue
    
    raise HTTPException(status_code=401, detail="Неверная подпись")

def token_search(token: str):
    os.makedirs("users", exist_ok=True)
    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data.get("token") == token:
                        return data.get("id"), data.get("login")
            except json.JSONDecodeError:
                continue
    return None, None
 
def gronsfeld_encrypt(text: str, key: List[int]) -> str: # функции шифрования 
    if not all(isinstance(k, int) and k >= 0 for k in key):
        raise HTTPException(status_code=400, detail="Ключ должен содержать только неотрицательные целые числа")
    
    alphabets = [
        'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ',
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 
        'abcdefghijklmnopqrstuvwxyz', 
    ]
    
    key_len = len(key)
    result = []
    
    for i, char in enumerate(text):
        for alphabet in alphabets:
            if char in alphabet:
                shift = key[i % key_len]
                index_char = alphabet.index(char)
                new_char = alphabet[(index_char + shift) % len(alphabet)]
                result.append(new_char)
                break
        else:
            result.append(char)

    return ''.join(result)

def gronsfeld_decrypt(text: str, key: List[int]) -> str: # функции дешифрования
    if not all(isinstance(k, int) and k >= 0 for k in key):
        raise HTTPException(status_code=400, detail="Ключ должен содержать только неотрицательные целые числа")
    
    alphabets = [
        'АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ', 
        'абвгдеёжзийклмнопрстуфхцчшщъыьэюя',  
        'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
        'abcdefghijklmnopqrstuvwxyz', 
    ]
    
    key_len = len(key)
    result = []
    
    for i, char in enumerate(text):
        for alphabet in alphabets:
            if char in alphabet:
                shift = key[i % key_len]
                index_char = alphabet.index(char)
                new_char = alphabet[(index_char - shift) % len(alphabet)]
                result.append(new_char)
                break
        else:
            result.append(char)

    return ''.join(result)

@app.post("/users/regist")
def create_user(user: User):
    os.makedirs("users", exist_ok=True)

    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
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

    user.id = int(time.time())
    user.token = str(random.getrandbits(128))

    with open(f"users/user_{user.id}.json", "w", encoding="utf-8") as f:
        json.dump(user.dict(), f, ensure_ascii=False)

    return AuthResponse(login=user.login, token=user.token)


@app.post("/users/auth")
def auth_user(params: AuthUser):
    os.makedirs("users", exist_ok=True)

    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if data["login"] == params.login and data["password"] == params.password:
                        return AuthResponse(login=data["login"], token=data["token"])
            except json.JSONDecodeError:
                raise HTTPException(
                    status_code=500,
                    detail="Ошибка чтения базы пользователей"
                )
    raise HTTPException(status_code=401, detail="Неверный логин или пароль")


@app.get("/users/{user_id}")
def user_read(user_id: int, q: Union[int, None] = 0, a: Union[int, None] = 0, request: Request = None):
    user_data = signature_variant_4(request)
    
    if user_data.get("id") != user_id:
        raise HTTPException(status_code=403, detail="Доступ запрещен")
    
    sum = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": sum}

@app.post("/texts/add") #добавление текста
def add_text(text_request: TextRequest, request: Request):
 
    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if not text_request.text or not text_request.text.strip():
        raise HTTPException(status_code=400, detail="Текст не может быть пустым")
    
    os.makedirs("user_texts", exist_ok=True)

    text_id = int(time.time())
   
    text_file = f"user_texts/text_{user_id}_{text_id}.txt"
    try:
        with open(text_file, "w", encoding="utf-8") as f:
            f.write(text_request.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения текста: {str(e)}")
    
    return {
        "message": "Текст успешно добавлен",
        "text_id": text_id
    }


@app.get("/texts") # просмотр всех текстов
def get_all_texts(request: Request):

    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    user_texts = []
    
    if os.path.exists("user_texts"):
        for file in os.listdir("user_texts"):
            if file.startswith(f"text_{user_id}_") and file.endswith(".txt"):
                try:
                    file_text_id = int(file.split("_")[2].split(".")[0])
                    try:
                        with open(f"user_texts/{file}", "r", encoding="utf-8") as f:
                            content = f.read()
                            preview = content[:100] + "..." if len(content) > 100 else content
                            user_texts.append({
                                "text_id": file_text_id,
                                "filename": file,
                                "preview": preview,
                                "full_length": len(content)
                            })
                    except:
                        user_texts.append({
                            "text_id": file_text_id,
                            "filename": file,
                            "preview": "Ошибка чтения файла",
                            "full_length": 0
                        })
                except:
                    continue
    
    user_texts.sort(key=lambda x: x["text_id"], reverse=True)
    
    return {
        "user_id": user_id,
        "texts_count": len(user_texts),
        "texts": user_texts
    }

@app.get("/texts/{text_id}") # просмотр конкретного текста
def get_text(text_id: int, request: Request):

    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    text_files = []
    if os.path.exists("user_texts"):
        for file in os.listdir("user_texts"):
            if file.startswith(f"text_{user_id}_") and file.endswith(".txt"):
                try:
                    file_text_id = int(file.split("_")[2].split(".")[0])
                    if file_text_id == text_id:
                        text_files.append(file)
                except:
                    continue
    
    if not text_files:
        raise HTTPException(status_code=404, detail="Текст не найден")
    
    text_file = text_files[0]
    try:
        with open(f"user_texts/{text_file}", "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения текста: {str(e)}")
    
    return {
        "text_id": text_id,
        "content": content,
        "filename": text_file
    }

@app.delete("/texts/{text_id}") # удаление текста
def delete_text(text_id: int, request: Request):

    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    text_files = []
    if os.path.exists("user_texts"):
        for file in os.listdir("user_texts"):
            if file.startswith(f"text_{user_id}_") and file.endswith(".txt"):
                try:
                    file_text_id = int(file.split("_")[2].split(".")[0])
                    if file_text_id == text_id:
                        text_files.append(file)
                except:
                    continue
    
    if not text_files:
        raise HTTPException(status_code=404, detail="Текст не найден")
    
    text_file = text_files[0]
    file_path = f"user_texts/{text_file}"
    
    try:
        os.remove(file_path)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка удаления текста: {str(e)}")
    
    return {
        "message": "Текст успешно удален",
        "text_id": text_id,
        "filename": text_file
    }

@app.patch("/texts/{text_id}") # изменение текста
def update_text(text_id: int, text_request: TextRequest, request: Request):

    user_data = signature_variant_4(request)
    
    if not user_data:
        raise HTTPException(status_code=401, detail="Пользователь не найден")
    
    user_id = user_data.get("id")
    
    if not text_request.text or not text_request.text.strip():
        raise HTTPException(status_code=400, detail="Текст не может быть пустым")
    
    text_files = []
    if os.path.exists("user_texts"):
        for file in os.listdir("user_texts"):
            if file.startswith(f"text_{user_id}_") and file.endswith(".txt"):
                try:
                    file_text_id = int(file.split("_")[2].split(".")[0])
                    if file_text_id == text_id:
                        text_files.append(file)
                except:
                    continue
    
    if not text_files:
        raise HTTPException(status_code=404, detail="Текст не найден")
    
    text_file = text_files[0]
    
    try:
        with open(f"user_texts/{text_file}", "w", encoding="utf-8") as f:
            f.write(text_request.text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка изменения текста: {str(e)}")
    
    return {
        "message": "Текст успешно изменен",
        "text_id": text_id,
        "filename": text_file
    }

@app.post("/cipher_encrypt") # функция шифрования текста
def encrypt(data: CipherRequest):
    user_id, user_login = token_search(data.token)
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    if not data.text.strip():
        user_folder = f"user_texts/{user_id}"
        if not os.path.exists(user_folder) or not os.listdir(user_folder):
            raise HTTPException(status_code=404, detail="Нет доступных текстов для пользователя")
        
        text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
        text_files.sort(reverse=True)
        last_text_file = text_files[0]
        file_path = f"{user_folder}/{last_text_file}"
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data.text = f.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка чтения текста: {str(e)}")
    
    try:
        key_list = [int(digit) for digit in data.key]
        encrypted_text = gronsfeld_encrypt(data.text, key_list)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка шифрования: {str(e)}")
    
    user_folder = f"encrypted_texts/{user_id}"
    os.makedirs(user_folder, exist_ok=True)
    
    text_id = int(time.time())
    file_path = f"{user_folder}/text_{text_id}.txt"
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(encrypted_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения зашифрованного текста: {str(e)}")
    
    return {"message": encrypted_text}

@app.post("/cipher_decrypt") # функция дешифрования текста
def decrypt(data: CipherRequest):
    user_id, user_login = token_search(data.token)
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    if not data.text.strip():
        user_folder = f"encrypted_texts/{user_id}"
        if not os.path.exists(user_folder) or not os.listdir(user_folder):
            raise HTTPException(status_code=404, detail="Нет доступных зашифрованных текстов")
        
        text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
        text_files.sort(reverse=True)
        last_text_file = text_files[0]
        file_path = f"{user_folder}/{last_text_file}"
        
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data.text = f.read()
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Ошибка чтения зашифрованного текста: {str(e)}")
    
    try:
        key_list = [int(digit) for digit in data.key]
        decrypted_text = gronsfeld_decrypt(data.text, key_list)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка дешифрования: {str(e)}")
    
    user_folder = f"decrypted_texts/{user_id}"
    os.makedirs(user_folder, exist_ok=True)
    
    text_id = int(time.time())
    file_path = f"{user_folder}/text_{text_id}.txt"
    
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(decrypted_text)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка сохранения расшифрованного текста: {str(e)}")
    
    return {"message": decrypted_text}

@app.get("/view_encrypted_texts") # просмотр зашифрованных текстов 
def view_encrypted_text(token: str):
    user_id, user_login = token_search(token)
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_folder = f"encrypted_texts/{user_id}"
    os.makedirs(user_folder, exist_ok=True)
    
    if not os.path.exists(user_folder) or not os.listdir(user_folder):
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
    
    return {"texts": encrypted_texts}

@app.get("/view_decrypted_texts") # просмотр расшифрованных текстов 
def view_decrypted_text(token: str):
    user_id, user_login = token_search(token)
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    user_folder = f"decrypted_texts/{user_id}"
    os.makedirs(user_folder, exist_ok=True)
    
    if not os.path.exists(user_folder) or not os.listdir(user_folder):
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
    
    return {"texts": decrypted_texts}

@app.post("/view_one_text") # просмотр одного текста пользователя
def view_one_text(text: OneTextRequest):
    user_id, user_login = token_search(text.token)
    
    if user_id is None:
        raise HTTPException(status_code=404, detail="Пользователь не найден")
    
    if text.type == "user_text":
        base_dir = "user_texts"
    elif text.type == "encrypted_text":
        base_dir = "encrypted_texts"
    elif text.type == "decrypted_text":
        base_dir = "decrypted_texts"
    else:
        raise HTTPException(status_code=400, detail="Неверный тип текста")
    
    user_folder = f"{base_dir}/{user_id}"
    
    if not os.path.exists(user_folder):
        raise HTTPException(status_code=404, detail="Нет текстов для пользователя")
    
    text_files = [f for f in os.listdir(user_folder) if f.endswith(".txt")]
    text_files.sort(reverse=True)
    
    if not text_files:
        return {"message": f"У вас нет текстов типа '{text.type}'."}
    
    if text.text_number < 1 or text.text_number > len(text_files):
        raise HTTPException(status_code=400, detail=f"Выберите номер от 1 до {len(text_files)}")
    
    selected_file = text_files[text.text_number - 1]
    file_path = os.path.join(user_folder, selected_file)
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ошибка чтения файла: {str(e)}")
    
    return {"text": content, "filename": selected_file}