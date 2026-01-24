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

# Второй вариант подписи
def signature_variant_2(request: Request):
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        raise HTTPException(status_code=401, detail="Отсутствует заголовок Authorization")
    
    if ":" not in auth_header:
        raise HTTPException(status_code=401, detail="Неверный формат подписи")

    signature_hash, sent_timestamp = auth_header.split(":", 1)

    try:
        sent_time = int(sent_timestamp)
        current_time = int(time.time())
        
        # Проверяем, что время не устарело (180 сек)
        if abs(current_time - sent_time) > 180:  
            raise HTTPException(status_code=401, detail="Время подписи устарело")
            
    except ValueError:
        raise HTTPException(status_code=401, detail="Неверный формат времени")
    
    # Ищем пользователя, чей токен дает нужный хэш
    os.makedirs("users", exist_ok=True)
    for file in os.listdir("users"):
        if file.endswith(".json"):
            try:
                with open(f"users/{file}", "r", encoding="utf-8") as f:
                    data = json.load(f)
                    user_token = data.get("token")
                    if user_token:
                        # Проверяем хэш
                        expected_hash = hashlib.sha256(f"{user_token}{sent_timestamp}".encode()).hexdigest()
                        if expected_hash == signature_hash:
                            return True  
            except json.JSONDecodeError:
                continue
    
    raise HTTPException(status_code=401, detail="Неверная подпись")

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
    signature_variant_2(request)
    
    sum = q + a
    return {"user_id": user_id, "q": q, "a": a, "sum": sum} 



