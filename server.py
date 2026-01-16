from fastapi import FastAPI
from pydantic import BaseModel
import json
import time
import random
import os

app = FastAPI()


class User(BaseModel):
    login: str
    email: str
    password: str


class AuthUser(BaseModel):
    login: str
    password: str


class AuthResponse(BaseModel):
    login: str
    token: str


@app.post("/users/regist")
def create_user(user: User):
    os.makedirs("users", exist_ok=True)

    user_id = int(time.time())
    token = str(random.getrandbits(128))

    data = {
        "login": user.login,
        "email": user.email,
        "password": user.password,
        "token": token
    }

    with open(f"users/{user_id}.json", "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False)

    return AuthResponse(login=user.login, token=token)


@app.post("/users/auth")
def auth_user(params: AuthUser):
    os.makedirs("users", exist_ok=True)

    for file in os.listdir("users"):
        if file.endswith(".json"):
            with open(f"users/{file}", "r", encoding="utf-8") as f:
                data = json.load(f)
                if data["login"] == params.login and data["password"] == params.password:
                    return AuthResponse(login=data["login"], token=data["token"])

    return AuthResponse(login="", token="")

