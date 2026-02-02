from typing import Optional, List
from pydantic import BaseModel

class User(BaseModel): #модель для пользователя
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


class ChangePasswordRequest(BaseModel): #модель для смены пароля
    old_password: str
    new_password: str


class ChangePasswordResponse(BaseModel): 
    message: str
    token: str


class TextRequest(BaseModel): #модель для работы с текстом
    text: str


class CipherRequest(BaseModel): #модель для шифрования, дешифрования
    text: str
    key: List[int]


class HistoryEntry(BaseModel):
    timestamp: str
    endpoint: str
    method: str
    data: Optional[dict] = None
    result: Optional[dict] = None


class HistoryResponse(BaseModel):
    user_id: int
    login: Optional[str] = None
    history: List[HistoryEntry]
    count: int