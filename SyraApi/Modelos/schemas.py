from pydantic import BaseModel, EmailStr, Field, validator
from typing import Optional
from datetime import datetime
import re

class UserRegister(BaseModel):
    """Schema para registro de novo usuário"""
    user: str = Field(..., min_length=3, max_length=50, description="Nome de usuário único")
    email: EmailStr = Field(..., description="Email válido")
    password: str = Field(..., min_length=8, description="Senha principal (mínimo 8 caracteres)")
    senha_seguranca: str = Field(..., min_length=6, description="Senha de segurança (mínimo 6 caracteres)")
    telefone: str = Field(..., description="Número de telefone")
    foto_perfil: Optional[str] = Field(None, description="URL ou caminho da foto (opcional)")
    
    @validator('user')
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_-]+$', v):
            raise ValueError('Username deve conter apenas letras, números, underscore e hífen')
        return v
    
    @validator('telefone')
    def validate_phone(cls, v):
        # Remove caracteres não numéricos
        phone = re.sub(r'\D', '', v)
        if len(phone) < 10 or len(phone) > 15:
            raise ValueError('Telefone deve ter entre 10 e 15 dígitos')
        return phone
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Senha deve ter no mínimo 8 caracteres')
        if not re.search(r'[A-Z]', v):
            raise ValueError('Senha deve conter pelo menos uma letra maiúscula')
        if not re.search(r'[a-z]', v):
            raise ValueError('Senha deve conter pelo menos uma letra minúscula')
        if not re.search(r'\d', v):
            raise ValueError('Senha deve conter pelo menos um número')
        return v

class UserLogin(BaseModel):
    """Schema para login de usuário"""
    user: str = Field(..., description="Username ou email")
    password: str = Field(..., description="Senha principal")

class UserResponse(BaseModel):
    """Schema para resposta com dados do usuário"""
    id: int  # Mudado de str para int
    user: str
    email: str
    hash_unico: str
    telefone: str
    foto_perfil: Optional[str]
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]
    
    class Config:
        from_attributes = True

class TokenResponse(BaseModel):
    """Schema para resposta de token JWT"""
    access_token: str
    token_type: str = "bearer"
    user: UserResponse
    default_model_id: Optional[int] = None  # ID do modelo padrão criado para o usuário
