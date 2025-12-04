from fastapi import APIRouter, Depends, HTTPException, status, Header, Form
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
from datetime import datetime
from typing import Optional

from DB.database import get_db
from Modelos.user import User
from Modelos.schemas import UserRegister, UserLogin, TokenResponse, UserResponse
from Tools.security import (
    hash_password, 
    verify_password, 
    generate_unique_hash, 
    create_access_token,
    verify_token
)
from Tools.file_manager import create_user_directory

router = APIRouter(prefix="/auth", tags=["Autenticação"])


def create_default_user_model(user_id: int, username: str, db: Session):
    """
    Cria modelo de IA padrão para o usuário no momento do cadastro
    Cada usuário recebe automaticamente seu próprio modelo personalizado
    """
    from Modelos.ai_models import UserAIModel
    from Tools.ai_manager import ai_manager
    
    try:
        # Criar modelo padrão
        default_model = UserAIModel(
            user_id=user_id,
            model_name=f"Assistente de {username}",
            model_type="conversational",
            description=f"Modelo de IA pessoal de {username}. Treine-o com seus próprios conhecimentos e comandos.",
            model_path=""
        )
        
        db.add(default_model)
        db.commit()
        db.refresh(default_model)
        
        # Criar estrutura de diretórios e bancos
        model_dir = ai_manager.get_user_model_dir(user_id, default_model.id)
        default_model.model_path = str(model_dir / "model.pt")
        
        # Criar bancos de conhecimento e comandos
        knowledge_db = ai_manager.get_knowledge_db_path(user_id, default_model.id)
        commands_db = ai_manager.get_commands_db_path(user_id, default_model.id)
        
        ai_manager.create_knowledge_db(str(knowledge_db))
        ai_manager.create_commands_db(str(commands_db))
        
        # Adicionar conhecimentos básicos padrão
        default_knowledge = [
            {"question": "qual seu nome", "answer": f"Sou o assistente pessoal de {username}, criado na plataforma Syra."},
            {"question": "quem te criou", "answer": f"Fui criado por {username} usando a plataforma Syra."},
            {"question": "o que você faz", "answer": "Sou um assistente de IA personalizado. Posso aprender novos conhecimentos e executar comandos conforme você me treinar."},
            {"question": "como funciona", "answer": "Você pode me ensinar coisas novas adicionando conhecimentos e comandos. Quanto mais você me treinar, mais útil eu serei!"},
        ]
        
        for item in default_knowledge:
            ai_manager.add_knowledge(
                str(knowledge_db),
                question=item["question"],
                answer=item["answer"],
                category="sistema"
            )
        
        db.commit()
        
        return default_model
        
    except Exception as e:
        db.rollback()
        print(f"[!] Erro ao criar modelo padrão para {username}: {e}")
        return None

# ──────────────────────────────────────────────
# REGISTRO DE NOVO USUÁRIO
# ──────────────────────────────────────────────
@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register_user(user_data: UserRegister, db: Session = Depends(get_db)):
    """
    Registra um novo usuário no sistema
    
    - **user**: Nome de usuário único (3-50 caracteres, apenas letras, números, _ e -)
    - **email**: Email válido e único
    - **password**: Senha principal (mínimo 8 caracteres, deve conter maiúscula, minúscula e número)
    - **senha_seguranca**: Senha de segurança para recuperação (mínimo 6 caracteres)
    - **telefone**: Número de telefone (10-15 dígitos)
    - **foto_perfil**: URL ou caminho da foto (opcional)
    """
    
    # Verifica se username já existe
    existing_user = db.query(User).filter(User.user == user_data.user).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username já está em uso"
        )
    
    # Verifica se email já existe
    existing_email = db.query(User).filter(User.email == user_data.email).first()
    if existing_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email já está cadastrado"
        )
    
    # Gera hash único para o usuário
    hash_unico = generate_unique_hash(user_data.user, user_data.email)
    
    # Cria diretório pessoal do usuário
    user_directory = create_user_directory(hash_unico)
    
    # Cria hash das senhas
    password_hash = hash_password(user_data.password)
    senha_seguranca_hash = hash_password(user_data.senha_seguranca)
    
    # Cria novo usuário
    new_user = User(
        user=user_data.user,
        hash_unico=hash_unico,
        email=user_data.email,
        password_hash=password_hash,
        senha_seguranca_hash=senha_seguranca_hash,
        telefone=user_data.telefone,
        foto_perfil=user_data.foto_perfil,
        user_directory=user_directory,
        is_active=True
    )
    
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    # Criar modelo de IA padrão para o usuário
    default_model = create_default_user_model(new_user.id, new_user.user, db)
    
    # Gera token JWT
    access_token = create_access_token(data={"sub": new_user.user, "user_id": new_user.id})
    
    # Prepara resposta
    user_response = UserResponse.from_orm(new_user)
    
    return TokenResponse(
        access_token=access_token,
        user=user_response,
        default_model_id=default_model.id if default_model else None
    )

# ──────────────────────────────────────────────
# LOGIN DE USUÁRIO
# ──────────────────────────────────────────────
@router.post("/login", response_model=TokenResponse)
async def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Autentica um usuário e retorna token JWT
    
    Suporta OAuth2 form data (username/password) ou JSON (user/password)
    
    - **username**: Username ou email
    - **password**: Senha principal
    """
    
    # Busca usuário por username ou email
    user = db.query(User).filter(
        (User.user == form_data.username) | (User.email == form_data.username)
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica senha
    if not verify_password(form_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica se usuário está ativo
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo"
        )
    
    # Atualiza último login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Gera token JWT
    access_token = create_access_token(data={"sub": user.user, "user_id": user.id})
    
    # Prepara resposta
    user_response = UserResponse.from_orm(user)
    
    return TokenResponse(
        access_token=access_token,
        user=user_response
    )


@router.post("/login/json", response_model=TokenResponse)
async def login_user_json(login_data: UserLogin, db: Session = Depends(get_db)):
    """
    Autentica um usuário via JSON e retorna token JWT
    
    - **user**: Username ou email
    - **password**: Senha principal
    """
    
    # Busca usuário por username ou email
    user = db.query(User).filter(
        (User.user == login_data.user) | (User.email == login_data.user)
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica senha
    if not verify_password(login_data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Credenciais inválidas",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica se usuário está ativo
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo"
        )
    
    # Atualiza último login
    user.last_login = datetime.utcnow()
    db.commit()
    
    # Gera token JWT
    access_token = create_access_token(data={"sub": user.user, "user_id": user.id})
    
    # Prepara resposta
    user_response = UserResponse.from_orm(user)
    
    return TokenResponse(
        access_token=access_token,
        user=user_response
    )

# ──────────────────────────────────────────────
# OBTER USUÁRIO ATUAL (PROTEGIDA)
# ──────────────────────────────────────────────
async def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency para obter o usuário atual do token JWT
    Uso: current_user: User = Depends(get_current_user)
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token não fornecido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Extrai token do header "Bearer <token>"
    try:
        scheme, token = authorization.split()
        if scheme.lower() != "bearer":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Esquema de autenticação inválido",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Formato de token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verifica token
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido ou expirado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id: str = payload.get("user_id")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token inválido",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Busca usuário
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuário não encontrado",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Usuário inativo"
        )
    
    return user

# ──────────────────────────────────────────────
# ROTA PROTEGIDA DE EXEMPLO - PERFIL DO USUÁRIO
# ──────────────────────────────────────────────
@router.get("/me", response_model=UserResponse)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    """
    Retorna informações do usuário autenticado
    Requer token JWT válido no header: Authorization: Bearer <token>
    """
    return UserResponse.from_orm(current_user)
