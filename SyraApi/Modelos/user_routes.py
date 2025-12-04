"""
Rotas de Perfil de Usuário e Busca
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_, func
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Modelos.location import UserBond


router_user = APIRouter(prefix="/user", tags=["Usuário"])


# ========== Schemas ==========

class UserProfileResponse(BaseModel):
    """Schema de resposta de perfil"""
    id: int
    user: str
    email: str
    telefone: str
    foto_perfil: Optional[str]
    created_at: datetime
    
    # Estatísticas
    total_compromissos: int = 0
    total_arquivos: int = 0
    total_notas: int = 0
    total_posts: int = 0
    total_vinculos: int = 0
    
    class Config:
        from_attributes = True


class UserSearchResponse(BaseModel):
    """Schema de resposta de busca"""
    id: int
    user: str
    foto_perfil: Optional[str]
    tem_vinculo: bool = False
    status_vinculo: Optional[str] = None
    
    class Config:
        from_attributes = True


class ProfileUpdateRequest(BaseModel):
    """Schema para atualizar perfil"""
    telefone: Optional[str] = Field(None, min_length=10, max_length=15)
    foto_perfil: Optional[str] = None


# ========== Rotas ==========

@router_user.get("/me", response_model=UserProfileResponse)
async def obter_perfil_completo(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Obtém perfil completo do usuário autenticado
    Inclui todas as estatísticas e informações
    """
    
    from Modelos.agenda import Compromisso
    from Modelos.social_models import UserFile, UserNote, Post
    
    # Contar estatísticas
    total_compromissos = db.query(func.count(Compromisso.id)).filter(
        Compromisso.user_id == current_user.id
    ).scalar()
    
    total_arquivos = db.query(func.count(UserFile.id)).filter(
        UserFile.user_id == current_user.id
    ).scalar()
    
    total_notas = db.query(func.count(UserNote.id)).filter(
        UserNote.user_id == current_user.id
    ).scalar()
    
    total_posts = db.query(func.count(Post.id)).filter(
        Post.user_id == current_user.id,
        Post.expires_at > datetime.now()
    ).scalar()
    
    total_vinculos = db.query(func.count(UserBond.id)).filter(
        or_(
            UserBond.user_id_1 == current_user.id,
            UserBond.user_id_2 == current_user.id
        ),
        UserBond.status == "accepted"
    ).scalar()
    
    # Criar resposta
    profile = UserProfileResponse(
        id=current_user.id,
        user=current_user.user,
        email=current_user.email,
        telefone=current_user.telefone,
        foto_perfil=current_user.foto_perfil,
        created_at=current_user.created_at,
        total_compromissos=total_compromissos,
        total_arquivos=total_arquivos,
        total_notas=total_notas,
        total_posts=total_posts,
        total_vinculos=total_vinculos
    )
    
    return profile


@router_user.put("/me")
async def atualizar_perfil(
    dados: ProfileUpdateRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza informações do perfil"""
    
    update_data = dados.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(current_user, field, value)
    
    current_user.updated_at = datetime.now()
    
    db.commit()
    db.refresh(current_user)
    
    return {
        "success": True,
        "message": "Perfil atualizado com sucesso",
        "user": {
            "id": current_user.id,
            "user": current_user.user,
            "telefone": current_user.telefone,
            "foto_perfil": current_user.foto_perfil
        }
    }


@router_user.get("/search", response_model=List[UserSearchResponse])
async def buscar_usuarios(
    query: str,
    skip: int = 0,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Busca usuários por username ou email
    Mostra status de vínculo com cada usuário
    """
    
    if len(query) < 2:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Query deve ter pelo menos 2 caracteres"
        )
    
    # Buscar usuários
    usuarios = db.query(User).filter(
        or_(
            User.user.like(f"%{query}%"),
            User.email.like(f"%{query}%")
        ),
        User.id != current_user.id,  # Não mostrar o próprio usuário
        User.is_active == True
    ).offset(skip).limit(limit).all()
    
    # Verificar vínculos
    response_users = []
    for user in usuarios:
        vinculo = db.query(UserBond).filter(
            or_(
                and_(UserBond.user_id_1 == current_user.id, UserBond.user_id_2 == user.id),
                and_(UserBond.user_id_1 == user.id, UserBond.user_id_2 == current_user.id)
            )
        ).first()
        
        user_response = UserSearchResponse(
            id=user.id,
            user=user.user,
            foto_perfil=user.foto_perfil,
            tem_vinculo=vinculo is not None,
            status_vinculo=vinculo.status if vinculo else None
        )
        
        response_users.append(user_response)
    
    return response_users


@router_user.get("/{user_id}", response_model=UserProfileResponse)
async def obter_perfil_usuario(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Obtém perfil público de outro usuário
    Mostra informações limitadas (apenas estatísticas públicas)
    """
    
    user = db.query(User).filter(
        User.id == user_id,
        User.is_active == True
    ).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    from Modelos.social_models import Post
    
    # Estatísticas públicas
    total_posts = db.query(func.count(Post.id)).filter(
        Post.user_id == user_id,
        Post.expires_at > datetime.now()
    ).scalar()
    
    total_vinculos = db.query(func.count(UserBond.id)).filter(
        or_(
            UserBond.user_id_1 == user_id,
            UserBond.user_id_2 == user_id
        ),
        UserBond.status == "accepted"
    ).scalar()
    
    # Perfil público (informações limitadas)
    profile = UserProfileResponse(
        id=user.id,
        user=user.user,
        email=user.email if user_id == current_user.id else "***",  # Email oculto
        telefone="***",  # Telefone oculto
        foto_perfil=user.foto_perfil,
        created_at=user.created_at,
        total_posts=total_posts,
        total_vinculos=total_vinculos
    )
    
    return profile


@router_user.get("/stats/dashboard")
async def dashboard_estatisticas(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Dashboard com estatísticas completas do usuário
    """
    
    from Modelos.agenda import Compromisso
    from Modelos.social_models import UserFile, UserNote, Post
    
    agora = datetime.now()
    
    # Compromissos
    total_compromissos = db.query(func.count(Compromisso.id)).filter(
        Compromisso.user_id == current_user.id
    ).scalar()
    
    compromissos_pendentes = db.query(func.count(Compromisso.id)).filter(
        Compromisso.user_id == current_user.id,
        Compromisso.concluido == False,
        Compromisso.data_hora > agora
    ).scalar()
    
    # Arquivos
    total_arquivos = db.query(func.count(UserFile.id)).filter(
        UserFile.user_id == current_user.id
    ).scalar()
    
    tamanho_total = db.query(func.sum(UserFile.file_size)).filter(
        UserFile.user_id == current_user.id
    ).scalar() or 0
    
    # Notas
    total_notas = db.query(func.count(UserNote.id)).filter(
        UserNote.user_id == current_user.id
    ).scalar()
    
    notas_fixadas = db.query(func.count(UserNote.id)).filter(
        UserNote.user_id == current_user.id,
        UserNote.fixada == True
    ).scalar()
    
    # Posts
    total_posts = db.query(func.count(Post.id)).filter(
        Post.user_id == current_user.id,
        Post.expires_at > agora
    ).scalar()
    
    total_curtidas_recebidas = db.query(func.sum(Post.curtidas)).filter(
        Post.user_id == current_user.id
    ).scalar() or 0
    
    # Vínculos
    total_vinculos = db.query(func.count(UserBond.id)).filter(
        or_(
            UserBond.user_id_1 == current_user.id,
            UserBond.user_id_2 == current_user.id
        ),
        UserBond.status == "accepted"
    ).scalar()
    
    vinculos_pendentes = db.query(func.count(UserBond.id)).filter(
        UserBond.user_id_2 == current_user.id,
        UserBond.status == "pending"
    ).scalar()
    
    return {
        "usuario": {
            "id": current_user.id,
            "username": current_user.user,
            "membro_desde": current_user.created_at.strftime("%Y-%m-%d")
        },
        "agenda": {
            "total_compromissos": total_compromissos,
            "pendentes": compromissos_pendentes
        },
        "drive": {
            "total_arquivos": total_arquivos,
            "tamanho_total_mb": round(tamanho_total / (1024*1024), 2)
        },
        "notas": {
            "total": total_notas,
            "fixadas": notas_fixadas
        },
        "social": {
            "total_posts": total_posts,
            "curtidas_recebidas": total_curtidas_recebidas,
            "vinculos": total_vinculos,
            "vinculos_pendentes": vinculos_pendentes
        }
    }
