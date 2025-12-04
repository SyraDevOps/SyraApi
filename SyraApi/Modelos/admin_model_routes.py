"""
Rotas de administração para gerenciamento de modelos de IA
Permite que admin controle acesso a modelos entre usuários
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import or_
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.ai_models import UserAIModel, SharedModelAccess, GlobalModel
from Modelos.auth import get_current_user
from Tools.middleware import verify_admin

router_admin_models = APIRouter(prefix="/admin/models", tags=["Admin - Modelos"])


# ========== Schemas ==========

class ShareModelRequest(BaseModel):
    """Schema para compartilhar modelo com usuário"""
    user_id: int = Field(..., description="ID do usuário que receberá acesso")
    model_id: int = Field(..., description="ID do modelo a compartilhar")
    access_level: str = Field("read", description="Nível de acesso: read, write, train, full")
    expires_at: Optional[datetime] = Field(None, description="Data de expiração do acesso (opcional)")


class RevokeAccessRequest(BaseModel):
    """Schema para revogar acesso a modelo"""
    user_id: int = Field(..., description="ID do usuário")
    model_id: int = Field(..., description="ID do modelo")


class CreateGlobalModelRequest(BaseModel):
    """Schema para criar modelo global"""
    model_name: str = Field(..., min_length=3, max_length=255)
    model_type: str = Field("selene", description="selene, custom, imported")
    description: Optional[str] = None
    model_path: str = Field(..., description="Caminho do modelo")
    is_public: bool = Field(True, description="Se todos podem usar")
    requires_approval: bool = Field(False, description="Se admin precisa aprovar uso")
    config: Optional[dict] = None


class UpdateAccessLevelRequest(BaseModel):
    """Schema para atualizar nível de acesso"""
    access_level: str = Field(..., description="Novo nível: read, write, train, full")
    expires_at: Optional[datetime] = None


class SharedModelResponse(BaseModel):
    """Response para modelo compartilhado"""
    id: int
    user_id: int
    username: str
    model_id: int
    model_name: str
    model_owner_id: int
    model_owner_name: str
    access_level: str
    is_active: bool
    expires_at: Optional[datetime]
    granted_at: datetime
    granted_by: int
    
    class Config:
        from_attributes = True


class GlobalModelResponse(BaseModel):
    """Response para modelo global"""
    id: int
    model_name: str
    model_type: str
    description: Optional[str]
    model_path: str
    is_public: bool
    requires_approval: bool
    is_active: bool
    created_by: int
    created_at: datetime
    
    class Config:
        from_attributes = True


class UserModelSummary(BaseModel):
    """Resumo dos modelos de um usuário"""
    user_id: int
    username: str
    own_models: int
    shared_with_user: int
    shared_by_user: int


# ========== Rotas de Compartilhamento ==========

@router_admin_models.post("/share")
async def share_model_with_user(
    request: ShareModelRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Compartilha um modelo com outro usuário
    Apenas administradores podem usar esta rota
    """
    verify_admin(current_user)
    
    # Verificar se usuário existe
    target_user = db.query(User).filter(User.id == request.user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com ID {request.user_id} não encontrado"
        )
    
    # Verificar se modelo existe
    model = db.query(UserAIModel).filter(UserAIModel.id == request.model_id).first()
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Modelo com ID {request.model_id} não encontrado"
        )
    
    # Verificar se usuário já é dono do modelo
    if model.user_id == request.user_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível compartilhar modelo com o próprio dono"
        )
    
    # Validar nível de acesso
    valid_levels = ["read", "write", "train", "full"]
    if request.access_level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nível de acesso inválido. Use: {', '.join(valid_levels)}"
        )
    
    # Verificar se já existe compartilhamento
    existing = db.query(SharedModelAccess).filter(
        SharedModelAccess.user_id == request.user_id,
        SharedModelAccess.model_id == request.model_id
    ).first()
    
    if existing:
        # Atualizar compartilhamento existente
        existing.access_level = request.access_level
        existing.expires_at = request.expires_at
        existing.is_active = True
        existing.granted_by = current_user.id
        existing.granted_at = datetime.utcnow()
        db.commit()
        
        return {
            "success": True,
            "message": "Acesso atualizado",
            "access_id": existing.id,
            "user": target_user.user,
            "model": model.model_name,
            "access_level": request.access_level
        }
    
    # Criar novo compartilhamento
    new_access = SharedModelAccess(
        user_id=request.user_id,
        model_id=request.model_id,
        access_level=request.access_level,
        granted_by=current_user.id,
        expires_at=request.expires_at,
        is_active=True
    )
    
    db.add(new_access)
    db.commit()
    db.refresh(new_access)
    
    return {
        "success": True,
        "message": "Modelo compartilhado com sucesso",
        "access_id": new_access.id,
        "user": target_user.user,
        "model": model.model_name,
        "access_level": request.access_level,
        "expires_at": request.expires_at
    }


@router_admin_models.post("/revoke")
async def revoke_model_access(
    request: RevokeAccessRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revoga acesso de um usuário a um modelo
    """
    verify_admin(current_user)
    
    access = db.query(SharedModelAccess).filter(
        SharedModelAccess.user_id == request.user_id,
        SharedModelAccess.model_id == request.model_id
    ).first()
    
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Acesso não encontrado"
        )
    
    db.delete(access)
    db.commit()
    
    return {
        "success": True,
        "message": "Acesso revogado com sucesso"
    }


@router_admin_models.get("/shared")
async def list_all_shared_models(
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[int] = None,
    model_id: Optional[int] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista todos os compartilhamentos de modelos
    Filtros opcionais por user_id ou model_id
    """
    verify_admin(current_user)
    
    query = db.query(SharedModelAccess)
    
    if user_id:
        query = query.filter(SharedModelAccess.user_id == user_id)
    if model_id:
        query = query.filter(SharedModelAccess.model_id == model_id)
    
    total = query.count()
    accesses = query.offset(skip).limit(limit).all()
    
    result = []
    for access in accesses:
        user = db.query(User).filter(User.id == access.user_id).first()
        model = db.query(UserAIModel).filter(UserAIModel.id == access.model_id).first()
        owner = db.query(User).filter(User.id == model.user_id).first() if model else None
        
        result.append({
            "id": access.id,
            "user_id": access.user_id,
            "username": user.user if user else "Desconhecido",
            "model_id": access.model_id,
            "model_name": model.model_name if model else "Desconhecido",
            "model_owner_id": model.user_id if model else None,
            "model_owner_name": owner.user if owner else "Desconhecido",
            "access_level": access.access_level,
            "is_active": access.is_active,
            "expires_at": access.expires_at,
            "granted_at": access.granted_at,
            "granted_by": access.granted_by
        })
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "shared_models": result
    }


@router_admin_models.put("/access/{access_id}")
async def update_access_level(
    access_id: int,
    request: UpdateAccessLevelRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Atualiza nível de acesso de um compartilhamento
    """
    verify_admin(current_user)
    
    access = db.query(SharedModelAccess).filter(SharedModelAccess.id == access_id).first()
    
    if not access:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Acesso não encontrado"
        )
    
    valid_levels = ["read", "write", "train", "full"]
    if request.access_level not in valid_levels:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Nível inválido. Use: {', '.join(valid_levels)}"
        )
    
    access.access_level = request.access_level
    if request.expires_at:
        access.expires_at = request.expires_at
    
    db.commit()
    
    return {
        "success": True,
        "message": "Nível de acesso atualizado",
        "access_id": access_id,
        "new_level": request.access_level
    }


# ========== Rotas de Modelos Globais ==========

@router_admin_models.post("/global")
async def create_global_model(
    request: CreateGlobalModelRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cria um modelo global disponível para todos os usuários
    Usado para registrar modelos Selene ou outros modelos pré-treinados
    """
    verify_admin(current_user)
    
    # Verificar se já existe modelo com esse nome
    existing = db.query(GlobalModel).filter(
        GlobalModel.model_name == request.model_name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Já existe um modelo global com o nome '{request.model_name}'"
        )
    
    new_model = GlobalModel(
        model_name=request.model_name,
        model_type=request.model_type,
        description=request.description,
        model_path=request.model_path,
        is_public=request.is_public,
        requires_approval=request.requires_approval,
        config=request.config,
        created_by=current_user.id,
        is_active=True
    )
    
    db.add(new_model)
    db.commit()
    db.refresh(new_model)
    
    return {
        "success": True,
        "message": "Modelo global criado",
        "model_id": new_model.id,
        "model_name": new_model.model_name
    }


@router_admin_models.get("/global")
async def list_global_models(
    include_inactive: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista todos os modelos globais disponíveis
    """
    query = db.query(GlobalModel)
    
    if not include_inactive:
        query = query.filter(GlobalModel.is_active == True)
    
    models = query.all()
    
    return {
        "total": len(models),
        "global_models": [
            {
                "id": m.id,
                "model_name": m.model_name,
                "model_type": m.model_type,
                "description": m.description,
                "model_path": m.model_path,
                "is_public": m.is_public,
                "requires_approval": m.requires_approval,
                "is_active": m.is_active,
                "created_by": m.created_by,
                "created_at": m.created_at
            }
            for m in models
        ]
    }


@router_admin_models.delete("/global/{model_id}")
async def delete_global_model(
    model_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Remove um modelo global
    """
    verify_admin(current_user)
    
    model = db.query(GlobalModel).filter(GlobalModel.id == model_id).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo global não encontrado"
        )
    
    db.delete(model)
    db.commit()
    
    return {
        "success": True,
        "message": f"Modelo global '{model.model_name}' removido"
    }


@router_admin_models.put("/global/{model_id}/toggle")
async def toggle_global_model(
    model_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Ativa/desativa um modelo global
    """
    verify_admin(current_user)
    
    model = db.query(GlobalModel).filter(GlobalModel.id == model_id).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo global não encontrado"
        )
    
    model.is_active = not model.is_active
    db.commit()
    
    return {
        "success": True,
        "model_id": model_id,
        "is_active": model.is_active,
        "message": f"Modelo {'ativado' if model.is_active else 'desativado'}"
    }


# ========== Rotas de Visão Geral ==========

@router_admin_models.get("/user/{user_id}/models")
async def get_user_models(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista todos os modelos de um usuário (próprios e compartilhados)
    """
    verify_admin(current_user)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Modelos próprios
    own_models = db.query(UserAIModel).filter(
        UserAIModel.user_id == user_id
    ).all()
    
    # Modelos compartilhados com o usuário
    shared_access = db.query(SharedModelAccess).filter(
        SharedModelAccess.user_id == user_id,
        SharedModelAccess.is_active == True
    ).all()
    
    shared_models = []
    for access in shared_access:
        model = db.query(UserAIModel).filter(UserAIModel.id == access.model_id).first()
        owner = db.query(User).filter(User.id == model.user_id).first() if model else None
        shared_models.append({
            "model_id": access.model_id,
            "model_name": model.model_name if model else "Desconhecido",
            "owner_id": model.user_id if model else None,
            "owner_name": owner.user if owner else "Desconhecido",
            "access_level": access.access_level,
            "expires_at": access.expires_at
        })
    
    # Modelos globais acessíveis
    global_models = db.query(GlobalModel).filter(
        GlobalModel.is_active == True,
        GlobalModel.is_public == True
    ).all()
    
    return {
        "user_id": user_id,
        "username": user.user,
        "own_models": [
            {
                "id": m.id,
                "model_name": m.model_name,
                "model_type": m.model_type,
                "is_trained": m.is_trained,
                "is_active": m.is_active,
                "created_at": m.created_at
            }
            for m in own_models
        ],
        "shared_models": shared_models,
        "global_models": [
            {
                "id": m.id,
                "model_name": m.model_name,
                "model_type": m.model_type
            }
            for m in global_models
        ]
    }


@router_admin_models.get("/summary")
async def models_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Resumo geral de modelos no sistema
    """
    verify_admin(current_user)
    
    total_users = db.query(User).count()
    total_models = db.query(UserAIModel).count()
    total_shared = db.query(SharedModelAccess).filter(SharedModelAccess.is_active == True).count()
    total_global = db.query(GlobalModel).filter(GlobalModel.is_active == True).count()
    trained_models = db.query(UserAIModel).filter(UserAIModel.is_trained == True).count()
    
    # Top usuários com mais modelos
    users_models = db.query(User).all()
    user_summaries = []
    for u in users_models[:10]:  # Top 10
        own = db.query(UserAIModel).filter(UserAIModel.user_id == u.id).count()
        shared_with = db.query(SharedModelAccess).filter(
            SharedModelAccess.user_id == u.id,
            SharedModelAccess.is_active == True
        ).count()
        shared_by = db.query(SharedModelAccess).filter(
            SharedModelAccess.granted_by == u.id,
            SharedModelAccess.is_active == True
        ).count()
        
        if own > 0 or shared_with > 0:
            user_summaries.append({
                "user_id": u.id,
                "username": u.user,
                "own_models": own,
                "shared_with_user": shared_with,
                "shared_by_user": shared_by
            })
    
    return {
        "total_users": total_users,
        "total_models": total_models,
        "trained_models": trained_models,
        "total_shared_access": total_shared,
        "total_global_models": total_global,
        "user_summaries": sorted(user_summaries, key=lambda x: x["own_models"], reverse=True)
    }


@router_admin_models.post("/user/{user_id}/create-default")
async def create_default_model_for_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cria modelo padrão para um usuário que não tem (usuários antigos)
    """
    verify_admin(current_user)
    
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário não encontrado"
        )
    
    # Verificar se já tem modelo
    existing = db.query(UserAIModel).filter(UserAIModel.user_id == user_id).first()
    if existing:
        return {
            "success": False,
            "message": f"Usuário já possui {db.query(UserAIModel).filter(UserAIModel.user_id == user_id).count()} modelo(s)",
            "existing_model_id": existing.id
        }
    
    # Criar modelo padrão
    from Modelos.auth import create_default_user_model
    default_model = create_default_user_model(user_id, user.user, db)
    
    if default_model:
        return {
            "success": True,
            "message": f"Modelo padrão criado para {user.user}",
            "model_id": default_model.id,
            "model_name": default_model.model_name
        }
    else:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Erro ao criar modelo padrão"
        )


@router_admin_models.post("/init-selene")
async def initialize_selene_models(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Inicializa modelos Selene como modelos globais
    Registra Luna e mml como disponíveis para todos
    """
    verify_admin(current_user)
    
    selene_models = [
        {
            "model_name": "Luna",
            "model_type": "selene",
            "description": "Modelo conversacional Selene Luna - Assistente geral inteligente",
            "model_path": "Modelos/Selene/models/Luna",
            "is_public": True
        },
        {
            "model_name": "mml",
            "model_type": "selene", 
            "description": "Modelo Selene MML - Multi-Modal Learning",
            "model_path": "Modelos/Selene/models/mml",
            "is_public": True
        }
    ]
    
    created = []
    skipped = []
    
    for model_data in selene_models:
        existing = db.query(GlobalModel).filter(
            GlobalModel.model_name == model_data["model_name"]
        ).first()
        
        if existing:
            skipped.append(model_data["model_name"])
            continue
        
        new_model = GlobalModel(
            model_name=model_data["model_name"],
            model_type=model_data["model_type"],
            description=model_data["description"],
            model_path=model_data["model_path"],
            is_public=model_data["is_public"],
            requires_approval=False,
            created_by=current_user.id,
            is_active=True
        )
        
        db.add(new_model)
        created.append(model_data["model_name"])
    
    db.commit()
    
    return {
        "success": True,
        "created": created,
        "skipped": skipped,
        "message": f"Modelos Selene inicializados: {len(created)} criados, {len(skipped)} já existiam"
    }
