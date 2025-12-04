"""
Rotas para gerenciamento de modelos de IA personalizados
Parte 1: CRUD de modelos e configurações
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from sqlalchemy.orm import Session
from typing import List, Optional, Tuple
from datetime import datetime
import shutil
import os

from DB.database import get_db
from Modelos.user import User
from Modelos.ai_models import UserAIModel, UserDataset, SharedModelAccess, GlobalModel
from Modelos.ai_schemas import (
    AIModelCreate,
    AIModelUpdate,
    AIModelResponse,
    DatasetCreate,
    DatasetResponse
)
from Modelos.auth import get_current_user
from Tools.ai_manager import ai_manager


router_ai_models = APIRouter(prefix="/ai/models", tags=["AI - Modelos"])


def check_model_access(
    user_id: int, 
    model_id: int, 
    db: Session,
    required_level: str = "read"
) -> Tuple[UserAIModel, str]:
    """
    Verifica se usuário tem acesso ao modelo
    Retorna tupla (modelo, nível_de_acesso) ou levanta HTTPException
    
    Níveis: read < write < train < full
    """
    level_hierarchy = {"read": 1, "write": 2, "train": 3, "full": 4}
    required_level_num = level_hierarchy.get(required_level, 1)
    
    # Verificar se é dono do modelo
    model = db.query(UserAIModel).filter(UserAIModel.id == model_id).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado"
        )
    
    # Dono tem acesso total
    if model.user_id == user_id:
        return model, "owner"
    
    # Verificar acesso compartilhado
    shared_access = db.query(SharedModelAccess).filter(
        SharedModelAccess.user_id == user_id,
        SharedModelAccess.model_id == model_id,
        SharedModelAccess.is_active == True
    ).first()
    
    if shared_access:
        # Verificar expiração
        if shared_access.expires_at and shared_access.expires_at < datetime.utcnow():
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Seu acesso a este modelo expirou"
            )
        
        # Verificar nível de acesso
        access_level_num = level_hierarchy.get(shared_access.access_level, 0)
        if access_level_num >= required_level_num:
            return model, shared_access.access_level
        else:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Você precisa de acesso '{required_level}' ou superior. Seu acesso é '{shared_access.access_level}'"
            )
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Você não tem acesso a este modelo"
    )


@router_ai_models.post("/", response_model=AIModelResponse, status_code=status.HTTP_201_CREATED)
async def create_ai_model(
    model_data: AIModelCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cria novo modelo de IA personalizado para o usuário
    """
    # Verificar se já existe modelo com esse nome
    existing = db.query(UserAIModel).filter(
        UserAIModel.user_id == current_user.id,
        UserAIModel.model_name == model_data.model_name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Você já tem um modelo com o nome '{model_data.model_name}'"
        )
    
    # Criar modelo
    new_model = UserAIModel(
        user_id=current_user.id,
        model_name=model_data.model_name,
        model_type=model_data.model_type,
        description=model_data.description,
        config=model_data.config,
        model_path=""  # Será definido após criar diretórios
    )
    
    db.add(new_model)
    db.commit()
    db.refresh(new_model)
    
    # Criar estrutura de diretórios e bancos
    model_dir = ai_manager.get_user_model_dir(current_user.id, new_model.id)
    new_model.model_path = str(model_dir / "model.pt")
    
    # Criar bancos de conhecimento e comandos
    knowledge_db = ai_manager.get_knowledge_db_path(current_user.id, new_model.id)
    commands_db = ai_manager.get_commands_db_path(current_user.id, new_model.id)
    
    ai_manager.create_knowledge_db(str(knowledge_db))
    ai_manager.create_commands_db(str(commands_db))
    
    db.commit()
    db.refresh(new_model)
    
    return new_model


@router_ai_models.get("/", response_model=List[AIModelResponse])
async def list_my_ai_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    active_only: bool = True,
    include_shared: bool = True
):
    """
    Lista todos os modelos de IA do usuário (próprios e compartilhados)
    """
    # Modelos próprios
    query = db.query(UserAIModel).filter(UserAIModel.user_id == current_user.id)
    
    if active_only:
        query = query.filter(UserAIModel.is_active == True)
    
    own_models = query.order_by(UserAIModel.created_at.desc()).all()
    
    # Adicionar modelos compartilhados se solicitado
    if include_shared:
        shared_accesses = db.query(SharedModelAccess).filter(
            SharedModelAccess.user_id == current_user.id,
            SharedModelAccess.is_active == True
        ).all()
        
        shared_model_ids = [sa.model_id for sa in shared_accesses]
        
        if shared_model_ids:
            shared_query = db.query(UserAIModel).filter(
                UserAIModel.id.in_(shared_model_ids)
            )
            if active_only:
                shared_query = shared_query.filter(UserAIModel.is_active == True)
            
            shared_models = shared_query.all()
            own_models.extend(shared_models)
    
    return own_models


@router_ai_models.get("/shared/list")
async def list_shared_models_with_me(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lista apenas modelos compartilhados com o usuário (não seus próprios)
    """
    shared_accesses = db.query(SharedModelAccess).filter(
        SharedModelAccess.user_id == current_user.id,
        SharedModelAccess.is_active == True
    ).all()
    
    result = []
    for access in shared_accesses:
        # Verificar expiração
        if access.expires_at and access.expires_at < datetime.utcnow():
            continue
        
        model = db.query(UserAIModel).filter(UserAIModel.id == access.model_id).first()
        if model and model.is_active:
            owner = db.query(User).filter(User.id == model.user_id).first()
            result.append({
                "model_id": model.id,
                "model_name": model.model_name,
                "model_type": model.model_type,
                "description": model.description,
                "is_trained": model.is_trained,
                "owner_id": model.user_id,
                "owner_name": owner.user if owner else "Desconhecido",
                "access_level": access.access_level,
                "expires_at": access.expires_at,
                "granted_at": access.granted_at
            })
    
    return {
        "total": len(result),
        "shared_models": result
    }


@router_ai_models.get("/global/available")
async def list_available_global_models(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lista modelos globais disponíveis para uso
    """
    global_models = db.query(GlobalModel).filter(
        GlobalModel.is_active == True,
        GlobalModel.is_public == True
    ).all()
    
    return {
        "total": len(global_models),
        "global_models": [
            {
                "id": m.id,
                "model_name": m.model_name,
                "model_type": m.model_type,
                "description": m.description,
                "model_path": m.model_path
            }
            for m in global_models
        ]
    }


@router_ai_models.get("/{model_id}", response_model=AIModelResponse)
async def get_ai_model(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de um modelo específico (próprio ou compartilhado)
    """
    # Usa a função de verificação de acesso
    model, access_level = check_model_access(current_user.id, model_id, db, "read")
    
    return model


@router_ai_models.get("/{model_id}/access")
async def get_my_access_level(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retorna o nível de acesso do usuário ao modelo
    """
    model, access_level = check_model_access(current_user.id, model_id, db, "read")
    
    return {
        "model_id": model_id,
        "model_name": model.model_name,
        "access_level": access_level,
        "is_owner": access_level == "owner"
    }
        )
    
    return model


@router_ai_models.patch("/{model_id}", response_model=AIModelResponse)
async def update_ai_model(
    model_id: int,
    model_update: AIModelUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza configurações do modelo
    """
    model = db.query(UserAIModel).filter(
        UserAIModel.id == model_id,
        UserAIModel.user_id == current_user.id
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado"
        )
    
    # Atualizar campos
    update_data = model_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(model, field, value)
    
    model.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(model)
    
    return model


@router_ai_models.delete("/{model_id}")
async def delete_ai_model(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta modelo e todos os dados associados
    """
    model = db.query(UserAIModel).filter(
        UserAIModel.id == model_id,
        UserAIModel.user_id == current_user.id
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado"
        )
    
    # Deletar diretório do modelo
    model_dir = ai_manager.get_user_model_dir(current_user.id, model_id)
    if model_dir.exists():
        shutil.rmtree(model_dir)
    
    model_name = model.model_name
    db.delete(model)
    db.commit()
    
    return {"message": "Modelo deletado com sucesso", "model_name": model_name}


# ========== Datasets ==========

router_datasets = APIRouter(prefix="/ai/datasets", tags=["AI - Datasets"])


@router_datasets.post("/upload", response_model=DatasetResponse, status_code=status.HTTP_201_CREATED)
async def upload_dataset(
    file: UploadFile = File(...),
    dataset_name: str = None,
    description: str = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Faz upload de dataset CSV e converte para SQLite
    """
    # Validar extensão
    if not file.filename.endswith('.csv'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Apenas arquivos CSV são suportados"
        )
    
    # Nome do dataset
    if not dataset_name:
        dataset_name = file.filename.replace('.csv', '')
    
    # Verificar se já existe
    existing = db.query(UserDataset).filter(
        UserDataset.user_id == current_user.id,
        UserDataset.dataset_name == dataset_name
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Dataset '{dataset_name}' já existe"
        )
    
    # Salvar arquivo CSV temporariamente
    dataset_dir = ai_manager.get_user_dataset_dir(current_user.id)
    csv_path = dataset_dir / file.filename
    
    with open(csv_path, 'wb') as f:
        shutil.copyfileobj(file.file, f)
    
    # Converter para SQLite
    db_path = dataset_dir / f"{dataset_name}.db"
    conversion_result = ai_manager.csv_to_sqlite(str(csv_path), str(db_path), "data")
    
    if not conversion_result['success']:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao converter CSV: {conversion_result['error']}"
        )
    
    # Criar registro
    new_dataset = UserDataset(
        user_id=current_user.id,
        dataset_name=dataset_name,
        description=description,
        file_path=str(db_path),
        total_rows=conversion_result['total_rows'],
        columns=conversion_result['columns']
    )
    
    db.add(new_dataset)
    db.commit()
    db.refresh(new_dataset)
    
    # Remover CSV original (mantém apenas SQLite)
    os.remove(csv_path)
    
    return new_dataset


@router_datasets.get("/", response_model=List[DatasetResponse])
async def list_my_datasets(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lista todos os datasets do usuário
    """
    datasets = db.query(UserDataset).filter(
        UserDataset.user_id == current_user.id,
        UserDataset.is_active == True
    ).order_by(UserDataset.uploaded_at.desc()).all()
    
    return datasets


@router_datasets.get("/{dataset_id}", response_model=DatasetResponse)
async def get_dataset(
    dataset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de um dataset
    """
    dataset = db.query(UserDataset).filter(
        UserDataset.id == dataset_id,
        UserDataset.user_id == current_user.id
    ).first()
    
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset não encontrado"
        )
    
    return dataset


@router_datasets.delete("/{dataset_id}")
async def delete_dataset(
    dataset_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta dataset
    """
    dataset = db.query(UserDataset).filter(
        UserDataset.id == dataset_id,
        UserDataset.user_id == current_user.id
    ).first()
    
    if not dataset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dataset não encontrado"
        )
    
    # Deletar arquivo
    if os.path.exists(dataset.file_path):
        os.remove(dataset.file_path)
    
    dataset_name = dataset.dataset_name
    db.delete(dataset)
    db.commit()
    
    return {"message": "Dataset deletado", "dataset_name": dataset_name}
