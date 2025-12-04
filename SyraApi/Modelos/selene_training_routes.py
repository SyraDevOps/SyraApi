"""
Rotas para criação e treinamento de modelos Selene customizados
Permite criar, treinar e gerenciar modelos próprios
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import csv
import io

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Tools.selene_trainer import selene_trainer


router_selene_train = APIRouter(prefix="/ai/selene/train", tags=["Selene - Treinamento"])


# ========== Schemas ==========

class ModelCreateRequest(BaseModel):
    """Schema para criar novo modelo"""
    model_name: str = Field(..., min_length=1, max_length=50, description="Nome do modelo")


class TrainingDataItem(BaseModel):
    """Item de dado de treinamento"""
    pergunta: str = Field(..., min_length=1, description="Pergunta")
    resposta: str = Field(..., min_length=1, description="Resposta")
    contexto: str = Field("", description="Contexto opcional")


class AddTrainingDataRequest(BaseModel):
    """Schema para adicionar dados de treinamento"""
    data: List[TrainingDataItem] = Field(..., min_items=1, description="Lista de dados")


class TrainModelRequest(BaseModel):
    """Schema para treinar modelo"""
    epochs: int = Field(10, ge=1, le=100, description="Número de épocas")
    batch_size: int = Field(16, ge=1, le=128, description="Tamanho do batch")
    learning_rate: float = Field(0.01, gt=0, le=1, description="Taxa de aprendizado")
    continue_training: bool = Field(False, description="Continuar treinamento existente")


class RemoveDataRequest(BaseModel):
    """Schema para remover dados de treinamento"""
    ids: Optional[List[int]] = Field(None, description="IDs específicos a remover")
    condition: Optional[str] = Field(None, description="Condição SQL (ex: \"pergunta LIKE '%teste%'\")")


# ========== Rotas ==========

@router_selene_train.post("/create-model")
async def create_selene_model(
    request: ModelCreateRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Cria um novo modelo Selene customizado
    """
    result = selene_trainer.create_model(request.model_name)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    
    return result


@router_selene_train.post("/{model_name}/add-data")
async def add_training_data(
    model_name: str,
    request: AddTrainingDataRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Adiciona dados de treinamento ao modelo
    """
    # Converter Pydantic models para dicts
    data = [item.dict() for item in request.data]
    
    result = selene_trainer.add_training_data(model_name, data)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    
    return result


@router_selene_train.post("/{model_name}/upload-csv")
async def upload_training_csv(
    model_name: str,
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user)
):
    """
    Faz upload de CSV com dados de treinamento
    Formato esperado: pergunta,resposta,contexto
    """
    # Verificar se é CSV
    if not file.filename.endswith('.csv'):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Arquivo deve ser CSV"
        )
    
    try:
        # Ler CSV
        contents = await file.read()
        csv_string = contents.decode('utf-8')
        csv_reader = csv.DictReader(io.StringIO(csv_string))
        
        # Converter para formato esperado
        data = []
        for row in csv_reader:
            data.append({
                "pergunta": row.get('pergunta', ''),
                "resposta": row.get('resposta', ''),
                "contexto": row.get('contexto', '')
            })
        
        if not data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="CSV vazio ou formato inválido"
            )
        
        # Adicionar ao modelo
        result = selene_trainer.add_training_data(model_name, data)
        
        if not result["success"]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=result["error"]
            )
        
        result["filename"] = file.filename
        result["total_rows"] = len(data)
        
        return result
        
    except UnicodeDecodeError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Erro ao decodificar arquivo. Certifique-se que está em UTF-8"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar CSV: {str(e)}"
        )


@router_selene_train.post("/{model_name}/train")
async def train_selene_model(
    model_name: str,
    request: TrainModelRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user)
):
    """
    Inicia treinamento do modelo Selene
    O treinamento acontece em background
    """
    # Verificar se modelo existe
    stats = selene_trainer.get_model_stats(model_name)
    
    if not stats["success"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=stats["error"]
        )
    
    if stats["total_samples"] == 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Modelo não possui dados de treinamento. Adicione dados primeiro."
        )
    
    # Iniciar treinamento
    result = selene_trainer.train_model(
        model_name=model_name,
        epochs=request.epochs,
        batch_size=request.batch_size,
        learning_rate=request.learning_rate,
        continue_training=request.continue_training
    )
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"]
        )
    
    return result


@router_selene_train.get("/{model_name}/stats")
async def get_model_statistics(
    model_name: str,
    current_user: User = Depends(get_current_user)
):
    """
    Obtém estatísticas do modelo
    """
    result = selene_trainer.get_model_stats(model_name)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"]
        )
    
    return result


@router_selene_train.delete("/{model_name}")
async def delete_selene_model(
    model_name: str,
    current_user: User = Depends(get_current_user)
):
    """
    Deleta um modelo Selene completamente
    """
    result = selene_trainer.delete_model(model_name)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"]
        )
    
    return result


@router_selene_train.get("/{model_name}/data")
async def get_training_data(
    model_name: str,
    limit: int = 100,
    offset: int = 0,
    current_user: User = Depends(get_current_user)
):
    """
    Obtém dados de treinamento paginados
    """
    result = selene_trainer.get_training_data(model_name, limit, offset)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"]
        )
    
    return result


@router_selene_train.post("/{model_name}/remove-data")
async def remove_training_data(
    model_name: str,
    request: RemoveDataRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Remove dados específicos de treinamento
    Pode remover por IDs ou por condição SQL
    """
    result = selene_trainer.remove_training_data(
        model_name=model_name,
        ids=request.ids,
        condition=request.condition
    )
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["error"]
        )
    
    return result


@router_selene_train.get("/{model_name}/export-csv")
async def export_training_csv(
    model_name: str,
    current_user: User = Depends(get_current_user)
):
    """
    Exporta dados de treinamento para CSV
    """
    result = selene_trainer.export_training_data_csv(model_name)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result["error"]
        )
    
    return result


@router_selene_train.get("/{model_name}/training-history")
async def get_training_history(
    model_name: str,
    current_user: User = Depends(get_current_user)
):
    """
    Obtém histórico completo de treinamento (todos os losses e métricas)
    """
    result = selene_trainer.get_training_history(model_name)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"]
        )
    
    return result


@router_selene_train.get("/list-custom")
async def list_custom_models(current_user: User = Depends(get_current_user)):
    """
    Lista todos os modelos customizados criados
    """
    from pathlib import Path
    
    models_path = Path("/root/SyraApi/Modelos/Selene/models")
    custom_models = []
    
    if models_path.exists():
        for model_dir in models_path.iterdir():
            if model_dir.is_dir():
                stats = selene_trainer.get_model_stats(model_dir.name)
                if stats["success"]:
                    custom_models.append(stats)
    
    return {
        "total": len(custom_models),
        "models": custom_models
    }
