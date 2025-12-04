"""
Rotas para treinamento de modelos de IA
Parte 3: Treinamento e Integração com Selene
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import torch
import torch.nn as nn
from pathlib import Path
import json
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.ai_models import UserAIModel, UserDataset
from Modelos.ai_schemas import TrainingConfig, TrainingResponse
from Modelos.auth import get_current_user
from Tools.ai_manager import ai_manager
from Tools.selene_integration import selene_manager


router_training = APIRouter(prefix="/ai/models/{model_id}/training", tags=["AI - Treinamento"])


# ========== Training Tasks ==========

training_tasks: Dict[str, Dict[str, Any]] = {}


def train_model_background(
    task_id: str,
    model_id: int,
    user_id: int,
    config: TrainingConfig,
    db_session: Session
):
    """
    Executa treinamento em background usando TF-IDF + SimpleModel (mesmo método do Selene)
    """
    import time
    import pickle
    from sklearn.feature_extraction.text import TfidfVectorizer
    from torch.utils.data import Dataset, DataLoader
    
    start_time = time.time()
    
    # Dataset para TF-IDF
    class TextDataset(Dataset):
        def __init__(self, X, y):
            self.X = X.tocsr()
            self.y = y
        def __len__(self):
            return self.X.shape[0]
        def __getitem__(self, idx):
            x_sample = torch.tensor(self.X[idx].toarray().squeeze(), dtype=torch.float32)
            return x_sample, self.y[idx]
    
    # Modelo simples (compatível com Selene)
    class SimpleModel(nn.Module):
        def __init__(self, input_dim, output_dim):
            super().__init__()
            self.linear = nn.Linear(input_dim, output_dim)
        def forward(self, x):
            return self.linear(x)
    
    try:
        training_tasks[task_id]["status"] = "running"
        training_tasks[task_id]["progress"] = 0
        
        # Buscar modelo
        model = db_session.query(UserAIModel).filter(
            UserAIModel.id == model_id,
            UserAIModel.user_id == user_id
        ).first()
        
        if not model:
            training_tasks[task_id]["status"] = "error"
            training_tasks[task_id]["error"] = "Modelo não encontrado"
            return
        
        # Carregar dados da base de conhecimento
        knowledge_db = ai_manager.get_knowledge_db_path(user_id, model_id)
        training_data = ai_manager.search_knowledge(str(knowledge_db), "", limit=10000)
        
        if not training_data:
            training_tasks[task_id]["status"] = "warning"
            training_tasks[task_id]["message"] = "Nenhum conhecimento para treinar. Adicione conhecimento ao modelo primeiro."
            training_tasks[task_id]["progress"] = 100
            return
        
        training_tasks[task_id]["progress"] = 10
        training_tasks[task_id]["message"] = f"Preparando {len(training_data)} itens de conhecimento"
        
        # Preparar dados para TF-IDF (mesmo formato do Selene)
        perguntas = []
        respostas = []
        for item in training_data:
            pergunta = item.get('question', '') or ''
            contexto = item.get('context', '') or ''
            resposta = item.get('answer', '')
            perguntas.append(f"{pergunta} {contexto}".strip())
            respostas.append(resposta)
        
        training_tasks[task_id]["progress"] = 20
        training_tasks[task_id]["message"] = "Vetorizando dados com TF-IDF..."
        
        # Vetorização TF-IDF
        vectorizer = TfidfVectorizer()
        X = vectorizer.fit_transform(perguntas)
        
        # Preparar labels
        respostas_set = sorted(list(set(respostas)))
        resposta2idx = {resp: idx for idx, resp in enumerate(respostas_set)}
        idx2resposta = {idx: resp for resp, idx in resposta2idx.items()}
        y = torch.tensor([resposta2idx[r] for r in respostas], dtype=torch.long)
        
        training_tasks[task_id]["progress"] = 30
        training_tasks[task_id]["message"] = f"Treinando modelo ({len(respostas_set)} respostas únicas)..."
        
        # Dataset e DataLoader
        dataset = TextDataset(X, y)
        data_loader = DataLoader(dataset, batch_size=config.batch_size, shuffle=True)
        
        # Criar modelo (compatível com Selene)
        ai_model = SimpleModel(X.shape[1], len(respostas_set))
        
        # Verificar se existe modelo anterior para continuar treinamento
        model_path = ai_manager.get_model_path(user_id, model_id)
        vectorizer_path = model_path.parent / "vectorizer.pkl"
        
        # Configurar treinamento
        criterion = nn.CrossEntropyLoss()
        optimizer = torch.optim.Adam(ai_model.parameters(), lr=config.learning_rate)
        
        # Loop de treinamento REAL
        ai_model.train()
        total_epochs = config.epochs
        final_loss = 0
        
        for epoch in range(total_epochs):
            total_loss = 0
            batch_count = 0
            
            for batch_X, batch_y in data_loader:
                optimizer.zero_grad()
                outputs = ai_model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()
                total_loss += loss.item()
                batch_count += 1
            
            avg_loss = total_loss / max(batch_count, 1)
            final_loss = avg_loss
            
            # Atualizar progresso
            progress = 30 + int(((epoch + 1) / total_epochs) * 60)
            training_tasks[task_id]["progress"] = progress
            training_tasks[task_id]["epoch"] = epoch + 1
            training_tasks[task_id]["loss"] = round(avg_loss, 4)
            training_tasks[task_id]["message"] = f"Época {epoch+1}/{total_epochs} - Loss: {avg_loss:.4f}"
        
        training_tasks[task_id]["progress"] = 95
        training_tasks[task_id]["message"] = "Salvando modelo e vetorizador..."
        
        # Calcular tempo total
        elapsed_time = time.time() - start_time
        
        # Salvar modelo treinado (.pt)
        torch.save(ai_model.state_dict(), model_path)
        
        # Salvar vetorizador e mapeamentos (.pkl) - mesmo formato do Selene
        with open(vectorizer_path, "wb") as f:
            pickle.dump((vectorizer, resposta2idx, idx2resposta), f)
        
        # Atualizar modelo no banco
        model.is_trained = True
        model.training_config = config.dict()
        model.total_training_time = elapsed_time
        model.last_trained_at = datetime.utcnow()
        
        db_session.commit()
        
        training_tasks[task_id]["status"] = "completed"
        training_tasks[task_id]["progress"] = 100
        training_tasks[task_id]["message"] = f"Treinamento concluído em {elapsed_time:.2f}s"
        training_tasks[task_id]["elapsed_time"] = elapsed_time
        
    except Exception as e:
        training_tasks[task_id]["status"] = "error"
        training_tasks[task_id]["error"] = str(e)
        training_tasks[task_id]["progress"] = 0


@router_training.post("/start", response_model=TrainingResponse)
async def start_training(
    model_id: int,
    config: TrainingConfig,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Inicia treinamento do modelo em background
    """
    # Verificar modelo
    model = db.query(UserAIModel).filter(
        UserAIModel.id == model_id,
        UserAIModel.user_id == current_user.id,
        UserAIModel.is_active == True
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado"
        )
    
    # Verificar se já está treinando
    active_tasks = [t for t in training_tasks.values() if t.get("model_id") == model_id and t.get("status") == "running"]
    if active_tasks:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Modelo já está em treinamento"
        )
    
    # Criar task ID
    import uuid
    task_id = str(uuid.uuid4())
    
    training_tasks[task_id] = {
        "model_id": model_id,
        "user_id": current_user.id,
        "status": "pending",
        "progress": 0,
        "created_at": datetime.now()
    }
    
    # Adicionar task ao background
    background_tasks.add_task(
        train_model_background,
        task_id,
        model_id,
        current_user.id,
        config,
        db
    )
    
    return TrainingResponse(
        task_id=task_id,
        status="pending",
        message="Treinamento iniciado em background",
        progress=0
    )


@router_training.get("/status/{task_id}", response_model=TrainingResponse)
async def get_training_status(
    model_id: int,
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Verifica status do treinamento
    """
    if task_id not in training_tasks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task de treinamento não encontrada"
        )
    
    task = training_tasks[task_id]
    
    # Verificar se task pertence ao usuário
    if task["user_id"] != current_user.id or task["model_id"] != model_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado"
        )
    
    return TrainingResponse(
        task_id=task_id,
        status=task["status"],
        message=task.get("message", ""),
        progress=task.get("progress", 0),
        current_epoch=task.get("epoch"),
        current_loss=task.get("loss"),
        error=task.get("error")
    )


@router_training.post("/stop/{task_id}")
async def stop_training(
    model_id: int,
    task_id: str,
    current_user: User = Depends(get_current_user)
):
    """
    Para treinamento em andamento
    """
    if task_id not in training_tasks:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Task de treinamento não encontrada"
        )
    
    task = training_tasks[task_id]
    
    if task["user_id"] != current_user.id or task["model_id"] != model_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acesso negado"
        )
    
    if task["status"] != "running":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Treinamento não está em execução"
        )
    
    # Marcar para parar (implementação simplificada)
    task["status"] = "stopped"
    task["message"] = "Treinamento interrompido pelo usuário"
    
    return {
        "message": "Treinamento interrompido",
        "task_id": task_id
    }


@router_training.get("/history")
async def get_training_history(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Histórico de treinamentos do modelo
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
    
    # Buscar tasks do modelo
    model_tasks = [
        {
            "task_id": task_id,
            "status": task["status"],
            "progress": task.get("progress", 0),
            "created_at": task.get("created_at"),
            "error": task.get("error")
        }
        for task_id, task in training_tasks.items()
        if task["model_id"] == model_id and task["user_id"] == current_user.id
    ]
    
    return {
        "model_id": model_id,
        "model_name": model.model_name,
        "is_trained": model.is_trained,
        "total_training_time": model.total_training_time,
        "training_config": model.training_config,
        "training_history": model_tasks
    }


# ========== Selene Integration ==========

router_selene = APIRouter(prefix="/ai/selene", tags=["AI - Selene"])


@router_selene.get("/status")
async def get_selene_status():
    """
    Verifica status da integração com Selene
    """
    try:
        available_models = selene_manager.list_available_models()
        
        return {
            "available": len(available_models) > 0,
            "path": str(selene_manager.models_path),
            "models": available_models,
            "message": f"{len(available_models)} modelo(s) Selene disponível(is)",
            "loaded_models": list(selene_manager.loaded_models.keys())
        }
    except Exception as e:
        return {
            "available": False,
            "error": str(e),
            "message": "Erro ao verificar modelos Selene"
        }


@router_selene.post("/load-to-model/{model_id}")
async def load_selene_to_model(
    model_id: int,
    selene_model_name: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Configura modelo de usuário para usar Selene pré-treinado
    """
    # Verificar modelo do usuário
    model = db.query(UserAIModel).filter(
        UserAIModel.id == model_id,
        UserAIModel.user_id == current_user.id
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado"
        )
    
    # Verificar se modelo Selene existe
    selene_model = selene_manager.load_model(selene_model_name)
    if not selene_model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Modelo Selene '{selene_model_name}' não encontrado"
        )
    
    # Obter informações do modelo Selene
    selene_info = selene_model.get_model_info()
    
    # Atualizar configuração do modelo para usar Selene
    if not model.config:
        model.config = {}
    
    model.config['use_selene'] = True
    model.config['selene_model'] = selene_model_name
    model.config['selene_info'] = selene_info
    model.is_trained = True
    model.training_config = {
        "source": "selene",
        "model": selene_model_name,
        "integrated_at": datetime.now().isoformat()
    }
    
    db.commit()
    
    return {
        "message": f"Modelo '{model.model_name}' configurado para usar Selene '{selene_model_name}'",
        "model_id": model_id,
        "selene_model": selene_model_name,
        "selene_info": selene_info
    }


@router_selene.post("/test-chat")
async def test_selene_chat(
    model_name: str,
    message: str,
    contexto: str = ""
):
    """
    Testa conversa direta com modelo Selene
    Endpoint público para testar modelos sem autenticação
    """
    try:
        response = selene_manager.predict_with_model(model_name, message, contexto)
        
        return {
            "model": model_name,
            "message": message,
            "response": response,
            "contexto": contexto
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao processar mensagem: {str(e)}"
        )


@router_selene.get("/model-info/{model_name}")
async def get_selene_model_info(model_name: str):
    """
    Obtém informações detalhadas de um modelo Selene específico
    """
    info = selene_manager.get_model_info(model_name)
    
    if "error" in info:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=info["error"]
        )
    
    return info
