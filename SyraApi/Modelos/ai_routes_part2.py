"""
Rotas para gerenciamento de modelos de IA personalizados
Parte 2: Conhecimento, Comandos e Conversação
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Dict, Any
import time
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.ai_models import UserAIModel, AIKnowledgeBase, AICommand, AIConversation
from Modelos.ai_schemas import (
    KnowledgeCreate,
    KnowledgeBulkCreate,
    KnowledgeResponse,
    CommandCreate,
    CommandResponse,
    AIMessageSend,
    AIMessageResponse,
    TrainingConfig,
    TrainingResponse
)
from Modelos.auth import get_current_user
from Tools.ai_manager import ai_manager


# ========== Knowledge Base ==========

router_knowledge = APIRouter(prefix="/ai/models/{model_id}/knowledge", tags=["AI - Base de Conhecimento"])


@router_knowledge.post("/", response_model=KnowledgeResponse, status_code=status.HTTP_201_CREATED)
async def add_knowledge(
    model_id: int,
    knowledge_data: KnowledgeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Adiciona conhecimento ao modelo de IA
    """
    # Verificar se modelo existe e pertence ao usuário
    model = db.query(UserAIModel).filter(
        UserAIModel.id == model_id,
        UserAIModel.user_id == current_user.id
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado"
        )
    
    # Adicionar ao banco SQL
    new_knowledge = AIKnowledgeBase(
        model_id=model_id,
        category=knowledge_data.category,
        question=knowledge_data.question,
        answer=knowledge_data.answer,
        context=knowledge_data.context,
        source=knowledge_data.source or "manual",
        confidence=knowledge_data.confidence
    )
    
    db.add(new_knowledge)
    
    # Adicionar também ao banco SQLite local do modelo
    knowledge_db = ai_manager.get_knowledge_db_path(current_user.id, model_id)
    ai_manager.add_knowledge(str(knowledge_db), [{
        "category": knowledge_data.category,
        "question": knowledge_data.question,
        "answer": knowledge_data.answer,
        "context": knowledge_data.context,
        "source": knowledge_data.source or "manual",
        "confidence": knowledge_data.confidence
    }])
    
    db.commit()
    db.refresh(new_knowledge)
    
    return new_knowledge


@router_knowledge.post("/bulk", status_code=status.HTTP_201_CREATED)
async def add_bulk_knowledge(
    model_id: int,
    knowledge_bulk: KnowledgeBulkCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Adiciona múltiplos conhecimentos de uma vez
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
    
    added_count = 0
    knowledge_items = []
    
    for item in knowledge_bulk.items:
        # Adicionar ao banco SQL
        new_knowledge = AIKnowledgeBase(
            model_id=model_id,
            category=item.category,
            question=item.question,
            answer=item.answer,
            context=item.context,
            source=item.source or "bulk_import",
            confidence=item.confidence
        )
        db.add(new_knowledge)
        
        # Preparar para SQLite
        knowledge_items.append({
            "category": item.category,
            "question": item.question,
            "answer": item.answer,
            "context": item.context,
            "source": item.source or "bulk_import",
            "confidence": item.confidence
        })
        added_count += 1
    
    # Adicionar ao SQLite
    knowledge_db = ai_manager.get_knowledge_db_path(current_user.id, model_id)
    ai_manager.add_knowledge(str(knowledge_db), knowledge_items)
    
    db.commit()
    
    return {
        "message": "Conhecimentos adicionados com sucesso",
        "added_count": added_count
    }


@router_knowledge.get("/", response_model=List[KnowledgeResponse])
async def list_knowledge(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    category: str = None,
    limit: int = 100
):
    """
    Lista conhecimentos do modelo
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
    
    query = db.query(AIKnowledgeBase).filter(
        AIKnowledgeBase.model_id == model_id,
        AIKnowledgeBase.is_active == True
    )
    
    if category:
        query = query.filter(AIKnowledgeBase.category == category)
    
    knowledge = query.order_by(AIKnowledgeBase.created_at.desc()).limit(limit).all()
    return knowledge


@router_knowledge.delete("/{knowledge_id}")
async def delete_knowledge(
    model_id: int,
    knowledge_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta conhecimento específico
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
    
    knowledge = db.query(AIKnowledgeBase).filter(
        AIKnowledgeBase.id == knowledge_id,
        AIKnowledgeBase.model_id == model_id
    ).first()
    
    if not knowledge:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conhecimento não encontrado"
        )
    
    db.delete(knowledge)
    db.commit()
    
    return {"message": "Conhecimento deletado"}


@router_knowledge.delete("/")
async def clear_all_knowledge(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Limpa TODA a base de conhecimento do modelo
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
    
    deleted_count = db.query(AIKnowledgeBase).filter(
        AIKnowledgeBase.model_id == model_id
    ).delete()
    
    # Recriar banco SQLite vazio
    knowledge_db = ai_manager.get_knowledge_db_path(current_user.id, model_id)
    ai_manager.create_knowledge_db(str(knowledge_db))
    
    db.commit()
    
    return {
        "message": "Base de conhecimento limpa",
        "deleted_count": deleted_count
    }


# ========== Commands ==========

router_commands = APIRouter(prefix="/ai/models/{model_id}/commands", tags=["AI - Comandos"])


@router_commands.post("/", response_model=CommandResponse, status_code=status.HTTP_201_CREATED)
async def create_command(
    model_id: int,
    command_data: CommandCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Cria comando de automação para o modelo
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
    
    # Criar comando
    new_command = AICommand(
        model_id=model_id,
        command_trigger=command_data.command_trigger,
        command_type=command_data.command_type,
        target_route=command_data.target_route,
        target_function=command_data.target_function,
        target_file=command_data.target_file,
        parameters=command_data.parameters,
        description=command_data.description,
        response_template=command_data.response_template
    )
    
    db.add(new_command)
    db.commit()
    db.refresh(new_command)
    
    return new_command


@router_commands.get("/", response_model=List[CommandResponse])
async def list_commands(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lista comandos do modelo
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
    
    commands = db.query(AICommand).filter(
        AICommand.model_id == model_id,
        AICommand.is_active == True
    ).order_by(AICommand.created_at.desc()).all()
    
    return commands


@router_commands.delete("/{command_id}")
async def delete_command(
    model_id: int,
    command_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta comando
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
    
    command = db.query(AICommand).filter(
        AICommand.id == command_id,
        AICommand.model_id == model_id
    ).first()
    
    if not command:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Comando não encontrado"
        )
    
    db.delete(command)
    db.commit()
    
    return {"message": "Comando deletado"}


# ========== Conversation ==========

router_chat = APIRouter(prefix="/ai/models/{model_id}/chat", tags=["AI - Conversação"])


@router_chat.post("/", response_model=AIMessageResponse)
async def chat_with_ai(
    model_id: int,
    message_data: AIMessageSend,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Conversa com modelo de IA personalizado
    Suporta execução de comandos automáticos
    """
    start_time = time.time()
    
    # Verificar modelo
    model = db.query(UserAIModel).filter(
        UserAIModel.id == model_id,
        UserAIModel.user_id == current_user.id,
        UserAIModel.is_active == True
    ).first()
    
    if not model:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Modelo não encontrado ou inativo"
        )
    
    # Verificar se é comando
    commands_db = ai_manager.get_commands_db_path(current_user.id, model_id)
    command_match = ai_manager.find_command(str(commands_db), message_data.message)
    
    was_command = False
    command_result = None
    
    if command_match:
        was_command = True
        # Executar comando (implementação simplificada)
        command_result = {
            "command_type": command_match['command_type'],
            "target": command_match.get('target_route') or command_match.get('target_function'),
            "status": "executed"
        }
        
        if command_match['response_template']:
            response_text = command_match['response_template']
        else:
            response_text = f"Comando '{command_match['trigger']}' executado com sucesso!"
    else:
        # Buscar na base de conhecimento
        knowledge_db = ai_manager.get_knowledge_db_path(current_user.id, model_id)
        knowledge_results = ai_manager.search_knowledge(str(knowledge_db), message_data.message)
        
        # Verificar se deve usar Selene
        use_selene = False
        selene_model_name = None
        
        # Checar se modelo tem configuração de Selene
        if model.config and isinstance(model.config, dict):
            use_selene = model.config.get('use_selene', False)
            selene_model_name = model.config.get('selene_model', 'Luna')
        
        # Pegar contexto das últimas mensagens
        last_conversations = db.query(AIConversation).filter(
            AIConversation.model_id == model_id,
            AIConversation.user_id == current_user.id
        ).order_by(AIConversation.created_at.desc()).limit(3).all()
        
        contexto = " ".join([conv.user_message[-30:] for conv in reversed(last_conversations)])
        
        # Gerar resposta (com suporte a modelo treinado e Selene)
        response_text = ai_manager.generate_response(
            message_data.message,
            knowledge_results,
            model_name=selene_model_name if use_selene else None,
            use_selene=use_selene,
            contexto=contexto,
            user_id=current_user.id,
            model_id=model_id
        )
    
    response_time = time.time() - start_time
    
    # Salvar conversação
    conversation = AIConversation(
        model_id=model_id,
        user_id=current_user.id,
        user_message=message_data.message,
        ai_response=response_text,
        context=message_data.context,
        was_command=was_command,
        response_time=response_time
    )
    
    db.add(conversation)
    
    # Atualizar estatísticas do modelo
    model.total_conversations += 1
    model.total_messages += 1
    
    db.commit()
    db.refresh(conversation)
    
    return AIMessageResponse(
        response=response_text,
        was_command=was_command,
        command_executed=command_match['trigger'] if command_match else None,
        command_result=command_result,
        response_time=response_time,
        conversation_id=conversation.id
    )


@router_chat.get("/history")
async def get_chat_history(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    limit: int = 50
):
    """
    Obtém histórico de conversas com o modelo
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
    
    conversations = db.query(AIConversation).filter(
        AIConversation.model_id == model_id,
        AIConversation.user_id == current_user.id
    ).order_by(AIConversation.created_at.desc()).limit(limit).all()
    
    return [
        {
            "id": conv.id,
            "user_message": conv.user_message,
            "ai_response": conv.ai_response,
            "was_command": conv.was_command,
            "response_time": conv.response_time,
            "created_at": conv.created_at
        }
        for conv in conversations
    ]


@router_chat.delete("/history")
async def clear_chat_history(
    model_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Limpa histórico de conversas do modelo
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
    
    deleted_count = db.query(AIConversation).filter(
        AIConversation.model_id == model_id,
        AIConversation.user_id == current_user.id
    ).delete()
    
    db.commit()
    
    return {
        "message": "Histórico limpo",
        "deleted_count": deleted_count
    }
