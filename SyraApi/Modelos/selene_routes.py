from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
import json

from DB.database import get_db
from Modelos.user import User
from Modelos.conversation import Conversation, Message
from Modelos.conversation_schemas import (
    ConversationCreate,
    ConversationResponse,
    ConversationWithMessages,
    MessageCreate,
    MessageResponse,
    ModelInteraction,
    ModelResponse
)
from Modelos.auth import get_current_user
from Tools.selene_integration import selene_manager

router = APIRouter(prefix="/selene", tags=["Selene Model"])

# ──────────────────────────────────────────────
# CRIAR NOVA CONVERSA COM SELENE
# ──────────────────────────────────────────────
@router.post("/conversation", response_model=ConversationResponse, status_code=status.HTTP_201_CREATED)
async def create_selene_conversation(
    conversation_data: ConversationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cria uma nova conversa com o modelo Selene
    
    - **title**: Título opcional para a conversa
    - **initial_message**: Mensagem inicial opcional
    """
    # Força o tipo do modelo para Selene
    conversation_data.model_type = "selene"
    
    # Cria nova conversa
    new_conversation = Conversation(
        user_id=current_user.id,
        model_type="selene",
        title=conversation_data.title
    )
    
    db.add(new_conversation)
    db.commit()
    db.refresh(new_conversation)
    
    # Se houver mensagem inicial, adiciona
    if conversation_data.initial_message:
        initial_msg = Message(
            conversation_id=new_conversation.id,
            sender_type="user",
            content=conversation_data.initial_message
        )
        db.add(initial_msg)
        db.commit()
    
    return ConversationResponse.from_orm(new_conversation)

# ──────────────────────────────────────────────
# ENVIAR MENSAGEM PARA SELENE E RECEBER RESPOSTA
# ──────────────────────────────────────────────
@router.post("/chat", response_model=ModelResponse)
async def chat_with_selene(
    interaction: ModelInteraction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Envia uma mensagem para Selene e recebe resposta
    
    - **conversation_id**: ID de conversa existente (opcional, cria nova se não fornecido)
    - **message**: Mensagem do usuário para o modelo
    - **title**: Título para nova conversa (se criar uma nova)
    """
    
    # Se não tem conversation_id, cria nova conversa
    if not interaction.conversation_id:
        new_conversation = Conversation(
            user_id=current_user.id,
            model_type="selene",
            title=interaction.title or f"Conversa Selene - {current_user.user}"
        )
        db.add(new_conversation)
        db.commit()
        db.refresh(new_conversation)
        conversation = new_conversation
    else:
        # Busca conversa existente
        conversation = db.query(Conversation).filter(
            Conversation.id == interaction.conversation_id,
            Conversation.user_id == current_user.id,
            Conversation.model_type == "selene"
        ).first()
        
        if not conversation:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Conversa não encontrada ou não pertence ao usuário"
            )
    
    # Salva mensagem do usuário
    user_message = Message(
        conversation_id=conversation.id,
        sender_type="user",
        content=interaction.message
    )
    db.add(user_message)
    db.commit()
    db.refresh(user_message)
    
    # ──────────────────────────────────────────────
    # INTEGRAÇÃO COM MODELO SELENE
    # Usa modelos treinados Luna/mml
    # ──────────────────────────────────────────────
    
    # Buscar contexto das últimas mensagens
    recent_messages = db.query(Message).filter(
        Message.conversation_id == conversation.id
    ).order_by(Message.created_at.desc()).limit(5).all()
    
    contexto = " ".join([msg.content[-50:] for msg in reversed(recent_messages) if msg.sender_type == "user"])
    
    # Tentar usar modelo Selene (Luna por padrão)
    try:
        available_models = selene_manager.list_available_models()
        if available_models:
            # Usar primeiro modelo disponível (geralmente Luna)
            model_name = available_models[0]["name"]
            model_response_content = selene_manager.predict_with_model(
                model_name, 
                interaction.message, 
                contexto
            )
        else:
            model_response_content = f"[SELENE] Nenhum modelo treinado disponível. Mensagem recebida: {interaction.message[:100]}"
    except Exception as e:
        model_response_content = f"[SELENE] Erro ao processar: {str(e)[:100]}"
    
    # Salva resposta do modelo
    model_message = Message(
        conversation_id=conversation.id,
        sender_type="model",
        content=model_response_content,
        metadata_json=json.dumps({"model": "selene", "version": "1.0"})
    )
    db.add(model_message)
    db.commit()
    db.refresh(model_message)
    
    return ModelResponse(
        conversation_id=conversation.id,
        user_message=MessageResponse.from_orm(user_message),
        model_message=MessageResponse.from_orm(model_message),
        conversation=ConversationResponse.from_orm(conversation)
    )

# ──────────────────────────────────────────────
# LISTAR CONVERSAS COM SELENE
# ──────────────────────────────────────────────
@router.get("/conversations", response_model=List[ConversationResponse])
async def list_selene_conversations(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = 50
):
    """
    Lista todas as conversas do usuário com Selene
    """
    conversations = db.query(Conversation).filter(
        Conversation.user_id == current_user.id,
        Conversation.model_type == "selene"
    ).order_by(Conversation.updated_at.desc()).limit(limit).all()
    
    return [ConversationResponse.from_orm(conv) for conv in conversations]

# ──────────────────────────────────────────────
# OBTER CONVERSA ESPECÍFICA COM MENSAGENS
# ──────────────────────────────────────────────
@router.get("/conversation/{conversation_id}", response_model=ConversationWithMessages)
async def get_selene_conversation(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Obtém uma conversa específica com todas as mensagens
    """
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.user_id == current_user.id,
        Conversation.model_type == "selene"
    ).first()
    
    if not conversation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversa não encontrada"
        )
    
    return ConversationWithMessages.from_orm(conversation)

# ──────────────────────────────────────────────
# DELETAR CONVERSA
# ──────────────────────────────────────────────
@router.delete("/conversation/{conversation_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_selene_conversation(
    conversation_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deleta uma conversa e todas as suas mensagens
    """
    conversation = db.query(Conversation).filter(
        Conversation.id == conversation_id,
        Conversation.user_id == current_user.id,
        Conversation.model_type == "selene"
    ).first()
    
    if not conversation:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Conversa não encontrada"
        )
    
    db.delete(conversation)
    db.commit()
    
    return None
