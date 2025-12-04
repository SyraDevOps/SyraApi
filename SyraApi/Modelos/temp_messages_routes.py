"""
Rotas para mensagens temporárias entre usuários
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List
from datetime import datetime, timedelta

from DB.database import get_db
from Modelos.user import User
from Modelos.temp_messages import TemporaryMessage
from Modelos.temp_messages_schemas import (
    TempMessageCreate,
    TempMessageResponse,
    TempMessageListResponse
)
from Modelos.auth import get_current_user


router = APIRouter(prefix="/temp-messages", tags=["Mensagens Temporárias"])


@router.post("/send", response_model=TempMessageResponse, status_code=status.HTTP_201_CREATED)
async def send_temp_message(
    message_data: TempMessageCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Envia mensagem temporária para outro usuário
    Mensagem expira automaticamente após o tempo especificado
    """
    # Verificar se destinatário existe
    receiver = db.query(User).filter(User.id == message_data.receiver_id).first()
    if not receiver:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Destinatário não encontrado"
        )
    
    # Não pode enviar para si mesmo
    if receiver.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Não é possível enviar mensagem para si mesmo"
        )
    
    # Calcular data de expiração
    expires_at = datetime.utcnow() + timedelta(hours=message_data.expires_in_hours)
    
    # Criar mensagem
    new_message = TemporaryMessage(
        sender_id=current_user.id,
        receiver_id=message_data.receiver_id,
        subject=message_data.subject,
        content=message_data.content,
        expires_at=expires_at
    )
    
    db.add(new_message)
    db.commit()
    db.refresh(new_message)
    
    # Adicionar campo is_expired dinamicamente
    response = TempMessageResponse.from_orm(new_message)
    response.is_expired = new_message.is_expired()
    
    return response


@router.get("/inbox", response_model=List[TempMessageListResponse])
async def get_inbox(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    include_expired: bool = False
):
    """
    Lista mensagens recebidas (inbox)
    Por padrão, exclui mensagens expiradas
    """
    query = db.query(TemporaryMessage).filter(
        TemporaryMessage.receiver_id == current_user.id,
        TemporaryMessage.is_deleted_by_receiver == False
    )
    
    messages = query.order_by(TemporaryMessage.created_at.desc()).all()
    
    # Filtrar expiradas se necessário
    result = []
    for msg in messages:
        if not include_expired and msg.is_expired():
            continue
        
        response = TempMessageListResponse(
            id=msg.id,
            sender_id=msg.sender_id,
            receiver_id=msg.receiver_id,
            subject=msg.subject,
            content_preview=msg.content[:100] + "..." if len(msg.content) > 100 else msg.content,
            created_at=msg.created_at,
            expires_at=msg.expires_at,
            is_read=msg.is_read,
            is_expired=msg.is_expired()
        )
        result.append(response)
    
    return result


@router.get("/sent", response_model=List[TempMessageListResponse])
async def get_sent_messages(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    include_expired: bool = False
):
    """
    Lista mensagens enviadas
    """
    query = db.query(TemporaryMessage).filter(
        TemporaryMessage.sender_id == current_user.id,
        TemporaryMessage.is_deleted_by_sender == False
    )
    
    messages = query.order_by(TemporaryMessage.created_at.desc()).all()
    
    result = []
    for msg in messages:
        if not include_expired and msg.is_expired():
            continue
        
        response = TempMessageListResponse(
            id=msg.id,
            sender_id=msg.sender_id,
            receiver_id=msg.receiver_id,
            subject=msg.subject,
            content_preview=msg.content[:100] + "..." if len(msg.content) > 100 else msg.content,
            created_at=msg.created_at,
            expires_at=msg.expires_at,
            is_read=msg.is_read,
            is_expired=msg.is_expired()
        )
        result.append(response)
    
    return result


@router.get("/{message_id}", response_model=TempMessageResponse)
async def get_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes completos de uma mensagem
    Marca como lida se for o destinatário
    """
    message = db.query(TemporaryMessage).filter(
        TemporaryMessage.id == message_id
    ).first()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mensagem não encontrada"
        )
    
    # Verificar se usuário tem permissão
    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para ver esta mensagem"
        )
    
    # Marcar como lida se for o destinatário
    if message.receiver_id == current_user.id and not message.is_read:
        message.is_read = True
        message.read_at = datetime.utcnow()
        db.commit()
        db.refresh(message)
    
    response = TempMessageResponse.from_orm(message)
    response.is_expired = message.is_expired()
    
    return response


@router.delete("/{message_id}")
async def delete_message(
    message_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    'Deleta' mensagem (marca como deletada para o usuário)
    Mensagem só é deletada realmente quando ambos deletarem
    """
    message = db.query(TemporaryMessage).filter(
        TemporaryMessage.id == message_id
    ).first()
    
    if not message:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Mensagem não encontrada"
        )
    
    # Verificar permissão
    if message.sender_id != current_user.id and message.receiver_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para deletar esta mensagem"
        )
    
    # Marcar como deletada
    if message.sender_id == current_user.id:
        message.is_deleted_by_sender = True
    else:
        message.is_deleted_by_receiver = True
    
    # Se ambos deletaram, deletar permanentemente
    if message.is_deleted_by_sender and message.is_deleted_by_receiver:
        db.delete(message)
    
    db.commit()
    
    return {"message": "Mensagem deletada com sucesso"}


@router.post("/cleanup")
async def cleanup_expired_messages(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Remove mensagens expiradas do usuário
    (tanto recebidas quanto enviadas)
    """
    now = datetime.utcnow()
    
    deleted_count = db.query(TemporaryMessage).filter(
        or_(
            TemporaryMessage.sender_id == current_user.id,
            TemporaryMessage.receiver_id == current_user.id
        ),
        TemporaryMessage.expires_at < now
    ).delete()
    
    db.commit()
    
    return {
        "message": "Limpeza concluída",
        "deleted_count": deleted_count
    }


@router.get("/stats/summary")
async def get_message_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Estatísticas de mensagens do usuário
    """
    now = datetime.utcnow()
    
    # Recebidas
    total_received = db.query(TemporaryMessage).filter(
        TemporaryMessage.receiver_id == current_user.id,
        TemporaryMessage.is_deleted_by_receiver == False
    ).count()
    
    unread_received = db.query(TemporaryMessage).filter(
        TemporaryMessage.receiver_id == current_user.id,
        TemporaryMessage.is_read == False,
        TemporaryMessage.is_deleted_by_receiver == False,
        TemporaryMessage.expires_at > now
    ).count()
    
    # Enviadas
    total_sent = db.query(TemporaryMessage).filter(
        TemporaryMessage.sender_id == current_user.id,
        TemporaryMessage.is_deleted_by_sender == False
    ).count()
    
    return {
        "inbox": {
            "total": total_received,
            "unread": unread_received
        },
        "sent": {
            "total": total_sent
        }
    }
