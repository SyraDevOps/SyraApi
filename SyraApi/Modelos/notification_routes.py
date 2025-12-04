from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import func
from typing import List, Optional
from datetime import datetime
import json

from DB.database import get_db
from Modelos.user import User
from Modelos.notification import Notification
from Modelos.notification_schemas import (
    NotificationCreate,
    GlobalNotificationCreate,
    SystemNotificationCreate,
    NotificationResponse,
    NotificationSummary,
    BulkNotificationResult
)
from Modelos.auth import get_current_user

router = APIRouter(prefix="/notifications", tags=["Notificações"])

# ──────────────────────────────────────────────
# ADMIN: CRIAR NOTIFICAÇÃO GLOBAL
# ──────────────────────────────────────────────
@router.post("/global", response_model=BulkNotificationResult, status_code=status.HTTP_201_CREATED)
async def create_global_notification(
    notification_data: GlobalNotificationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [ADMIN] Cria uma notificação global para todos os usuários ativos
    
    - **title**: Título da notificação
    - **message**: Mensagem da notificação
    - **priority**: Prioridade (low, normal, high, urgent)
    - **category**: Categoria (update, maintenance, feature, alert, etc.)
    
    Exemplo: "Atualização sexta feita"
    """
    
    # Busca todos os usuários ativos
    active_users = db.query(User).filter(User.is_active == True).all()
    
    if not active_users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nenhum usuário ativo encontrado"
        )
    
    # Cria notificação para cada usuário
    notification_ids = []
    metadata_str = json.dumps(notification_data.metadata) if notification_data.metadata else None
    
    for user in active_users:
        notification = Notification(
            notification_type="global",
            user_id=user.id,
            title=notification_data.title,
            message=notification_data.message,
            priority=notification_data.priority or "normal",
            category=notification_data.category,
            created_by=current_user.id,
            metadata_json=metadata_str
        )
        db.add(notification)
        notification_ids.append(notification.id)
    
    db.commit()
    
    return BulkNotificationResult(
        created_count=len(notification_ids),
        notification_ids=notification_ids,
        message=f"Notificação global enviada para {len(notification_ids)} usuários"
    )

# ──────────────────────────────────────────────
# ADMIN: CRIAR NOTIFICAÇÃO ESPECÍFICA
# ──────────────────────────────────────────────
@router.post("/specific", response_model=NotificationResponse, status_code=status.HTTP_201_CREATED)
async def create_specific_notification(
    notification_data: NotificationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [ADMIN] Cria uma notificação específica para um usuário
    
    - **user_id**: ID do usuário destinatário
    - **title**: Título da notificação
    - **message**: Mensagem da notificação
    - **priority**: Prioridade (low, normal, high, urgent)
    - **category**: Categoria da notificação
    """
    
    # Verifica se o usuário destinatário existe
    target_user = db.query(User).filter(User.id == notification_data.user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Usuário destinatário não encontrado"
        )
    
    # Cria notificação
    metadata_str = json.dumps(notification_data.metadata) if notification_data.metadata else None
    
    notification = Notification(
        notification_type="user_specific",
        user_id=notification_data.user_id,
        title=notification_data.title,
        message=notification_data.message,
        priority=notification_data.priority or "normal",
        category=notification_data.category,
        created_by=current_user.id,
        metadata_json=metadata_str
    )
    
    db.add(notification)
    db.commit()
    db.refresh(notification)
    
    return NotificationResponse.from_orm(notification)

# ──────────────────────────────────────────────
# ADMIN: CRIAR NOTIFICAÇÃO DE SISTEMA
# ──────────────────────────────────────────────
@router.post("/system", response_model=BulkNotificationResult, status_code=status.HTTP_201_CREATED)
async def create_system_notification(
    notification_data: SystemNotificationCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    [ADMIN] Cria uma notificação de sistema para todos os usuários
    
    Diferente de notificação global, notificações de sistema são marcadas especialmente
    e podem ter tratamento diferenciado no frontend
    """
    
    # Busca todos os usuários ativos
    active_users = db.query(User).filter(User.is_active == True).all()
    
    if not active_users:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nenhum usuário ativo encontrado"
        )
    
    # Cria notificação de sistema para cada usuário
    notification_ids = []
    
    for user in active_users:
        notification = Notification(
            notification_type="system",
            user_id=user.id,
            title=notification_data.title,
            message=notification_data.message,
            priority=notification_data.priority or "normal",
            category=notification_data.category or "system",
            created_by=current_user.id
        )
        db.add(notification)
        notification_ids.append(notification.id)
    
    db.commit()
    
    return BulkNotificationResult(
        created_count=len(notification_ids),
        notification_ids=notification_ids,
        message=f"Notificação de sistema enviada para {len(notification_ids)} usuários"
    )

# ──────────────────────────────────────────────
# USUÁRIO: LISTAR MINHAS NOTIFICAÇÕES
# ──────────────────────────────────────────────
@router.get("/my", response_model=List[NotificationResponse])
async def get_my_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    unread_only: bool = Query(False, description="Mostrar apenas não lidas"),
    priority: Optional[str] = Query(None, description="Filtrar por prioridade"),
    category: Optional[str] = Query(None, description="Filtrar por categoria"),
    limit: int = Query(50, le=200, description="Limite de resultados")
):
    """
    Retorna todas as notificações do usuário autenticado
    
    - **unread_only**: Se True, retorna apenas notificações não lidas
    - **priority**: Filtrar por prioridade (low, normal, high, urgent)
    - **category**: Filtrar por categoria
    - **limit**: Máximo de notificações a retornar (padrão: 50, máx: 200)
    """
    
    query = db.query(Notification).filter(Notification.user_id == current_user.id)
    
    if unread_only:
        query = query.filter(Notification.is_read == False)
    
    if priority:
        query = query.filter(Notification.priority == priority)
    
    if category:
        query = query.filter(Notification.category == category)
    
    notifications = query.order_by(Notification.created_at.desc()).limit(limit).all()
    
    return [NotificationResponse.from_orm(n) for n in notifications]


# ──────────────────────────────────────────────
# USUÁRIO: CONTAGEM DE NOTIFICAÇÕES NÃO LIDAS
# ──────────────────────────────────────────────
@router.get("/unread-count")
async def get_unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna a quantidade de notificações não lidas do usuário
    """
    count = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).count()
    
    return {"unread_count": count}

# ──────────────────────────────────────────────
# USUÁRIO: RESUMO DE NOTIFICAÇÕES
# ──────────────────────────────────────────────
@router.get("/summary", response_model=NotificationSummary)
async def get_notification_summary(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Retorna um resumo das notificações do usuário
    """
    
    # Total de notificações
    total = db.query(Notification).filter(Notification.user_id == current_user.id).count()
    
    # Não lidas
    unread = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).count()
    
    # Por prioridade
    priority_counts = db.query(
        Notification.priority,
        func.count(Notification.id)
    ).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).group_by(Notification.priority).all()
    
    by_priority = {p: c for p, c in priority_counts}
    
    # Por categoria
    category_counts = db.query(
        Notification.category,
        func.count(Notification.id)
    ).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False,
        Notification.category.isnot(None)
    ).group_by(Notification.category).all()
    
    by_category = {c: count for c, count in category_counts if c}
    
    return NotificationSummary(
        total=total,
        unread=unread,
        by_priority=by_priority,
        by_category=by_category
    )

# ──────────────────────────────────────────────
# USUÁRIO: MARCAR NOTIFICAÇÃO COMO LIDA
# ──────────────────────────────────────────────
@router.patch("/{notification_id}/read", response_model=NotificationResponse)
async def mark_notification_as_read(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Marca uma notificação como lida
    
    A notificação será automaticamente deletada após ser marcada como lida
    """
    
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()
    
    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notificação não encontrada"
        )
    
    notification.is_read = True
    notification.read_at = datetime.utcnow()
    db.commit()
    db.refresh(notification)
    
    # Deleta a notificação após marcar como lida
    db.delete(notification)
    db.commit()
    
    return NotificationResponse.from_orm(notification)

# ──────────────────────────────────────────────
# USUÁRIO: MARCAR TODAS COMO LIDAS E DELETAR
# ──────────────────────────────────────────────
@router.post("/read-all", response_model=dict)
async def mark_all_as_read_and_delete(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Marca todas as notificações como lidas e as deleta
    """
    
    # Busca todas as notificações não lidas do usuário
    notifications = db.query(Notification).filter(
        Notification.user_id == current_user.id,
        Notification.is_read == False
    ).all()
    
    count = len(notifications)
    
    # Marca como lida e deleta
    for notification in notifications:
        notification.is_read = True
        notification.read_at = datetime.utcnow()
        db.delete(notification)
    
    db.commit()
    
    return {
        "message": f"{count} notificações marcadas como lidas e deletadas",
        "count": count
    }

# ──────────────────────────────────────────────
# USUÁRIO: DELETAR NOTIFICAÇÃO ESPECÍFICA
# ──────────────────────────────────────────────
@router.delete("/{notification_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_notification(
    notification_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deleta uma notificação específica
    """
    
    notification = db.query(Notification).filter(
        Notification.id == notification_id,
        Notification.user_id == current_user.id
    ).first()
    
    if not notification:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Notificação não encontrada"
        )
    
    db.delete(notification)
    db.commit()
    
    return None

# ──────────────────────────────────────────────
# ADMIN: LIMPAR NOTIFICAÇÕES ANTIGAS LIDAS
# ──────────────────────────────────────────────
@router.post("/cleanup", response_model=dict)
async def cleanup_old_notifications(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    days_old: int = Query(7, description="Deletar notificações lidas com mais de X dias")
):
    """
    [ADMIN] Remove notificações lidas antigas do sistema
    """
    from datetime import timedelta
    
    cutoff_date = datetime.utcnow() - timedelta(days=days_old)
    
    # Deleta notificações lidas antigas
    deleted = db.query(Notification).filter(
        Notification.is_read == True,
        Notification.read_at < cutoff_date
    ).delete()
    
    db.commit()
    
    return {
        "message": f"{deleted} notificações antigas removidas",
        "deleted_count": deleted,
        "cutoff_date": cutoff_date.isoformat()
    }
