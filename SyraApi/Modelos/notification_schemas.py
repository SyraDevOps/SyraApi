from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# ──────────────────────────────────────────────
# Schemas para Criar Notificações
# ──────────────────────────────────────────────
class NotificationCreate(BaseModel):
    """Schema para criar notificação específica para um usuário"""
    user_id: str = Field(..., description="ID do usuário destinatário")
    title: str = Field(..., min_length=1, max_length=200, description="Título da notificação")
    message: str = Field(..., min_length=1, max_length=5000, description="Mensagem da notificação")
    priority: Optional[str] = Field("normal", description="Prioridade: low, normal, high, urgent")
    category: Optional[str] = Field(None, description="Categoria da notificação")
    metadata: Optional[dict] = Field(None, description="Metadados adicionais")

class GlobalNotificationCreate(BaseModel):
    """Schema para criar notificação global para todos os usuários"""
    title: str = Field(..., min_length=1, max_length=200, description="Título da notificação")
    message: str = Field(..., min_length=1, max_length=5000, description="Mensagem da notificação")
    priority: Optional[str] = Field("normal", description="Prioridade: low, normal, high, urgent")
    category: Optional[str] = Field(None, description="Categoria da notificação")
    metadata: Optional[dict] = Field(None, description="Metadados adicionais")

class SystemNotificationCreate(BaseModel):
    """Schema para notificação do sistema"""
    title: str = Field(..., min_length=1, max_length=200, description="Título da notificação")
    message: str = Field(..., min_length=1, max_length=5000, description="Mensagem da notificação")
    priority: Optional[str] = Field("normal", description="Prioridade: low, normal, high, urgent")
    category: Optional[str] = Field(None, description="Categoria da notificação")

# ──────────────────────────────────────────────
# Schemas para Resposta de Notificações
# ──────────────────────────────────────────────
class NotificationResponse(BaseModel):
    """Schema para resposta de notificação"""
    id: str
    notification_type: str
    user_id: Optional[str]
    title: str
    message: str
    priority: str
    category: Optional[str]
    is_read: bool
    read_at: Optional[datetime]
    created_at: datetime
    created_by: Optional[str]
    metadata_json: Optional[str]
    
    class Config:
        from_attributes = True

class NotificationSummary(BaseModel):
    """Schema para resumo de notificações do usuário"""
    total: int
    unread: int
    by_priority: dict
    by_category: dict

class BulkNotificationResult(BaseModel):
    """Schema para resultado de criação em massa"""
    created_count: int
    notification_ids: List[str]
    message: str
