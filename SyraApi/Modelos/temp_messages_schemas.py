"""
Schemas Pydantic para mensagens temporárias
"""
from pydantic import BaseModel, Field, validator
from typing import Optional
from datetime import datetime, timedelta


class TempMessageCreate(BaseModel):
    """Schema para criar mensagem temporária"""
    receiver_id: int = Field(..., description="ID do destinatário")
    subject: Optional[str] = Field(None, max_length=255, description="Assunto da mensagem")
    content: str = Field(..., min_length=1, description="Conteúdo da mensagem")
    expires_in_hours: int = Field(24, ge=1, le=168, description="Expira em quantas horas (1-168h)")


class TempMessageResponse(BaseModel):
    """Schema de resposta de mensagem temporária"""
    id: int
    sender_id: int
    receiver_id: int
    subject: Optional[str]
    content: str
    created_at: datetime
    expires_at: datetime
    is_read: bool
    read_at: Optional[datetime]
    is_expired: bool = False
    
    class Config:
        from_attributes = True


class TempMessageListResponse(BaseModel):
    """Schema para lista de mensagens"""
    id: int
    sender_id: int
    receiver_id: int
    subject: Optional[str]
    content_preview: str = Field(..., description="Primeiros 100 caracteres")
    created_at: datetime
    expires_at: datetime
    is_read: bool
    is_expired: bool = False
    
    class Config:
        from_attributes = True
