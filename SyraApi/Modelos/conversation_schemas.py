from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

# ──────────────────────────────────────────────
# Schemas para Mensagens
# ──────────────────────────────────────────────
class MessageCreate(BaseModel):
    """Schema para criar uma nova mensagem"""
    content: str = Field(..., min_length=1, max_length=50000, description="Conteúdo da mensagem")
    metadata: Optional[dict] = Field(None, description="Metadados adicionais (opcional)")

class MessageResponse(BaseModel):
    """Schema para resposta de mensagem"""
    id: str
    conversation_id: str
    sender_type: str  # "user" ou "model"
    content: str
    created_at: datetime
    metadata_json: Optional[str]
    
    class Config:
        from_attributes = True

# ──────────────────────────────────────────────
# Schemas para Conversas
# ──────────────────────────────────────────────
class ConversationCreate(BaseModel):
    """Schema para criar uma nova conversa"""
    model_type: str = Field(..., description="Tipo do modelo: 'selene' ou 'luna'")
    title: Optional[str] = Field(None, max_length=200, description="Título da conversa (opcional)")
    initial_message: Optional[str] = Field(None, description="Mensagem inicial (opcional)")

class ConversationResponse(BaseModel):
    """Schema para resposta de conversa"""
    id: str
    user_id: str
    model_type: str
    title: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ConversationWithMessages(ConversationResponse):
    """Schema para conversa com mensagens"""
    messages: List[MessageResponse] = []
    
    class Config:
        from_attributes = True

# ──────────────────────────────────────────────
# Schema para interação com modelo
# ──────────────────────────────────────────────
class ModelInteraction(BaseModel):
    """Schema para enviar mensagem e receber resposta do modelo"""
    conversation_id: Optional[str] = Field(None, description="ID da conversa existente (opcional)")
    message: str = Field(..., min_length=1, max_length=50000, description="Mensagem do usuário")
    title: Optional[str] = Field(None, max_length=200, description="Título da nova conversa (se não existir)")

class ModelResponse(BaseModel):
    """Schema para resposta do modelo"""
    conversation_id: str
    user_message: MessageResponse
    model_message: MessageResponse
    conversation: ConversationResponse
