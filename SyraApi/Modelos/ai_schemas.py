"""
Schemas Pydantic para sistema de IA
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any, List
from datetime import datetime


# ========== AI Model Schemas ==========

class AIModelCreate(BaseModel):
    """Schema para criar modelo de IA"""
    model_name: str = Field(..., min_length=1, max_length=255)
    model_type: str = Field(default="conversational", description="conversational, classifier, etc")
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = Field(None, description="Configurações do modelo")


class AIModelUpdate(BaseModel):
    """Schema para atualizar modelo"""
    model_name: Optional[str] = None
    description: Optional[str] = None
    config: Optional[Dict[str, Any]] = None
    is_active: Optional[bool] = None


class AIModelResponse(BaseModel):
    """Schema de resposta do modelo"""
    id: int
    user_id: int
    model_name: str
    model_type: str
    description: Optional[str]
    config: Optional[Dict[str, Any]]
    total_conversations: int
    total_messages: int
    accuracy: Optional[float]
    last_trained_at: Optional[datetime]
    is_active: bool
    is_trained: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ========== Knowledge Base Schemas ==========

class KnowledgeCreate(BaseModel):
    """Schema para adicionar conhecimento"""
    category: Optional[str] = Field(None, max_length=100)
    question: Optional[str] = None
    answer: str = Field(..., min_length=1)
    context: Optional[str] = None
    source: Optional[str] = Field(None, description="manual, csv, training, etc")
    confidence: float = Field(1.0, ge=0.0, le=1.0)


class KnowledgeBulkCreate(BaseModel):
    """Schema para adicionar múltiplos conhecimentos"""
    items: List[KnowledgeCreate] = Field(..., min_items=1)


class KnowledgeResponse(BaseModel):
    """Schema de resposta de conhecimento"""
    id: int
    model_id: int
    category: Optional[str]
    question: Optional[str]
    answer: str
    context: Optional[str]
    source: Optional[str]
    confidence: float
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# ========== Command Schemas ==========

class CommandCreate(BaseModel):
    """Schema para criar comando de automação"""
    command_trigger: str = Field(..., min_length=1, max_length=255, description="Frase que ativa comando")
    command_type: str = Field(..., description="route, function, script, file")
    target_route: Optional[str] = None
    target_function: Optional[str] = None
    target_file: Optional[str] = None
    parameters: Optional[Dict[str, Any]] = None
    description: Optional[str] = None
    response_template: Optional[str] = Field(None, description="Template de resposta")
    
    @validator('command_type')
    def validate_command_type(cls, v):
        allowed = ['route', 'function', 'script', 'file']
        if v not in allowed:
            raise ValueError(f"command_type deve ser um de: {', '.join(allowed)}")
        return v


class CommandResponse(BaseModel):
    """Schema de resposta de comando"""
    id: int
    model_id: int
    command_trigger: str
    command_type: str
    target_route: Optional[str]
    target_function: Optional[str]
    target_file: Optional[str]
    parameters: Optional[Dict[str, Any]]
    description: Optional[str]
    response_template: Optional[str]
    is_active: bool
    execution_count: int
    last_executed_at: Optional[datetime]
    created_at: datetime
    
    class Config:
        from_attributes = True


# ========== Conversation Schemas ==========

class AIMessageSend(BaseModel):
    """Schema para enviar mensagem para IA"""
    message: str = Field(..., min_length=1, description="Mensagem do usuário")
    context: Optional[Dict[str, Any]] = Field(None, description="Contexto adicional")


class AIMessageResponse(BaseModel):
    """Schema de resposta da IA"""
    response: str
    was_command: bool = False
    command_executed: Optional[str] = None
    command_result: Optional[Dict[str, Any]] = None
    response_time: float
    conversation_id: int


# ========== Dataset Schemas ==========

class DatasetCreate(BaseModel):
    """Schema para criar dataset"""
    dataset_name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None


class DatasetResponse(BaseModel):
    """Schema de resposta de dataset"""
    id: int
    user_id: int
    dataset_name: str
    description: Optional[str]
    file_path: str
    total_rows: int
    columns: Optional[List[str]]
    is_active: bool
    uploaded_at: datetime
    
    class Config:
        from_attributes = True


# ========== Training Schemas ==========

class TrainingConfig(BaseModel):
    """Schema para configuração de treinamento"""
    epochs: int = Field(10, ge=1, le=1000, description="Número de épocas")
    batch_size: int = Field(32, ge=1, le=512, description="Tamanho do batch")
    learning_rate: float = Field(0.001, ge=0.00001, le=1.0, description="Taxa de aprendizado")
    validation_split: float = Field(0.2, ge=0.0, le=0.5, description="% para validação")
    use_dataset_id: Optional[int] = Field(None, description="ID do dataset a usar")


class TrainingResponse(BaseModel):
    """Schema de resposta do início do treinamento (background task)"""
    task_id: str
    status: str
    message: str = ""
    progress: int = 0
    current_epoch: Optional[int] = None
    current_loss: Optional[float] = None
    error: Optional[str] = None


class TrainingCompletedResponse(BaseModel):
    """Schema de resposta do treinamento concluído"""
    status: str
    message: str
    model_id: int
    epochs_completed: int
    final_accuracy: Optional[float]
    training_time: float
    model_path: str
