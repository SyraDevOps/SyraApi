"""
Modelos para sistema de IA personalizado por usuário
Cada usuário pode ter múltiplos modelos treinados
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey, Float, JSON
from sqlalchemy.orm import relationship
from datetime import datetime
from DB.database import Base


class UserAIModel(Base):
    """Modelos de IA personalizados por usuário"""
    __tablename__ = "user_ai_models"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Metadados do modelo
    model_name = Column(String(255), nullable=False)
    model_type = Column(String(100), default="conversational")  # conversational, classifier, etc
    description = Column(Text, nullable=True)
    
    # Caminhos dos arquivos
    model_path = Column(String(500), nullable=False)  # Caminho do modelo treinado
    dataset_path = Column(String(500), nullable=True)  # Caminho do dataset
    
    # Configurações do modelo
    config = Column(JSON, nullable=True)  # Hiperparâmetros, configurações
    training_config = Column(JSON, nullable=True)  # Configurações de treinamento
    
    # Estatísticas
    total_conversations = Column(Integer, default=0)
    total_messages = Column(Integer, default=0)
    accuracy = Column(Float, nullable=True)
    last_trained_at = Column(DateTime, nullable=True)
    total_training_time = Column(Float, nullable=True)  # Tempo total de treinamento em segundos
    
    # Status
    is_active = Column(Boolean, default=True)
    is_trained = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = relationship("User", back_populates="ai_models")
    knowledge_base = relationship("AIKnowledgeBase", back_populates="model", cascade="all, delete-orphan")
    commands = relationship("AICommand", back_populates="model", cascade="all, delete-orphan")
    conversations = relationship("AIConversation", back_populates="model", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<UserAIModel(user_id={self.user_id}, name='{self.model_name}')>"


class AIKnowledgeBase(Base):
    """Base de conhecimento para cada modelo de IA"""
    __tablename__ = "ai_knowledge_base"
    
    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("user_ai_models.id"), nullable=False, index=True)
    
    # Conteúdo
    category = Column(String(100), nullable=True)  # categoria do conhecimento
    question = Column(Text, nullable=True)
    answer = Column(Text, nullable=False)
    context = Column(Text, nullable=True)
    
    # Metadados
    source = Column(String(255), nullable=True)  # CSV, manual, training, etc
    confidence = Column(Float, default=1.0)
    
    # Controle
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamento
    model = relationship("UserAIModel", back_populates="knowledge_base")
    
    def __repr__(self):
        return f"<AIKnowledge(model_id={self.model_id}, category='{self.category}')>"


class AICommand(Base):
    """Comandos de automação para modelos de IA"""
    __tablename__ = "ai_commands"
    
    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("user_ai_models.id"), nullable=False, index=True)
    
    # Definição do comando
    command_trigger = Column(String(255), nullable=False, index=True)  # Frase que ativa
    command_type = Column(String(100), nullable=False)  # route, function, script, file
    
    # Ação a ser executada
    target_route = Column(String(500), nullable=True)  # Rota da API a chamar
    target_function = Column(String(255), nullable=True)  # Função Python
    target_file = Column(String(500), nullable=True)  # Arquivo a executar
    parameters = Column(JSON, nullable=True)  # Parâmetros do comando
    
    # Metadados
    description = Column(Text, nullable=True)
    response_template = Column(Text, nullable=True)  # Template de resposta após execução
    
    # Controle
    is_active = Column(Boolean, default=True)
    execution_count = Column(Integer, default=0)
    last_executed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamento
    model = relationship("UserAIModel", back_populates="commands")
    
    def __repr__(self):
        return f"<AICommand(trigger='{self.command_trigger}', type='{self.command_type}')>"


class AIConversation(Base):
    """Conversas com modelos de IA personalizados"""
    __tablename__ = "ai_conversations"
    
    id = Column(Integer, primary_key=True, index=True)
    model_id = Column(Integer, ForeignKey("user_ai_models.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Conteúdo
    user_message = Column(Text, nullable=False)
    ai_response = Column(Text, nullable=False)
    
    # Contexto
    context = Column(JSON, nullable=True)
    was_command = Column(Boolean, default=False)  # Se foi comando executado
    command_id = Column(Integer, ForeignKey("ai_commands.id"), nullable=True)
    
    # Metadados
    response_time = Column(Float, nullable=True)  # Tempo de resposta em segundos
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    
    # Relacionamentos
    model = relationship("UserAIModel", back_populates="conversations")
    user = relationship("User")
    
    def __repr__(self):
        return f"<AIConversation(model_id={self.model_id}, user_id={self.user_id})>"


class UserDataset(Base):
    """Datasets personalizados por usuário"""
    __tablename__ = "user_datasets"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Metadados
    dataset_name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(500), nullable=False)
    
    # Estatísticas
    total_rows = Column(Integer, default=0)
    columns = Column(JSON, nullable=True)  # Lista de colunas
    
    # Controle
    is_active = Column(Boolean, default=True)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamento
    user = relationship("User", back_populates="datasets")
    
    def __repr__(self):
        return f"<UserDataset(user_id={self.user_id}, name='{self.dataset_name}')>"


class SharedModelAccess(Base):
    """
    Controle de acesso a modelos compartilhados
    Permite que admin dê acesso a modelos de outros usuários ou modelos globais
    """
    __tablename__ = "shared_model_access"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Usuário que recebe acesso
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Modelo ao qual tem acesso
    model_id = Column(Integer, ForeignKey("user_ai_models.id"), nullable=False, index=True)
    
    # Tipo de acesso
    access_level = Column(String(50), default="read")  # read, write, train, full
    
    # Quem concedeu o acesso
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Controle
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)  # Acesso temporário
    granted_at = Column(DateTime, default=datetime.utcnow)
    
    # Relacionamentos
    user = relationship("User", foreign_keys=[user_id])
    model = relationship("UserAIModel")
    granter = relationship("User", foreign_keys=[granted_by])
    
    def __repr__(self):
        return f"<SharedModelAccess(user_id={self.user_id}, model_id={self.model_id}, level='{self.access_level}')>"


class GlobalModel(Base):
    """
    Modelos globais disponibilizados pelo admin para todos os usuários
    Referencia modelos Selene ou outros modelos pré-treinados
    """
    __tablename__ = "global_models"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Informações do modelo
    model_name = Column(String(255), nullable=False, unique=True)
    model_type = Column(String(100), default="selene")  # selene, custom, imported
    description = Column(Text, nullable=True)
    
    # Caminho do modelo (pode ser relativo a Modelos/Selene/models/)
    model_path = Column(String(500), nullable=False)
    
    # Configurações
    config = Column(JSON, nullable=True)
    
    # Controle de acesso
    is_public = Column(Boolean, default=True)  # Todos podem usar
    requires_approval = Column(Boolean, default=False)  # Admin precisa aprovar
    
    # Metadados
    created_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamento
    creator = relationship("User")
    
    def __repr__(self):
        return f"<GlobalModel(name='{self.model_name}', type='{self.model_type}')>"
