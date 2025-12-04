from sqlalchemy import Column, String, DateTime, Boolean, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
import uuid
from DB.database import Base

class User(Base):
    __tablename__ = "users"
    
    # Campos principais
    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user = Column(String, unique=True, nullable=False, index=True)  # Username
    hash_unico = Column(String, unique=True, nullable=False, index=True)  # Hash único do usuário
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)  # Hash da senha principal
    senha_seguranca_hash = Column(String, nullable=False)  # Hash da senha de segurança
    telefone = Column(String, nullable=False)
    foto_perfil = Column(String, nullable=True)  # Caminho da foto (opcional)
    
    # Campos de controle
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Diretório pessoal do usuário
    user_directory = Column(String, nullable=False)  # Caminho para pasta do usuário
    
    # Relacionamentos com UserNode (node_{username})
    keypairs = relationship("X25519KeyPair", back_populates="user", cascade="all, delete-orphan")
    qrcodes = relationship("QRCode", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    nodes = relationship("NodeRegistry", back_populates="user", cascade="all, delete-orphan")
    apis = relationship("APIRegistry", back_populates="user", cascade="all, delete-orphan")
    
    # Relacionamentos com Sistema de IA
    ai_models = relationship("UserAIModel", back_populates="user", cascade="all, delete-orphan")
    datasets = relationship("UserDataset", back_populates="user", cascade="all, delete-orphan")
    temp_messages_sent = relationship("TemporaryMessage", foreign_keys="[TemporaryMessage.sender_id]", back_populates="sender", cascade="all, delete-orphan")
    temp_messages_received = relationship("TemporaryMessage", foreign_keys="[TemporaryMessage.receiver_id]", back_populates="receiver", cascade="all, delete-orphan")
    ai_conversations = relationship("AIConversation", back_populates="user", cascade="all, delete-orphan")
    
    # Relacionamentos com Sistema Social
    compromissos = relationship("Compromisso", back_populates="user", cascade="all, delete-orphan")
    files = relationship("UserFile", back_populates="user", cascade="all, delete-orphan")
    notes = relationship("UserNote", back_populates="user", cascade="all, delete-orphan")
    posts = relationship("Post", back_populates="user", cascade="all, delete-orphan")
    
    def __repr__(self):
        return f"<User(user='{self.user}', email='{self.email}')>"
