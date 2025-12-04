"""
Modelos para sistema de Drive, Notas e Feed Social
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text, BigInteger
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from DB.database import Base


class UserFile(Base):
    """Arquivos armazenados no drive do usuário"""
    __tablename__ = "user_files"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    filename = Column(String(255), nullable=False)
    original_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    
    file_size = Column(BigInteger, nullable=False)  # bytes
    mime_type = Column(String(100))
    
    uploaded_at = Column(DateTime, default=datetime.now)
    
    # Relacionamento
    user = relationship("User", back_populates="files")


class UserNote(Base):
    """Notas pessoais do usuário"""
    __tablename__ = "user_notes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    titulo = Column(String(200), nullable=False)
    conteudo = Column(Text, nullable=False)
    
    cor = Column(String(7), default="#FFEB3B")  # Cor da nota (hex)
    fixada = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relacionamento
    user = relationship("User", back_populates="notes")


class Post(Base):
    """Posts do feed social (expiram em 2 dias)"""
    __tablename__ = "posts"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    conteudo = Column(Text, nullable=False)
    hashtags = Column(String(500))  # Hashtags separadas por vírgula
    
    imagem_url = Column(String(500))  # URL opcional de imagem
    
    curtidas = Column(Integer, default=0)
    comentarios_count = Column(Integer, default=0)
    encaminhamentos = Column(Integer, default=0)
    
    created_at = Column(DateTime, default=datetime.now)
    expires_at = Column(DateTime, default=lambda: datetime.now() + timedelta(days=2))
    
    # Relacionamentos
    user = relationship("User", back_populates="posts")
    comentarios = relationship("Comentario", back_populates="post", cascade="all, delete-orphan")
    curtidas_users = relationship("PostLike", back_populates="post", cascade="all, delete-orphan")


class Comentario(Base):
    """Comentários em posts"""
    __tablename__ = "comentarios"
    
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    conteudo = Column(Text, nullable=False)
    
    created_at = Column(DateTime, default=datetime.now)
    
    # Relacionamentos
    post = relationship("Post", back_populates="comentarios")
    user = relationship("User")


class PostLike(Base):
    """Curtidas em posts (tabela de relacionamento)"""
    __tablename__ = "post_likes"
    
    id = Column(Integer, primary_key=True, index=True)
    post_id = Column(Integer, ForeignKey("posts.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    created_at = Column(DateTime, default=datetime.now)
    
    # Relacionamentos
    post = relationship("Post", back_populates="curtidas_users")
    user = relationship("User")
