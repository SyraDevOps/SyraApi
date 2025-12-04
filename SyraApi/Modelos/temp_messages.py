"""
Modelos para mensagens temporárias entre usuários
Mensagens com tempo de expiração automático
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from datetime import datetime, timedelta
from DB.database import Base


class TemporaryMessage(Base):
    """Mensagens temporárias entre usuários com auto-expiração"""
    __tablename__ = "temporary_messages"
    
    id = Column(Integer, primary_key=True, index=True)
    
    # Remetente e destinatário
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Conteúdo
    subject = Column(String(255), nullable=True)
    content = Column(Text, nullable=False)
    
    # Controle de expiração
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)
    
    # Status
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime, nullable=True)
    is_deleted_by_sender = Column(Boolean, default=False)
    is_deleted_by_receiver = Column(Boolean, default=False)
    
    # Relacionamentos
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])
    
    def is_expired(self):
        """Verifica se a mensagem está expirada"""
        return datetime.utcnow() > self.expires_at
    
    def __repr__(self):
        return f"<TempMessage(from={self.sender_id}, to={self.receiver_id}, expires={self.expires_at})>"
