from sqlalchemy import Column, String, DateTime, Boolean, Text, ForeignKey, Integer
from sqlalchemy.orm import relationship
from datetime import datetime
from DB.database import Base
import uuid

class Notification(Base):
    __tablename__ = "notifications"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Tipo de notificação
    notification_type = Column(String, nullable=False)  # "global", "user_specific", "system"
    
    # Destinatário (None para notificações globais)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # Conteúdo
    title = Column(String, nullable=False)
    message = Column(Text, nullable=False)
    
    # Prioridade e categoria
    priority = Column(String, default="normal")  # "low", "normal", "high", "urgent"
    category = Column(String, nullable=True)  # "update", "maintenance", "feature", "alert", etc.
    
    # Controle de visualização
    is_read = Column(Boolean, default=False)
    read_at = Column(DateTime, nullable=True)
    
    # Controle de criação e remetente
    created_at = Column(DateTime, default=datetime.utcnow)
    created_by = Column(String, nullable=True)  # ID do usuário que criou (admin)
    
    # Metadados adicionais
    metadata_json = Column(Text, nullable=True)  # JSON para dados extras
    
    def __repr__(self):
        return f"<Notification(id='{self.id}', type='{self.notification_type}', title='{self.title}')>"
