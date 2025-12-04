"""
Modelo de Agenda - Compromissos e eventos do usuário
"""
from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from DB.database import Base


class Compromisso(Base):
    """Modelo de compromissos na agenda do usuário"""
    __tablename__ = "compromissos"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    titulo = Column(String(200), nullable=False)
    descricao = Column(Text)
    
    data_hora = Column(DateTime, nullable=False)
    duracao_minutos = Column(Integer, default=60)
    
    local = Column(String(300))
    lembrete_minutos = Column(Integer, default=30)  # Notificar X minutos antes
    
    notificado = Column(Boolean, default=False)
    concluido = Column(Boolean, default=False)
    
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relacionamento
    user = relationship("User", back_populates="compromissos")
