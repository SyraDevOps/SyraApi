from sqlalchemy import Column, String, DateTime, Float, Integer, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from datetime import datetime
from DB.database import Base
import uuid

class LocationLive(Base):
    """Localizações em tempo real dos usuários"""
    __tablename__ = "locations_live"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Coordenadas geográficas
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    accuracy = Column(Float, nullable=True)  # Precisão em metros
    
    # Controle de tempo
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    expires_at = Column(DateTime, nullable=False, index=True)  # Quando expira o compartilhamento
    is_active = Column(Boolean, default=True, index=True)
    
    # Configurações de visibilidade
    visibility_radius = Column(Float, default=1000.0)  # Raio de visibilidade em metros (padrão 1km)
    is_public = Column(Boolean, default=True)  # Se pode ser visto por outros
    
    # Metadados
    device_info = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<LocationLive(user_id='{self.user_id}', lat={self.latitude}, lng={self.longitude})>"


class LocationHistory(Base):
    """Histórico de localizações (após expirar)"""
    __tablename__ = "locations_history"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    latitude = Column(Float, nullable=False)
    longitude = Column(Float, nullable=False)
    
    shared_at = Column(DateTime, nullable=False)
    expired_at = Column(DateTime, nullable=False)
    
    def __repr__(self):
        return f"<LocationHistory(user_id='{self.user_id}', date='{self.shared_at}')>"


class UserBond(Base):
    """Vínculos entre usuários"""
    __tablename__ = "user_bonds"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Usuários envolvidos
    user_id_1 = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    user_id_2 = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Status do vínculo
    status = Column(String, nullable=False, default="pending")  # pending, accepted, rejected, blocked
    
    # Quem iniciou o vínculo
    initiated_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    accepted_at = Column(DateTime, nullable=True)
    
    # Metadados
    bond_type = Column(String, nullable=True)  # friend, family, colleague, etc
    notes = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<UserBond(user1='{self.user_id_1}', user2='{self.user_id_2}', status='{self.status}')>"


class MeetingInvite(Base):
    """Convites para encontros entre usuários"""
    __tablename__ = "meeting_invites"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Quem envia e quem recebe
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Localização do encontro (opcional - pode ser a do remetente)
    meeting_latitude = Column(Float, nullable=True)
    meeting_longitude = Column(Float, nullable=True)
    meeting_place_name = Column(String, nullable=True)
    
    # Mensagem do convite
    message = Column(Text, nullable=True)
    
    # Status
    status = Column(String, default="pending")  # pending, accepted, rejected, expired, cancelled
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)  # Convite expira
    responded_at = Column(DateTime, nullable=True)
    
    # Permite que o receptor veja a localização do remetente
    share_sender_location = Column(Boolean, default=True)
    
    def __repr__(self):
        return f"<MeetingInvite(from='{self.sender_id}', to='{self.receiver_id}', status='{self.status}')>"
