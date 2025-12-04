from pydantic import BaseModel, Field, validator
from typing import Optional, List
from datetime import datetime

# ──────────────────────────────────────────────
# Schemas para Localização
# ──────────────────────────────────────────────
class LocationShare(BaseModel):
    """Schema para compartilhar localização"""
    latitude: float = Field(..., ge=-90, le=90, description="Latitude (-90 a 90)")
    longitude: float = Field(..., ge=-180, le=180, description="Longitude (-180 a 180)")
    accuracy: Optional[float] = Field(None, description="Precisão em metros")
    duration_minutes: int = Field(..., ge=1, le=1440, description="Duração do compartilhamento (1 min a 24h)")
    visibility_radius: Optional[float] = Field(1000.0, ge=100, le=50000, description="Raio de visibilidade em metros")
    is_public: Optional[bool] = Field(True, description="Visível para outros usuários")
    device_info: Optional[str] = Field(None, max_length=500)

class LocationUpdate(BaseModel):
    """Schema para atualizar localização"""
    latitude: float = Field(..., ge=-90, le=90)
    longitude: float = Field(..., ge=-180, le=180)
    accuracy: Optional[float] = None

class LocationResponse(BaseModel):
    """Schema para resposta de localização"""
    id: str
    user_id: int
    latitude: float
    longitude: float
    accuracy: Optional[float]
    created_at: datetime
    expires_at: datetime
    is_active: bool
    visibility_radius: float
    is_public: bool
    
    class Config:
        from_attributes = True

class NearbyUser(BaseModel):
    """Schema para usuário próximo"""
    user_id: int
    username: str
    distance_meters: float
    latitude: float
    longitude: float
    last_update: datetime

class NearbyUsersResponse(BaseModel):
    """Schema para resposta de usuários próximos"""
    nearby_users: List[NearbyUser]
    total_count: int
    search_radius: float

# ──────────────────────────────────────────────
# Schemas para Vínculos
# ──────────────────────────────────────────────
class BondRequest(BaseModel):
    """Schema para solicitar vínculo"""
    target_user_id: int = Field(..., description="ID do usuário para criar vínculo")
    bond_type: Optional[str] = Field("friend", description="Tipo de vínculo (friend, family, colleague)")
    notes: Optional[str] = Field(None, max_length=500, description="Notas sobre o vínculo")

class BondResponse(BaseModel):
    """Schema para resposta de vínculo"""
    id: str
    user_id_1: int
    user_id_2: int
    status: str
    initiated_by: int
    created_at: datetime
    accepted_at: Optional[datetime]
    bond_type: Optional[str]
    notes: Optional[str]
    
    class Config:
        from_attributes = True

class BondAction(BaseModel):
    """Schema para aceitar/rejeitar vínculo"""
    action: str = Field(..., description="Ação: accept ou reject")
    
    @validator('action')
    def validate_action(cls, v):
        if v not in ['accept', 'reject']:
            raise ValueError('Ação deve ser "accept" ou "reject"')
        return v

# ──────────────────────────────────────────────
# Schemas para Convites de Encontro
# ──────────────────────────────────────────────
class MeetingInviteCreate(BaseModel):
    """Schema para criar convite de encontro"""
    receiver_id: int = Field(..., description="ID do usuário para convidar")
    message: Optional[str] = Field(None, max_length=1000, description="Mensagem do convite")
    meeting_place_name: Optional[str] = Field(None, max_length=200, description="Nome do local de encontro")
    meeting_latitude: Optional[float] = Field(None, ge=-90, le=90, description="Latitude do encontro")
    meeting_longitude: Optional[float] = Field(None, ge=-180, le=180, description="Longitude do encontro")
    duration_hours: int = Field(24, ge=1, le=168, description="Validade do convite em horas (1h a 7 dias)")
    share_sender_location: Optional[bool] = Field(True, description="Compartilhar localização com destinatário")

class MeetingInviteResponse(BaseModel):
    """Schema para resposta de convite"""
    id: str
    sender_id: int
    receiver_id: int
    meeting_latitude: Optional[float]
    meeting_longitude: Optional[float]
    meeting_place_name: Optional[str]
    message: Optional[str]
    status: str
    created_at: datetime
    expires_at: datetime
    responded_at: Optional[datetime]
    share_sender_location: bool
    
    class Config:
        from_attributes = True

class MeetingInviteAction(BaseModel):
    """Schema para responder convite"""
    action: str = Field(..., description="Ação: accept, reject ou cancel")
    
    @validator('action')
    def validate_action(cls, v):
        if v not in ['accept', 'reject', 'cancel']:
            raise ValueError('Ação deve ser "accept", "reject" ou "cancel"')
        return v

class MeetingWithLocation(BaseModel):
    """Schema para convite com localização do remetente"""
    invite: MeetingInviteResponse
    sender_location: Optional[LocationResponse]
    sender_username: str
