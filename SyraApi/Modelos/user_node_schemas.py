"""
Schemas Pydantic para validação de dados do sistema UserNode
"""
from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, Any
from datetime import datetime


# ========== X25519 KeyPair Schemas ==========

class X25519KeyPairCreate(BaseModel):
    """Schema para criação de par de chaves X25519"""
    key_name: str = Field(..., min_length=1, max_length=255, description="Nome identificador da chave")
    algorithm: str = Field(default="X25519", description="Algoritmo de criptografia")
    public_key: str = Field(..., description="Chave pública em base64url (campo 'x' do JWK)")
    private_key: str = Field(..., description="Chave privada em base64url (campo 'd' do JWK)")
    full_jwk: Optional[str] = Field(None, description="JSON completo da chave no formato JWK")
    
    # Campos opcionais personalizados
    psw: Optional[str] = Field(None, max_length=500, description="Senha adicional")
    data: Optional[str] = Field(None, description="Metadados extras em JSON")
    req: Optional[str] = Field(None, description="Requisitos/configurações em JSON")


class X25519KeyPairResponse(BaseModel):
    """Schema de resposta de chave X25519"""
    id: int
    user_id: int
    key_name: str
    timestamp: datetime
    algorithm: str
    public_key: str
    psw: Optional[str] = None
    data: Optional[str] = None
    req: Optional[str] = None
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class X25519KeyPairPublicOnly(BaseModel):
    """Schema apenas com chave pública (para compartilhamento)"""
    id: int
    key_name: str
    algorithm: str
    public_key: str
    timestamp: datetime
    
    class Config:
        from_attributes = True


# ========== QRCode Schemas ==========

class QRCodeCreate(BaseModel):
    """Schema para criação de QR code"""
    qr_name: str = Field(..., min_length=1, max_length=255)
    qr_type: str = Field(..., description="Tipo: 'public', 'private', 'full', 'custom'")
    description: Optional[str] = None
    qr_image_base64: str = Field(..., description="Imagem QR em base64")
    qr_data: str = Field(..., description="Dados originais que geraram o QR")
    keypair_id: Optional[int] = Field(None, description="ID do par de chaves associado")
    
    # Campos opcionais
    psw: Optional[str] = Field(None, max_length=500)
    data: Optional[str] = None
    req: Optional[str] = None
    
    @validator('qr_type')
    def validate_qr_type(cls, v):
        allowed = ['public', 'private', 'full', 'custom']
        if v not in allowed:
            raise ValueError(f"qr_type deve ser um de: {', '.join(allowed)}")
        return v


class QRCodeResponse(BaseModel):
    """Schema de resposta de QR code"""
    id: int
    user_id: int
    keypair_id: Optional[int]
    qr_name: str
    qr_type: str
    description: Optional[str]
    qr_image_base64: str
    psw: Optional[str]
    data: Optional[str]
    req: Optional[str]
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# ========== Device Schemas ==========

class DeviceCreate(BaseModel):
    """Schema para registro de dispositivo"""
    device_name: str = Field(..., min_length=1, max_length=255)
    device_type: Optional[str] = Field(None, max_length=100, description="Ex: ESP32, Raspberry Pi")
    mac_address: Optional[str] = Field(None, max_length=17, description="Formato: AA:BB:CC:DD:EE:FF")
    ip_address: Optional[str] = Field(None, max_length=45, description="IPv4 ou IPv6")
    endpoint_url: Optional[str] = Field(None, max_length=500, description="URL de acesso ao dispositivo")
    mdns_name: Optional[str] = Field(None, max_length=255, description="Nome mDNS (ex: device.local)")
    public_key_id: Optional[int] = Field(None, description="ID da chave pública associada")
    
    # Campos opcionais personalizados
    psw: Optional[str] = Field(None, max_length=500, description="Senha de acesso")
    data: Optional[str] = Field(None, description="Configurações em JSON")
    req: Optional[str] = Field(None, description="Requisitos de conexão em JSON")
    
    @validator('mac_address')
    def validate_mac(cls, v):
        if v and len(v.replace(':', '')) != 12:
            raise ValueError("MAC address deve ter formato AA:BB:CC:DD:EE:FF")
        return v


class DeviceUpdate(BaseModel):
    """Schema para atualização de dispositivo"""
    device_name: Optional[str] = Field(None, min_length=1, max_length=255)
    device_type: Optional[str] = None
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    endpoint_url: Optional[str] = None
    mdns_name: Optional[str] = None
    public_key_id: Optional[int] = None
    psw: Optional[str] = None
    data: Optional[str] = None
    req: Optional[str] = None
    is_online: Optional[bool] = None
    is_active: Optional[bool] = None


class DeviceResponse(BaseModel):
    """Schema de resposta de dispositivo"""
    id: int
    user_id: int
    device_name: str
    device_type: Optional[str]
    mac_address: Optional[str]
    ip_address: Optional[str]
    endpoint_url: Optional[str]
    mdns_name: Optional[str]
    public_key_id: Optional[int]
    psw: Optional[str]
    data: Optional[str]
    req: Optional[str]
    is_online: bool
    last_seen: Optional[datetime]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ========== Node Registry Schemas ==========

class NodeCreate(BaseModel):
    """Schema para registro de node"""
    node_name: str = Field(..., min_length=1, max_length=255)
    node_type: Optional[str] = Field(None, max_length=100)
    endpoint_url: str = Field(..., max_length=500)
    api_version: Optional[str] = Field(None, max_length=50)
    auth_type: Optional[str] = Field(None, max_length=50, description="Ex: JWT, X25519, Basic, API Key")
    public_key_id: Optional[int] = None
    
    # Campos opcionais
    psw: Optional[str] = Field(None, max_length=500, description="Senha/token de acesso")
    data: Optional[str] = Field(None, description="Configurações em JSON")
    req: Optional[str] = Field(None, description="Headers/requisitos em JSON")


class NodeUpdate(BaseModel):
    """Schema para atualização de node"""
    node_name: Optional[str] = None
    node_type: Optional[str] = None
    endpoint_url: Optional[str] = None
    api_version: Optional[str] = None
    auth_type: Optional[str] = None
    public_key_id: Optional[int] = None
    psw: Optional[str] = None
    data: Optional[str] = None
    req: Optional[str] = None
    is_online: Optional[bool] = None
    is_active: Optional[bool] = None


class NodeResponse(BaseModel):
    """Schema de resposta de node"""
    id: int
    user_id: int
    node_name: str
    node_type: Optional[str]
    endpoint_url: str
    api_version: Optional[str]
    auth_type: Optional[str]
    public_key_id: Optional[int]
    psw: Optional[str]
    data: Optional[str]
    req: Optional[str]
    is_online: bool
    last_ping: Optional[datetime]
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ========== API Registry Schemas ==========

class APICreate(BaseModel):
    """Schema para registro de API"""
    api_name: str = Field(..., min_length=1, max_length=255)
    api_provider: Optional[str] = Field(None, max_length=255, description="Ex: OpenAI, Google, Custom")
    api_category: Optional[str] = Field(None, max_length=100, description="Ex: AI, Maps, Payment, IoT")
    base_url: str = Field(..., max_length=500)
    api_version: Optional[str] = Field(None, max_length=50)
    auth_method: Optional[str] = Field(None, max_length=50, description="Ex: Bearer, API Key, OAuth2")
    api_key: Optional[str] = Field(None, description="Chave da API (será criptografada)")
    
    # Campos opcionais
    psw: Optional[str] = Field(None, max_length=500, description="Senha/secret adicional")
    data: Optional[str] = Field(None, description="Configurações/headers em JSON")
    req: Optional[str] = Field(None, description="Requisitos/limites em JSON")
    rate_limit: Optional[str] = Field(None, max_length=100, description="Ex: 1000/day")


class APIUpdate(BaseModel):
    """Schema para atualização de API"""
    api_name: Optional[str] = None
    api_provider: Optional[str] = None
    api_category: Optional[str] = None
    base_url: Optional[str] = None
    api_version: Optional[str] = None
    auth_method: Optional[str] = None
    api_key: Optional[str] = None
    psw: Optional[str] = None
    data: Optional[str] = None
    req: Optional[str] = None
    rate_limit: Optional[str] = None
    is_active: Optional[bool] = None


class APIResponse(BaseModel):
    """Schema de resposta de API (sem expor api_key)"""
    id: int
    user_id: int
    api_name: str
    api_provider: Optional[str]
    api_category: Optional[str]
    base_url: str
    api_version: Optional[str]
    auth_method: Optional[str]
    psw: Optional[str]
    data: Optional[str]
    req: Optional[str]
    rate_limit: Optional[str]
    usage_count: int
    is_active: bool
    last_used: Optional[datetime]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ========== Dashboard/Summary Schemas ==========

class UserNodeSummary(BaseModel):
    """Resumo do node do usuário (dashboard)"""
    username: str
    total_keypairs: int
    total_qrcodes: int
    total_devices: int
    total_nodes: int
    total_apis: int
    active_devices: int
    online_nodes: int
