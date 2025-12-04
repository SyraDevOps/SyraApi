"""
Modelos de banco de dados individuais por usuário (node_{username})
Armazena chaves X25519, QR codes, devices, nodes e APIs
"""
from sqlalchemy import Column, Integer, String, Text, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from datetime import datetime
from DB.database import Base


class X25519KeyPair(Base):
    """Armazena pares de chaves X25519 geradas pelo usuário"""
    __tablename__ = "x25519_keypairs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Metadados da chave
    key_name = Column(String(255), nullable=False)  # Nome identificador (ex: node_001)
    timestamp = Column(DateTime, default=datetime.utcnow)
    algorithm = Column(String(50), default="X25519")
    
    # Chaves em formato base64url (JWK-style)
    public_key = Column(Text, nullable=False)  # campo 'x' do JWK
    private_key_encrypted = Column(Text, nullable=False)  # campo 'd' do JWK (CRIPTOGRAFADO)
    
    # JSON completo da chave (criptografado)
    full_jwk_encrypted = Column(Text, nullable=True)
    
    # Campos opcionais personalizados
    psw = Column(String(500), nullable=True)  # Senha adicional
    data = Column(Text, nullable=True)  # Metadados extras (JSON string)
    req = Column(Text, nullable=True)  # Requisitos/configurações (JSON string)
    
    # Status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamento
    user = relationship("User", back_populates="keypairs")


class QRCode(Base):
    """Armazena QR codes gerados (público, privado e completo)"""
    __tablename__ = "qrcodes"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    keypair_id = Column(Integer, ForeignKey("x25519_keypairs.id"), nullable=True)
    
    # Metadados
    qr_name = Column(String(255), nullable=False)
    qr_type = Column(String(50), nullable=False)  # 'public', 'private', 'full', 'custom'
    description = Column(Text, nullable=True)
    
    # Imagem QR em base64
    qr_image_base64 = Column(Text, nullable=False)
    
    # Dados originais que geraram o QR (podem ser criptografados)
    qr_data_encrypted = Column(Text, nullable=False)
    
    # Campos opcionais
    psw = Column(String(500), nullable=True)
    data = Column(Text, nullable=True)
    req = Column(Text, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = relationship("User", back_populates="qrcodes")
    keypair = relationship("X25519KeyPair", backref="qrcodes")


class Device(Base):
    """Registro de dispositivos/nodes físicos do usuário"""
    __tablename__ = "devices"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Identificação do dispositivo
    device_name = Column(String(255), nullable=False)
    device_type = Column(String(100), nullable=True)  # ex: 'ESP32', 'Raspberry Pi', 'Arduino'
    mac_address = Column(String(17), nullable=True)
    ip_address = Column(String(45), nullable=True)  # IPv4 ou IPv6
    
    # Localização/URL de acesso
    endpoint_url = Column(String(500), nullable=True)  # ex: http://192.168.4.1/ ou http://device.local
    mdns_name = Column(String(255), nullable=True)  # ex: syra-node.local
    
    # Chave pública associada (opcional)
    public_key_id = Column(Integer, ForeignKey("x25519_keypairs.id"), nullable=True)
    
    # Campos opcionais personalizados
    psw = Column(String(500), nullable=True)  # Senha de acesso ao dispositivo
    data = Column(Text, nullable=True)  # Configurações/metadados (JSON)
    req = Column(Text, nullable=True)  # Requisitos de conexão (JSON)
    
    # Status
    is_online = Column(Boolean, default=False)
    last_seen = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = relationship("User", back_populates="devices")
    public_key = relationship("X25519KeyPair", foreign_keys=[public_key_id])


class NodeRegistry(Base):
    """Registro de nodes/servidores remotos"""
    __tablename__ = "node_registry"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Identificação do node
    node_name = Column(String(255), nullable=False)
    node_type = Column(String(100), nullable=True)  # ex: 'SyraNode', 'API Server', 'Database'
    
    # Localização
    endpoint_url = Column(String(500), nullable=False)
    api_version = Column(String(50), nullable=True)
    
    # Autenticação
    auth_type = Column(String(50), nullable=True)  # ex: 'JWT', 'X25519', 'Basic', 'API Key'
    public_key_id = Column(Integer, ForeignKey("x25519_keypairs.id"), nullable=True)
    
    # Campos opcionais personalizados
    psw = Column(String(500), nullable=True)  # Senha/token de acesso
    data = Column(Text, nullable=True)  # Configurações/metadados (JSON)
    req = Column(Text, nullable=True)  # Headers/requisitos (JSON)
    
    # Status
    is_online = Column(Boolean, default=False)
    last_ping = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = relationship("User", back_populates="nodes")
    public_key = relationship("X25519KeyPair", foreign_keys=[public_key_id])


class APIRegistry(Base):
    """Registro de APIs externas e integrações"""
    __tablename__ = "api_registry"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    
    # Identificação da API
    api_name = Column(String(255), nullable=False)
    api_provider = Column(String(255), nullable=True)  # ex: 'OpenAI', 'Google', 'Custom'
    api_category = Column(String(100), nullable=True)  # ex: 'AI', 'Maps', 'Payment', 'IoT'
    
    # Endpoint
    base_url = Column(String(500), nullable=False)
    api_version = Column(String(50), nullable=True)
    
    # Autenticação
    auth_method = Column(String(50), nullable=True)  # ex: 'Bearer', 'API Key', 'OAuth2'
    api_key_encrypted = Column(Text, nullable=True)  # Chave da API (CRIPTOGRAFADA)
    
    # Campos opcionais personalizados
    psw = Column(String(500), nullable=True)  # Senha/secret adicional
    data = Column(Text, nullable=True)  # Configurações/headers customizados (JSON)
    req = Column(Text, nullable=True)  # Requisitos/limites de uso (JSON)
    
    # Limites e uso
    rate_limit = Column(String(100), nullable=True)  # ex: '1000/day'
    usage_count = Column(Integer, default=0)
    
    # Status
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relacionamentos
    user = relationship("User", back_populates="apis")


# Adicionar relacionamentos no modelo User (será atualizado em user.py)
"""
Adicionar no Modelos/user.py na classe User:

    keypairs = relationship("X25519KeyPair", back_populates="user", cascade="all, delete-orphan")
    qrcodes = relationship("QRCode", back_populates="user", cascade="all, delete-orphan")
    devices = relationship("Device", back_populates="user", cascade="all, delete-orphan")
    nodes = relationship("NodeRegistry", back_populates="user", cascade="all, delete-orphan")
    apis = relationship("APIRegistry", back_populates="user", cascade="all, delete-orphan")
"""
