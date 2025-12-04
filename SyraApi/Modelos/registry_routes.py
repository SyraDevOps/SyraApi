"""
Rotas para gerenciamento de Devices, Nodes e APIs do usuário
Sistema node_{username} - Registro de dispositivos, servidores e integrações
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.user_node import Device, NodeRegistry, APIRegistry, X25519KeyPair, QRCode
from Modelos.user_node_schemas import (
    DeviceCreate, DeviceUpdate, DeviceResponse,
    NodeCreate, NodeUpdate, NodeResponse,
    APICreate, APIUpdate, APIResponse,
    UserNodeSummary
)
from Modelos.auth import get_current_user
from Tools.encryption import encrypt_sensitive_data, decrypt_sensitive_data


# ========== Devices ==========

router_devices = APIRouter(prefix="/user-node/devices", tags=["Devices/Dispositivos"])


@router_devices.post("/", response_model=DeviceResponse, status_code=status.HTTP_201_CREATED)
async def register_device(
    device: DeviceCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Registra um novo dispositivo IoT/embarcado para o usuário
    """
    try:
        # Verificar se public_key_id existe e pertence ao usuário
        if device.public_key_id:
            keypair = db.query(X25519KeyPair).filter(
                X25519KeyPair.id == device.public_key_id,
                X25519KeyPair.user_id == current_user.id
            ).first()
            
            if not keypair:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Chave pública não encontrada"
                )
        
        new_device = Device(
            user_id=current_user.id,
            device_name=device.device_name,
            device_type=device.device_type,
            mac_address=device.mac_address,
            ip_address=device.ip_address,
            endpoint_url=device.endpoint_url,
            mdns_name=device.mdns_name,
            public_key_id=device.public_key_id,
            psw=device.psw,
            data=device.data,
            req=device.req
        )
        
        db.add(new_device)
        db.commit()
        db.refresh(new_device)
        
        return new_device
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao registrar dispositivo: {str(e)}"
        )


@router_devices.get("/", response_model=List[DeviceResponse])
async def list_my_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    active_only: bool = True,
    online_only: bool = False
):
    """
    Lista todos os dispositivos do usuário autenticado
    """
    query = db.query(Device).filter(Device.user_id == current_user.id)
    
    if active_only:
        query = query.filter(Device.is_active == True)
    
    if online_only:
        query = query.filter(Device.is_online == True)
    
    devices = query.order_by(Device.created_at.desc()).all()
    return devices


@router_devices.get("/{device_id}", response_model=DeviceResponse)
async def get_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de um dispositivo específico
    """
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dispositivo não encontrado"
        )
    
    return device


@router_devices.patch("/{device_id}", response_model=DeviceResponse)
async def update_device(
    device_id: int,
    device_update: DeviceUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza informações de um dispositivo
    """
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dispositivo não encontrado"
        )
    
    # Atualizar campos fornecidos
    update_data = device_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(device, field, value)
    
    device.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(device)
    
    return device


@router_devices.patch("/{device_id}/heartbeat")
async def device_heartbeat(
    device_id: int,
    is_online: bool = True,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza o status online do dispositivo (heartbeat)
    """
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dispositivo não encontrado"
        )
    
    device.is_online = is_online
    device.last_seen = datetime.utcnow()
    db.commit()
    
    return {"device_name": device.device_name, "is_online": is_online, "last_seen": device.last_seen}


@router_devices.delete("/{device_id}")
async def delete_device(
    device_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta permanentemente um dispositivo
    """
    device = db.query(Device).filter(
        Device.id == device_id,
        Device.user_id == current_user.id
    ).first()
    
    if not device:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Dispositivo não encontrado"
        )
    
    device_name = device.device_name
    db.delete(device)
    db.commit()
    
    return {"message": "Dispositivo deletado", "device_name": device_name}


# ========== Nodes ==========

router_nodes = APIRouter(prefix="/user-node/nodes", tags=["Nodes/Servidores"])


@router_nodes.post("/", response_model=NodeResponse, status_code=status.HTTP_201_CREATED)
async def register_node(
    node: NodeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Registra um novo node/servidor remoto
    """
    try:
        # Verificar se public_key_id existe
        if node.public_key_id:
            keypair = db.query(X25519KeyPair).filter(
                X25519KeyPair.id == node.public_key_id,
                X25519KeyPair.user_id == current_user.id
            ).first()
            
            if not keypair:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Chave pública não encontrada"
                )
        
        new_node = NodeRegistry(
            user_id=current_user.id,
            node_name=node.node_name,
            node_type=node.node_type,
            endpoint_url=node.endpoint_url,
            api_version=node.api_version,
            auth_type=node.auth_type,
            public_key_id=node.public_key_id,
            psw=node.psw,
            data=node.data,
            req=node.req
        )
        
        db.add(new_node)
        db.commit()
        db.refresh(new_node)
        
        return new_node
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao registrar node: {str(e)}"
        )


@router_nodes.get("/", response_model=List[NodeResponse])
async def list_my_nodes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    active_only: bool = True
):
    """
    Lista todos os nodes do usuário
    """
    query = db.query(NodeRegistry).filter(NodeRegistry.user_id == current_user.id)
    
    if active_only:
        query = query.filter(NodeRegistry.is_active == True)
    
    nodes = query.order_by(NodeRegistry.created_at.desc()).all()
    return nodes


@router_nodes.get("/{node_id}", response_model=NodeResponse)
async def get_node(
    node_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de um node específico
    """
    node = db.query(NodeRegistry).filter(
        NodeRegistry.id == node_id,
        NodeRegistry.user_id == current_user.id
    ).first()
    
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Node não encontrado"
        )
    
    return node


@router_nodes.patch("/{node_id}", response_model=NodeResponse)
async def update_node(
    node_id: int,
    node_update: NodeUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza informações de um node
    """
    node = db.query(NodeRegistry).filter(
        NodeRegistry.id == node_id,
        NodeRegistry.user_id == current_user.id
    ).first()
    
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Node não encontrado"
        )
    
    update_data = node_update.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(node, field, value)
    
    node.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(node)
    
    return node


@router_nodes.delete("/{node_id}")
async def delete_node(
    node_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta permanentemente um node
    """
    node = db.query(NodeRegistry).filter(
        NodeRegistry.id == node_id,
        NodeRegistry.user_id == current_user.id
    ).first()
    
    if not node:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Node não encontrado"
        )
    
    node_name = node.node_name
    db.delete(node)
    db.commit()
    
    return {"message": "Node deletado", "node_name": node_name}


# ========== APIs ==========

router_apis = APIRouter(prefix="/user-node/apis", tags=["APIs/Integrações"])


@router_apis.post("/", response_model=APIResponse, status_code=status.HTTP_201_CREATED)
async def register_api(
    api: APICreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Registra uma nova API externa
    A API key é CRIPTOGRAFADA antes de ser armazenada
    """
    try:
        # Criptografar API key se fornecida
        api_key_encrypted = None
        if api.api_key:
            api_key_encrypted = encrypt_sensitive_data(api.api_key)
        
        new_api = APIRegistry(
            user_id=current_user.id,
            api_name=api.api_name,
            api_provider=api.api_provider,
            api_category=api.api_category,
            base_url=api.base_url,
            api_version=api.api_version,
            auth_method=api.auth_method,
            api_key_encrypted=api_key_encrypted,
            psw=api.psw,
            data=api.data,
            req=api.req,
            rate_limit=api.rate_limit
        )
        
        db.add(new_api)
        db.commit()
        db.refresh(new_api)
        
        return new_api
    
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao registrar API: {str(e)}"
        )


@router_apis.get("/", response_model=List[APIResponse])
async def list_my_apis(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    active_only: bool = True,
    category: Optional[str] = None
):
    """
    Lista todas as APIs do usuário
    """
    query = db.query(APIRegistry).filter(APIRegistry.user_id == current_user.id)
    
    if active_only:
        query = query.filter(APIRegistry.is_active == True)
    
    if category:
        query = query.filter(APIRegistry.api_category == category)
    
    apis = query.order_by(APIRegistry.created_at.desc()).all()
    return apis


@router_apis.get("/{api_id}", response_model=APIResponse)
async def get_api(
    api_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de uma API específica
    """
    api = db.query(APIRegistry).filter(
        APIRegistry.id == api_id,
        APIRegistry.user_id == current_user.id
    ).first()
    
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API não encontrada"
        )
    
    return api


@router_apis.get("/{api_id}/key")
async def get_api_key(
    api_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Descriptografa e retorna a API key
    ⚠️ USE COM CUIDADO
    """
    api = db.query(APIRegistry).filter(
        APIRegistry.id == api_id,
        APIRegistry.user_id == current_user.id
    ).first()
    
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API não encontrada"
        )
    
    if not api.api_key_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API key não disponível"
        )
    
    try:
        api_key = decrypt_sensitive_data(api.api_key_encrypted)
        
        return {
            "api_name": api.api_name,
            "api_key": api_key,
            "warning": "⚠️ API key descriptografada - mantenha segura!"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao descriptografar API key: {str(e)}"
        )


@router_apis.patch("/{api_id}", response_model=APIResponse)
async def update_api(
    api_id: int,
    api_update: APIUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Atualiza informações de uma API
    """
    api = db.query(APIRegistry).filter(
        APIRegistry.id == api_id,
        APIRegistry.user_id == current_user.id
    ).first()
    
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API não encontrada"
        )
    
    update_data = api_update.dict(exclude_unset=True)
    
    # Se estiver atualizando api_key, criptografar
    if 'api_key' in update_data and update_data['api_key']:
        update_data['api_key_encrypted'] = encrypt_sensitive_data(update_data['api_key'])
        del update_data['api_key']
    
    for field, value in update_data.items():
        setattr(api, field, value)
    
    api.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(api)
    
    return api


@router_apis.post("/{api_id}/use")
async def record_api_usage(
    api_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Registra uso da API (incrementa contador)
    """
    api = db.query(APIRegistry).filter(
        APIRegistry.id == api_id,
        APIRegistry.user_id == current_user.id
    ).first()
    
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API não encontrada"
        )
    
    api.usage_count += 1
    api.last_used = datetime.utcnow()
    db.commit()
    
    return {"api_name": api.api_name, "usage_count": api.usage_count}


@router_apis.delete("/{api_id}")
async def delete_api(
    api_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta permanentemente uma API
    """
    api = db.query(APIRegistry).filter(
        APIRegistry.id == api_id,
        APIRegistry.user_id == current_user.id
    ).first()
    
    if not api:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API não encontrada"
        )
    
    api_name = api.api_name
    db.delete(api)
    db.commit()
    
    return {"message": "API deletada", "api_name": api_name}


# ========== Dashboard/Summary ==========

router_summary = APIRouter(prefix="/user-node", tags=["Dashboard"])


@router_summary.get("/summary", response_model=UserNodeSummary)
async def get_user_node_summary(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retorna resumo completo do node do usuário (dashboard)
    """
    total_keypairs = db.query(X25519KeyPair).filter(X25519KeyPair.user_id == current_user.id).count()
    total_qrcodes = db.query(QRCode).filter(QRCode.user_id == current_user.id).count()
    total_devices = db.query(Device).filter(Device.user_id == current_user.id).count()
    total_nodes = db.query(NodeRegistry).filter(NodeRegistry.user_id == current_user.id).count()
    total_apis = db.query(APIRegistry).filter(APIRegistry.user_id == current_user.id).count()
    
    active_devices = db.query(Device).filter(
        Device.user_id == current_user.id,
        Device.is_active == True
    ).count()
    
    online_nodes = db.query(NodeRegistry).filter(
        NodeRegistry.user_id == current_user.id,
        NodeRegistry.is_online == True
    ).count()
    
    return UserNodeSummary(
        username=current_user.user,
        total_keypairs=total_keypairs,
        total_qrcodes=total_qrcodes,
        total_devices=total_devices,
        total_nodes=total_nodes,
        total_apis=total_apis,
        active_devices=active_devices,
        online_nodes=online_nodes
    )
