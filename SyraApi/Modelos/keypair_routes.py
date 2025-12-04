"""
Rotas para gerenciamento de chaves X25519 e QR codes do usuário
Sistema node_{username} - Armazenamento seguro de chaves criptográficas
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.user_node import X25519KeyPair, QRCode
from Modelos.user_node_schemas import (
    X25519KeyPairCreate, 
    X25519KeyPairResponse, 
    X25519KeyPairPublicOnly,
    QRCodeCreate,
    QRCodeResponse
)
from Modelos.auth import get_current_user
from Tools.encryption import encrypt_sensitive_data, decrypt_sensitive_data, encrypt_json, decrypt_json


router = APIRouter(prefix="/user-node/keys", tags=["Chaves X25519"])


# ========== Chaves X25519 ==========

@router.post("/generate", response_model=X25519KeyPairResponse, status_code=status.HTTP_201_CREATED)
async def store_x25519_keypair(
    keypair: X25519KeyPairCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Armazena um par de chaves X25519 gerado pelo frontend
    A chave privada é CRIPTOGRAFADA antes de ser armazenada
    """
    try:
        # Verificar se já existe chave com esse nome para o usuário
        existing = db.query(X25519KeyPair).filter(
            X25519KeyPair.user_id == current_user.id,
            X25519KeyPair.key_name == keypair.key_name
        ).first()
        
        if existing:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Já existe uma chave com o nome '{keypair.key_name}' para este usuário"
            )
        
        # Criptografar chave privada
        private_key_encrypted = encrypt_sensitive_data(keypair.private_key)
        
        # Criptografar JWK completo (se fornecido)
        full_jwk_encrypted = None
        if keypair.full_jwk:
            full_jwk_encrypted = encrypt_sensitive_data(keypair.full_jwk)
        
        # Criar registro
        new_keypair = X25519KeyPair(
            user_id=current_user.id,
            key_name=keypair.key_name,
            algorithm=keypair.algorithm,
            public_key=keypair.public_key,
            private_key_encrypted=private_key_encrypted,
            full_jwk_encrypted=full_jwk_encrypted,
            psw=keypair.psw,
            data=keypair.data,
            req=keypair.req
        )
        
        db.add(new_keypair)
        db.commit()
        db.refresh(new_keypair)
        
        return new_keypair
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao armazenar chave: {str(e)}"
        )


@router.get("/", response_model=List[X25519KeyPairResponse])
async def list_my_keypairs(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    active_only: bool = True
):
    """
    Lista todas as chaves X25519 do usuário autenticado
    Retorna dados completos (exceto chave privada descriptografada)
    """
    query = db.query(X25519KeyPair).filter(X25519KeyPair.user_id == current_user.id)
    
    if active_only:
        query = query.filter(X25519KeyPair.is_active == True)
    
    keypairs = query.order_by(X25519KeyPair.created_at.desc()).all()
    return keypairs


@router.get("/public", response_model=List[X25519KeyPairPublicOnly])
async def list_public_keys(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Lista apenas as chaves públicas do usuário (para compartilhamento seguro)
    """
    keypairs = db.query(X25519KeyPair).filter(
        X25519KeyPair.user_id == current_user.id,
        X25519KeyPair.is_active == True
    ).all()
    
    return keypairs


@router.get("/{keypair_id}", response_model=X25519KeyPairResponse)
async def get_keypair(
    keypair_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de uma chave específica (apenas do próprio usuário)
    """
    keypair = db.query(X25519KeyPair).filter(
        X25519KeyPair.id == keypair_id,
        X25519KeyPair.user_id == current_user.id
    ).first()
    
    if not keypair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chave não encontrada"
        )
    
    return keypair


@router.get("/{keypair_id}/private-key")
async def get_private_key(
    keypair_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Descriptografa e retorna a chave privada
    ⚠️ USE COM CUIDADO - Apenas para exportação segura
    """
    keypair = db.query(X25519KeyPair).filter(
        X25519KeyPair.id == keypair_id,
        X25519KeyPair.user_id == current_user.id
    ).first()
    
    if not keypair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chave não encontrada"
        )
    
    try:
        # Descriptografar chave privada
        private_key = decrypt_sensitive_data(keypair.private_key_encrypted)
        
        return {
            "key_name": keypair.key_name,
            "algorithm": keypair.algorithm,
            "public_key": keypair.public_key,
            "private_key": private_key,
            "warning": "⚠️ Chave privada descriptografada - mantenha segura!"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao descriptografar chave: {str(e)}"
        )


@router.get("/{keypair_id}/full-jwk")
async def get_full_jwk(
    keypair_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Retorna o JSON JWK completo descriptografado (se disponível)
    """
    keypair = db.query(X25519KeyPair).filter(
        X25519KeyPair.id == keypair_id,
        X25519KeyPair.user_id == current_user.id
    ).first()
    
    if not keypair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chave não encontrada"
        )
    
    if not keypair.full_jwk_encrypted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="JWK completo não disponível para esta chave"
        )
    
    try:
        full_jwk = decrypt_sensitive_data(keypair.full_jwk_encrypted)
        
        return {
            "key_name": keypair.key_name,
            "full_jwk": full_jwk,
            "warning": "⚠️ JWK completo com chave privada - mantenha seguro!"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao descriptografar JWK: {str(e)}"
        )


@router.patch("/{keypair_id}/deactivate")
async def deactivate_keypair(
    keypair_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Desativa uma chave (não deleta, apenas marca como inativa)
    """
    keypair = db.query(X25519KeyPair).filter(
        X25519KeyPair.id == keypair_id,
        X25519KeyPair.user_id == current_user.id
    ).first()
    
    if not keypair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chave não encontrada"
        )
    
    keypair.is_active = False
    keypair.updated_at = datetime.utcnow()
    db.commit()
    
    return {"message": "Chave desativada com sucesso", "key_name": keypair.key_name}


@router.delete("/{keypair_id}")
async def delete_keypair(
    keypair_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    ⚠️ DELETA permanentemente uma chave e seus QR codes associados
    """
    keypair = db.query(X25519KeyPair).filter(
        X25519KeyPair.id == keypair_id,
        X25519KeyPair.user_id == current_user.id
    ).first()
    
    if not keypair:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Chave não encontrada"
        )
    
    key_name = keypair.key_name
    db.delete(keypair)
    db.commit()
    
    return {"message": "Chave deletada permanentemente", "key_name": key_name}


# ========== QR Codes ==========

router_qr = APIRouter(prefix="/user-node/qrcodes", tags=["QR Codes"])


@router_qr.post("/", response_model=QRCodeResponse, status_code=status.HTTP_201_CREATED)
async def store_qrcode(
    qrcode: QRCodeCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Armazena um QR code gerado pelo frontend
    Os dados originais são CRIPTOGRAFADOS
    """
    try:
        # Verificar se keypair_id existe e pertence ao usuário
        if qrcode.keypair_id:
            keypair = db.query(X25519KeyPair).filter(
                X25519KeyPair.id == qrcode.keypair_id,
                X25519KeyPair.user_id == current_user.id
            ).first()
            
            if not keypair:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="Par de chaves não encontrado"
                )
        
        # Criptografar dados originais do QR
        qr_data_encrypted = encrypt_sensitive_data(qrcode.qr_data)
        
        # Criar registro
        new_qrcode = QRCode(
            user_id=current_user.id,
            keypair_id=qrcode.keypair_id,
            qr_name=qrcode.qr_name,
            qr_type=qrcode.qr_type,
            description=qrcode.description,
            qr_image_base64=qrcode.qr_image_base64,
            qr_data_encrypted=qr_data_encrypted,
            psw=qrcode.psw,
            data=qrcode.data,
            req=qrcode.req
        )
        
        db.add(new_qrcode)
        db.commit()
        db.refresh(new_qrcode)
        
        return new_qrcode
    
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao armazenar QR code: {str(e)}"
        )


@router_qr.get("/", response_model=List[QRCodeResponse])
async def list_my_qrcodes(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
    qr_type: str = None,
    active_only: bool = True
):
    """
    Lista todos os QR codes do usuário autenticado
    """
    query = db.query(QRCode).filter(QRCode.user_id == current_user.id)
    
    if qr_type:
        query = query.filter(QRCode.qr_type == qr_type)
    
    if active_only:
        query = query.filter(QRCode.is_active == True)
    
    qrcodes = query.order_by(QRCode.created_at.desc()).all()
    return qrcodes


@router_qr.get("/{qrcode_id}", response_model=QRCodeResponse)
async def get_qrcode(
    qrcode_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Obtém detalhes de um QR code específico
    """
    qrcode = db.query(QRCode).filter(
        QRCode.id == qrcode_id,
        QRCode.user_id == current_user.id
    ).first()
    
    if not qrcode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="QR code não encontrado"
        )
    
    return qrcode


@router_qr.get("/{qrcode_id}/data")
async def get_qrcode_data(
    qrcode_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Descriptografa e retorna os dados originais do QR code
    """
    qrcode = db.query(QRCode).filter(
        QRCode.id == qrcode_id,
        QRCode.user_id == current_user.id
    ).first()
    
    if not qrcode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="QR code não encontrado"
        )
    
    try:
        qr_data = decrypt_sensitive_data(qrcode.qr_data_encrypted)
        
        return {
            "qr_name": qrcode.qr_name,
            "qr_type": qrcode.qr_type,
            "qr_data": qr_data,
            "qr_image_base64": qrcode.qr_image_base64
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao descriptografar dados do QR: {str(e)}"
        )


@router_qr.delete("/{qrcode_id}")
async def delete_qrcode(
    qrcode_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Deleta permanentemente um QR code
    """
    qrcode = db.query(QRCode).filter(
        QRCode.id == qrcode_id,
        QRCode.user_id == current_user.id
    ).first()
    
    if not qrcode:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="QR code não encontrado"
        )
    
    qr_name = qrcode.qr_name
    db.delete(qrcode)
    db.commit()
    
    return {"message": "QR code deletado permanentemente", "qr_name": qr_name}
