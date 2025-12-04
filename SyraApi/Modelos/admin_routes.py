"""
Sistema de administração: gerenciar usuários e IPs banidos
"""
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field, IPvAnyAddress
from datetime import datetime
import sqlite3
from pathlib import Path

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Tools.middleware import verify_admin

router_admin = APIRouter(prefix="/admin", tags=["Administração"])


# ========== Middleware para verificar IPs banidos ==========

class BannedIPManager:
    """Gerenciador de IPs banidos"""
    def __init__(self, db_path: str = "/root/SyraApi/DB/banned_ips.db"):
        self.db_path = db_path
        self._init_db()
    
    def _init_db(self):
        """Inicializa banco de IPs banidos"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS banned_ips (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                reason TEXT,
                banned_by INTEGER,
                banned_at TEXT NOT NULL,
                expires_at TEXT
            )
        """)
        conn.commit()
        conn.close()
    
    def is_banned(self, ip: str) -> bool:
        """Verifica se IP está banido"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Remove IPs expirados
        cursor.execute("DELETE FROM banned_ips WHERE expires_at IS NOT NULL AND expires_at < ?",
                      (datetime.now().isoformat(),))
        conn.commit()
        
        # Verifica se IP está banido
        cursor.execute("SELECT COUNT(*) FROM banned_ips WHERE ip_address = ?", (ip,))
        is_banned = cursor.fetchone()[0] > 0
        
        conn.close()
        return is_banned
    
    def ban_ip(self, ip: str, reason: str = None, banned_by: int = None, 
               expires_at: datetime = None) -> dict:
        """Bane um IP"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                INSERT OR REPLACE INTO banned_ips 
                (ip_address, reason, banned_by, banned_at, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, reason, banned_by, datetime.now().isoformat(),
                  expires_at.isoformat() if expires_at else None))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "ip": ip,
                "message": "IP banido com sucesso"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def unban_ip(self, ip: str) -> dict:
        """Remove ban de um IP"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("DELETE FROM banned_ips WHERE ip_address = ?", (ip,))
            removed = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "ip": ip,
                "removed": removed > 0,
                "message": "IP removido da lista de banidos" if removed else "IP não estava banido"
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def list_banned_ips(self) -> List[dict]:
        """Lista todos os IPs banidos"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT ip_address, reason, banned_by, banned_at, expires_at 
            FROM banned_ips
        """)
        
        rows = cursor.fetchall()
        conn.close()
        
        return [
            {
                "ip": row[0],
                "reason": row[1],
                "banned_by": row[2],
                "banned_at": row[3],
                "expires_at": row[4]
            }
            for row in rows
        ]


# Instância global
banned_ip_manager = BannedIPManager()


# ========== Schemas ==========

class BanIPRequest(BaseModel):
    """Schema para banir IP"""
    ip_address: str = Field(..., description="Endereço IP a banir")
    reason: Optional[str] = Field(None, description="Motivo do banimento")
    expires_at: Optional[datetime] = Field(None, description="Data de expiração do ban (opcional)")


class UnbanIPRequest(BaseModel):
    """Schema para remover ban de IP"""
    ip_address: str = Field(..., description="Endereço IP a desbanir")


class DeleteUserRequest(BaseModel):
    """Schema para deletar usuário"""
    user_id: int = Field(..., description="ID do usuário a deletar")
    delete_data: bool = Field(True, description="Deletar também os dados do usuário")


# ========== Rotas de Administração ==========

@router_admin.post("/ban-ip")
async def ban_ip(
    request: BanIPRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Bane um endereço IP específico
    Apenas administradores podem acessar
    """
    # Verificar se é admin
    from Tools.middleware import verify_admin
    verify_admin(current_user)
    
    result = banned_ip_manager.ban_ip(
        ip=request.ip_address,
        reason=request.reason,
        banned_by=current_user.id,
        expires_at=request.expires_at
    )
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"]
        )
    
    return result


@router_admin.post("/unban-ip")
async def unban_ip(
    request: UnbanIPRequest,
    current_user: User = Depends(get_current_user)
):
    """
    Remove ban de um endereço IP
    Apenas administradores podem acessar
    """
    result = banned_ip_manager.unban_ip(request.ip_address)
    
    if not result["success"]:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=result["error"]
        )
    
    return result


@router_admin.get("/banned-ips")
async def list_banned_ips(current_user: User = Depends(get_current_user)):
    """
    Lista todos os IPs banidos
    Apenas administradores podem acessar
    """
    banned_ips = banned_ip_manager.list_banned_ips()
    
    return {
        "total": len(banned_ips),
        "banned_ips": banned_ips
    }


@router_admin.delete("/user/{user_id}")
async def delete_user(
    user_id: int,
    delete_data: bool = True,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deleta um usuário do sistema
    Apenas administradores podem acessar
    
    Args:
        user_id: ID do usuário a deletar
        delete_data: Se True, deleta também os dados do usuário (pasta, modelos, etc)
    """
    # Verifica se usuário existe
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com ID {user_id} não encontrado"
        )
    
    # Não permite deletar admin principal
    if user.id == 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Não é possível deletar o administrador principal"
        )
    
    try:
        username = user.user
        user_directory = user.user_directory
        
        # Deletar dados do usuário se solicitado
        if delete_data and user_directory:
            import shutil
            user_data_path = Path(user_directory)
            if user_data_path.exists():
                shutil.rmtree(user_data_path)
        
        # Deletar usuário do banco
        db.delete(user)
        db.commit()
        
        return {
            "success": True,
            "user_id": user_id,
            "username": username,
            "data_deleted": delete_data,
            "message": f"Usuário '{username}' deletado com sucesso"
        }
        
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Erro ao deletar usuário: {str(e)}"
        )


@router_admin.get("/users")
async def list_all_users(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista todos os usuários do sistema
    Apenas administradores podem acessar
    """
    users = db.query(User).offset(skip).limit(limit).all()
    total = db.query(User).count()
    
    return {
        "total": total,
        "skip": skip,
        "limit": limit,
        "users": [
            {
                "id": u.id,
                "user": u.user,
                "email": u.email,
                "is_active": u.is_active,
                "created_at": u.created_at.isoformat() if u.created_at else None
            }
            for u in users
        ]
    }


@router_admin.post("/user/{user_id}/deactivate")
async def deactivate_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Desativa um usuário (sem deletar)
    Apenas administradores podem acessar
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com ID {user_id} não encontrado"
        )
    
    if user.id == 1:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Não é possível desativar o administrador principal"
        )
    
    user.is_active = False
    db.commit()
    
    return {
        "success": True,
        "user_id": user_id,
        "username": user.user,
        "message": f"Usuário '{user.user}' desativado"
    }


@router_admin.post("/user/{user_id}/activate")
async def activate_user(
    user_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Reativa um usuário desativado
    Apenas administradores podem acessar
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Usuário com ID {user_id} não encontrado"
        )
    
    user.is_active = True
    db.commit()
    
    return {
        "success": True,
        "user_id": user_id,
        "username": user.user,
        "message": f"Usuário '{user.user}' reativado"
    }
