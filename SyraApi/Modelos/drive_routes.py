"""
Rotas de Drive - Upload e Download de arquivos do usuário
"""
from fastapi import APIRouter, Depends, HTTPException, status, UploadFile, File
from fastapi.responses import FileResponse as StarletteFileResponse
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel
from datetime import datetime
import os
import uuid
from pathlib import Path

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Modelos.social_models import UserFile


router_drive = APIRouter(prefix="/drive", tags=["Drive"])


# ========== Configurações ==========

MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
ALLOWED_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.txt', '.jpg', '.jpeg', '.png', '.gif',
    '.mp4', '.mp3', '.zip', '.rar', '.xlsx', '.xls', '.ppt', '.pptx'
}


# ========== Schemas ==========

class FileResponseSchema(BaseModel):
    """Schema de resposta de arquivo"""
    id: int
    filename: str
    original_filename: str
    file_size: int
    mime_type: Optional[str]
    uploaded_at: datetime
    
    class Config:
        from_attributes = True


# ========== Funções auxiliares ==========

def get_user_drive_path(user_id: int) -> Path:
    """Obtém caminho do drive do usuário"""
    drive_path = Path(f"/root/SyraApi/UserData/user_{user_id}/drive")
    drive_path.mkdir(parents=True, exist_ok=True)
    return drive_path


def validate_file(file: UploadFile):
    """Valida arquivo antes do upload"""
    # Verificar extensão
    ext = Path(file.filename).suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Tipo de arquivo não permitido. Extensões aceitas: {', '.join(ALLOWED_EXTENSIONS)}"
        )


# ========== Rotas ==========

@router_drive.post("/upload", response_model=FileResponseSchema, status_code=status.HTTP_201_CREATED)
async def upload_file(
    file: UploadFile = File(...),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Faz upload de um arquivo para o drive do usuário
    Tamanho máximo: 100MB
    """
    
    # Validar arquivo
    validate_file(file)
    
    # Ler conteúdo
    contents = await file.read()
    file_size = len(contents)
    
    if file_size > MAX_FILE_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"Arquivo muito grande. Tamanho máximo: {MAX_FILE_SIZE / (1024*1024)}MB"
        )
    
    # Gerar nome único
    ext = Path(file.filename).suffix
    unique_filename = f"{uuid.uuid4()}{ext}"
    
    # Caminho do arquivo
    drive_path = get_user_drive_path(current_user.id)
    file_path = drive_path / unique_filename
    
    # Salvar arquivo
    with open(file_path, "wb") as f:
        f.write(contents)
    
    # Registrar no banco
    user_file = UserFile(
        user_id=current_user.id,
        filename=unique_filename,
        original_filename=file.filename,
        file_path=str(file_path),
        file_size=file_size,
        mime_type=file.content_type
    )
    
    db.add(user_file)
    db.commit()
    db.refresh(user_file)
    
    return user_file


@router_drive.get("/files", response_model=List[FileResponseSchema])
async def listar_arquivos(
    skip: int = 0,
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista todos os arquivos do usuário"""
    
    files = db.query(UserFile).filter(
        UserFile.user_id == current_user.id
    ).order_by(
        UserFile.uploaded_at.desc()
    ).offset(skip).limit(limit).all()
    
    return files


@router_drive.get("/download/{file_id}")
async def download_file(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Baixa um arquivo do drive"""
    
    user_file = db.query(UserFile).filter(
        UserFile.id == file_id,
        UserFile.user_id == current_user.id
    ).first()
    
    if not user_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Arquivo não encontrado"
        )
    
    file_path = Path(user_file.file_path)
    
    if not file_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Arquivo não encontrado no sistema"
        )
    
    return StarletteFileResponse(
        path=str(file_path),
        filename=user_file.original_filename,
        media_type=user_file.mime_type
    )


@router_drive.delete("/{file_id}")
async def deletar_arquivo(
    file_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta um arquivo do drive"""
    
    user_file = db.query(UserFile).filter(
        UserFile.id == file_id,
        UserFile.user_id == current_user.id
    ).first()
    
    if not user_file:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Arquivo não encontrado"
        )
    
    # Deletar arquivo físico
    file_path = Path(user_file.file_path)
    if file_path.exists():
        file_path.unlink()
    
    # Deletar registro
    db.delete(user_file)
    db.commit()
    
    return {"success": True, "message": "Arquivo deletado"}


@router_drive.get("/stats")
async def estatisticas_drive(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Estatísticas do drive do usuário"""
    
    files = db.query(UserFile).filter(
        UserFile.user_id == current_user.id
    ).all()
    
    total_files = len(files)
    total_size = sum(f.file_size for f in files)
    
    # Agrupar por tipo
    tipos = {}
    for f in files:
        ext = Path(f.filename).suffix
        tipos[ext] = tipos.get(ext, 0) + 1
    
    return {
        "total_arquivos": total_files,
        "tamanho_total_bytes": total_size,
        "tamanho_total_mb": round(total_size / (1024*1024), 2),
        "tipos_arquivo": tipos,
        "limite_mb": MAX_FILE_SIZE / (1024*1024)
    }
