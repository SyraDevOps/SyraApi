"""
Rotas de Notas Pessoais
"""
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Modelos.social_models import UserNote


router_notes = APIRouter(prefix="/notes", tags=["Notas"])


# ========== Schemas ==========

class NoteCreate(BaseModel):
    """Schema para criar nota"""
    titulo: str = Field(..., min_length=1, max_length=200)
    conteudo: str = Field(..., min_length=1)
    cor: str = Field("#FFEB3B", pattern="^#[0-9A-Fa-f]{6}$")
    fixada: bool = False


class NoteUpdate(BaseModel):
    """Schema para atualizar nota"""
    titulo: Optional[str] = Field(None, min_length=1, max_length=200)
    conteudo: Optional[str] = Field(None, min_length=1)
    cor: Optional[str] = Field(None, pattern="^#[0-9A-Fa-f]{6}$")
    fixada: Optional[bool] = None


class NoteResponse(BaseModel):
    """Schema de resposta"""
    id: int
    titulo: str
    conteudo: str
    cor: str
    fixada: bool
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


# ========== Rotas ==========

@router_notes.post("/", response_model=NoteResponse, status_code=status.HTTP_201_CREATED)
async def criar_nota(
    nota: NoteCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria uma nova nota"""
    
    nova_nota = UserNote(
        user_id=current_user.id,
        **nota.dict()
    )
    
    db.add(nova_nota)
    db.commit()
    db.refresh(nova_nota)
    
    return nova_nota


@router_notes.get("/", response_model=List[NoteResponse])
async def listar_notas(
    skip: int = 0,
    limit: int = 100,
    fixadas: Optional[bool] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista todas as notas do usuário"""
    
    query = db.query(UserNote).filter(UserNote.user_id == current_user.id)
    
    if fixadas is not None:
        query = query.filter(UserNote.fixada == fixadas)
    
    # Notas fixadas primeiro, depois por data de atualização
    query = query.order_by(
        UserNote.fixada.desc(),
        UserNote.updated_at.desc()
    )
    
    notas = query.offset(skip).limit(limit).all()
    
    return notas


@router_notes.get("/{nota_id}", response_model=NoteResponse)
async def obter_nota(
    nota_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém uma nota específica"""
    
    nota = db.query(UserNote).filter(
        UserNote.id == nota_id,
        UserNote.user_id == current_user.id
    ).first()
    
    if not nota:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nota não encontrada"
        )
    
    return nota


@router_notes.put("/{nota_id}", response_model=NoteResponse)
async def atualizar_nota(
    nota_id: int,
    dados: NoteUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza uma nota existente"""
    
    nota = db.query(UserNote).filter(
        UserNote.id == nota_id,
        UserNote.user_id == current_user.id
    ).first()
    
    if not nota:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nota não encontrada"
        )
    
    # Atualizar campos fornecidos
    update_data = dados.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(nota, field, value)
    
    nota.updated_at = datetime.now()
    
    db.commit()
    db.refresh(nota)
    
    return nota


@router_notes.delete("/{nota_id}")
async def deletar_nota(
    nota_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta uma nota"""
    
    nota = db.query(UserNote).filter(
        UserNote.id == nota_id,
        UserNote.user_id == current_user.id
    ).first()
    
    if not nota:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nota não encontrada"
        )
    
    db.delete(nota)
    db.commit()
    
    return {"success": True, "message": "Nota deletada"}


@router_notes.post("/{nota_id}/toggle-fixar")
async def toggle_fixar_nota(
    nota_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Alterna status de fixação da nota"""
    
    nota = db.query(UserNote).filter(
        UserNote.id == nota_id,
        UserNote.user_id == current_user.id
    ).first()
    
    if not nota:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Nota não encontrada"
        )
    
    nota.fixada = not nota.fixada
    nota.updated_at = datetime.now()
    
    db.commit()
    
    return {
        "success": True,
        "fixada": nota.fixada,
        "message": "Nota fixada" if nota.fixada else "Nota desfixada"
    }
