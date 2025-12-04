"""
Rotas de Agenda - Compromissos e notificações
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timedelta

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Modelos.agenda import Compromisso


router_agenda = APIRouter(prefix="/agenda", tags=["Agenda"])


# ========== Schemas ==========

class CompromissoCreate(BaseModel):
    """Schema para criar compromisso"""
    titulo: str = Field(..., min_length=1, max_length=200)
    descricao: Optional[str] = None
    data_hora: datetime
    duracao_minutos: int = Field(60, ge=1, le=1440)
    local: Optional[str] = None
    lembrete_minutos: int = Field(30, ge=0, le=10080)  # Até 7 dias antes


class CompromissoUpdate(BaseModel):
    """Schema para atualizar compromisso"""
    titulo: Optional[str] = Field(None, min_length=1, max_length=200)
    descricao: Optional[str] = None
    data_hora: Optional[datetime] = None
    duracao_minutos: Optional[int] = Field(None, ge=1, le=1440)
    local: Optional[str] = None
    lembrete_minutos: Optional[int] = Field(None, ge=0, le=10080)
    concluido: Optional[bool] = None


class CompromissoResponse(BaseModel):
    """Schema de resposta"""
    id: int
    titulo: str
    descricao: Optional[str]
    data_hora: datetime
    duracao_minutos: int
    local: Optional[str]
    lembrete_minutos: int
    notificado: bool
    concluido: bool
    created_at: datetime
    
    class Config:
        from_attributes = True


# ========== Rotas ==========

@router_agenda.post("/", response_model=CompromissoResponse, status_code=status.HTTP_201_CREATED)
async def criar_compromisso(
    compromisso: CompromissoCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria um novo compromisso na agenda"""
    
    # Validar data no futuro
    if compromisso.data_hora <= datetime.now():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Data do compromisso deve ser no futuro"
        )
    
    novo_compromisso = Compromisso(
        user_id=current_user.id,
        **compromisso.dict()
    )
    
    db.add(novo_compromisso)
    db.commit()
    db.refresh(novo_compromisso)
    
    return novo_compromisso


@router_agenda.get("/", response_model=List[CompromissoResponse])
async def listar_compromissos(
    skip: int = 0,
    limit: int = 100,
    concluidos: Optional[bool] = None,
    data_inicio: Optional[datetime] = None,
    data_fim: Optional[datetime] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista compromissos do usuário com filtros"""
    
    query = db.query(Compromisso).filter(Compromisso.user_id == current_user.id)
    
    # Filtros
    if concluidos is not None:
        query = query.filter(Compromisso.concluido == concluidos)
    
    if data_inicio:
        query = query.filter(Compromisso.data_hora >= data_inicio)
    
    if data_fim:
        query = query.filter(Compromisso.data_hora <= data_fim)
    
    # Ordenar por data
    query = query.order_by(Compromisso.data_hora)
    
    compromissos = query.offset(skip).limit(limit).all()
    
    return compromissos


@router_agenda.get("/proximos", response_model=List[CompromissoResponse])
async def proximos_compromissos(
    dias: int = 7,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista próximos compromissos (próximos X dias)"""
    
    agora = datetime.now()
    limite = agora + timedelta(days=dias)
    
    compromissos = db.query(Compromisso).filter(
        Compromisso.user_id == current_user.id,
        Compromisso.data_hora >= agora,
        Compromisso.data_hora <= limite,
        Compromisso.concluido == False
    ).order_by(Compromisso.data_hora).all()
    
    return compromissos


@router_agenda.get("/{compromisso_id}", response_model=CompromissoResponse)
async def obter_compromisso(
    compromisso_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém detalhes de um compromisso específico"""
    
    compromisso = db.query(Compromisso).filter(
        Compromisso.id == compromisso_id,
        Compromisso.user_id == current_user.id
    ).first()
    
    if not compromisso:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compromisso não encontrado"
        )
    
    return compromisso


@router_agenda.put("/{compromisso_id}", response_model=CompromissoResponse)
async def atualizar_compromisso(
    compromisso_id: int,
    dados: CompromissoUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza um compromisso existente"""
    
    compromisso = db.query(Compromisso).filter(
        Compromisso.id == compromisso_id,
        Compromisso.user_id == current_user.id
    ).first()
    
    if not compromisso:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compromisso não encontrado"
        )
    
    # Atualizar campos fornecidos
    update_data = dados.dict(exclude_unset=True)
    for field, value in update_data.items():
        setattr(compromisso, field, value)
    
    compromisso.updated_at = datetime.now()
    
    db.commit()
    db.refresh(compromisso)
    
    return compromisso


@router_agenda.delete("/{compromisso_id}")
async def deletar_compromisso(
    compromisso_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta um compromisso"""
    
    compromisso = db.query(Compromisso).filter(
        Compromisso.id == compromisso_id,
        Compromisso.user_id == current_user.id
    ).first()
    
    if not compromisso:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Compromisso não encontrado"
        )
    
    db.delete(compromisso)
    db.commit()
    
    return {"success": True, "message": "Compromisso deletado"}


@router_agenda.get("/notificacoes/pendentes")
async def verificar_notificacoes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Verifica compromissos que precisam de notificação"""
    
    agora = datetime.now()
    
    # Buscar compromissos não notificados que estão no período de lembrete
    compromissos = db.query(Compromisso).filter(
        Compromisso.user_id == current_user.id,
        Compromisso.notificado == False,
        Compromisso.concluido == False
    ).all()
    
    pendentes = []
    for comp in compromissos:
        tempo_lembrete = comp.data_hora - timedelta(minutes=comp.lembrete_minutos)
        if agora >= tempo_lembrete:
            pendentes.append({
                "id": comp.id,
                "titulo": comp.titulo,
                "data_hora": comp.data_hora,
                "minutos_restantes": int((comp.data_hora - agora).total_seconds() / 60)
            })
            
            # Marcar como notificado
            comp.notificado = True
    
    if pendentes:
        db.commit()
    
    return {
        "total": len(pendentes),
        "notificacoes": pendentes
    }
