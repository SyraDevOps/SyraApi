"""
Rotas de Feed Social - Posts, Comentários, Curtidas
Posts expiram em 2 dias automaticamente
"""
from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import or_, and_
from typing import List, Optional
from pydantic import BaseModel, Field
from datetime import datetime, timedelta

from DB.database import get_db
from Modelos.user import User
from Modelos.auth import get_current_user
from Modelos.social_models import Post, Comentario, PostLike
from Modelos.location import UserBond  # Para verificar vínculos


router_feed = APIRouter(prefix="/feed", tags=["Feed Social"])


# ========== Schemas ==========

class PostCreate(BaseModel):
    """Schema para criar post"""
    conteudo: str = Field(..., min_length=1, max_length=5000)
    hashtags: Optional[str] = Field(None, max_length=500)
    imagem_url: Optional[str] = None


class ComentarioCreate(BaseModel):
    """Schema para criar comentário"""
    conteudo: str = Field(..., min_length=1, max_length=1000)


class PostResponse(BaseModel):
    """Schema de resposta de post"""
    id: int
    user_id: int
    username: str
    conteudo: str
    hashtags: Optional[str]
    imagem_url: Optional[str]
    curtidas: int
    comentarios_count: int
    encaminhamentos: int
    created_at: datetime
    expires_at: datetime
    user_curtiu: bool = False
    
    class Config:
        from_attributes = True


class ComentarioResponse(BaseModel):
    """Schema de resposta de comentário"""
    id: int
    post_id: int
    user_id: int
    username: str
    conteudo: str
    created_at: datetime
    
    class Config:
        from_attributes = True


# ========== Funções auxiliares ==========

async def limpar_posts_expirados(db: Session):
    """Remove posts expirados (mais de 2 dias)"""
    agora = datetime.now()
    posts_expirados = db.query(Post).filter(Post.expires_at <= agora).all()
    
    for post in posts_expirados:
        db.delete(post)
    
    if posts_expirados:
        db.commit()
    
    return len(posts_expirados)


def verificar_vinculo_ou_oficial(user_id: int, post_user_id: int, db: Session) -> bool:
    """
    Verifica se usuário tem vínculo com autor do post ou se é post oficial da SyraDevOps
    """
    # Usuário vendo próprio post
    if user_id == post_user_id:
        return True
    
    # Post oficial da SyraDevOps (user_id 1)
    if post_user_id == 1:
        return True
    
    # Verificar vínculo mútuo
    vinculo = db.query(UserBond).filter(
        or_(
            and_(UserBond.user_id_1 == user_id, UserBond.user_id_2 == post_user_id),
            and_(UserBond.user_id_1 == post_user_id, UserBond.user_id_2 == user_id)
        ),
        UserBond.status == "accepted"
    ).first()
    
    return vinculo is not None


# ========== Rotas ==========

@router_feed.post("/", response_model=PostResponse, status_code=status.HTTP_201_CREATED)
async def criar_post(
    post: PostCreate,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria um novo post no feed"""
    
    # Limpar posts expirados em background
    background_tasks.add_task(limpar_posts_expirados, db)
    
    novo_post = Post(
        user_id=current_user.id,
        **post.dict()
    )
    
    db.add(novo_post)
    db.commit()
    db.refresh(novo_post)
    
    # Criar resposta manualmente
    return {
        "id": novo_post.id,
        "user_id": novo_post.user_id,
        "username": current_user.user,
        "conteudo": novo_post.conteudo,
        "hashtags": novo_post.hashtags,
        "imagem_url": novo_post.imagem_url,
        "curtidas": novo_post.curtidas,
        "comentarios_count": novo_post.comentarios_count,
        "encaminhamentos": novo_post.encaminhamentos,
        "created_at": novo_post.created_at,
        "expires_at": novo_post.expires_at,
        "user_curtiu": False
    }


@router_feed.get("/", response_model=List[PostResponse])
async def listar_feed(
    skip: int = 0,
    limit: int = 50,
    hashtag: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Lista posts do feed
    Mostra apenas posts de:
    - Usuários com vínculo aceito
    - Posts oficiais da SyraDevOps (user_id 1)
    - Próprios posts do usuário
    """
    
    agora = datetime.now()
    
    # Buscar vínculos aceitos
    vinculos_query = db.query(UserBond).filter(
        or_(
            UserBond.user_id_1 == current_user.id,
            UserBond.user_id_2 == current_user.id
        ),
        UserBond.status == "accepted"
    ).all()
    
    # IDs de usuários vinculados
    vinculados_ids = set()
    for v in vinculos_query:
        if v.user_id_1 == current_user.id:
            vinculados_ids.add(v.user_id_2)
        else:
            vinculados_ids.add(v.user_id_1)
    
    # Adicionar ID do próprio usuário e da SyraDevOps
    vinculados_ids.add(current_user.id)
    vinculados_ids.add(1)  # SyraDevOps oficial
    
    # Query de posts
    query = db.query(Post).filter(
        Post.user_id.in_(vinculados_ids),
        Post.expires_at > agora
    )
    
    # Filtro por hashtag
    if hashtag:
        query = query.filter(Post.hashtags.like(f"%{hashtag}%"))
    
    posts = query.order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    
    # Adicionar informações extras
    response_posts = []
    for post in posts:
        user = db.query(User).filter(User.id == post.user_id).first()
        
        # Verificar se usuário curtiu
        curtida = db.query(PostLike).filter(
            PostLike.post_id == post.id,
            PostLike.user_id == current_user.id
        ).first()
        
        response_posts.append({
            "id": post.id,
            "user_id": post.user_id,
            "username": user.user if user else "Desconhecido",
            "conteudo": post.conteudo,
            "hashtags": post.hashtags,
            "imagem_url": post.imagem_url,
            "curtidas": post.curtidas,
            "comentarios_count": post.comentarios_count,
            "encaminhamentos": post.encaminhamentos,
            "created_at": post.created_at,
            "expires_at": post.expires_at,
            "user_curtiu": curtida is not None
        })
    
    return response_posts


@router_feed.get("/oficial", response_model=List[PostResponse])
async def feed_oficial(
    skip: int = 0,
    limit: int = 20,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Feed oficial da SyraDevOps (apenas posts do admin)"""
    
    agora = datetime.now()
    
    posts = db.query(Post).filter(
        Post.user_id == 1,  # Apenas posts oficiais
        Post.expires_at > agora
    ).order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    
    response_posts = []
    for post in posts:
        curtida = db.query(PostLike).filter(
            PostLike.post_id == post.id,
            PostLike.user_id == current_user.id
        ).first()
        
        response_posts.append({
            "id": post.id,
            "user_id": post.user_id,
            "username": "SyraDevOps",
            "conteudo": post.conteudo,
            "hashtags": post.hashtags,
            "imagem_url": post.imagem_url,
            "curtidas": post.curtidas,
            "comentarios_count": post.comentarios_count,
            "encaminhamentos": post.encaminhamentos,
            "created_at": post.created_at,
            "expires_at": post.expires_at,
            "user_curtiu": curtida is not None
        })
    
    return response_posts


@router_feed.get("/{post_id}", response_model=PostResponse)
async def obter_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém detalhes de um post específico"""
    
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post não encontrado"
        )
    
    # Verificar permissão
    if not verificar_vinculo_ou_oficial(current_user.id, post.user_id, db):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Você não tem permissão para ver este post"
        )
    
    user = db.query(User).filter(User.id == post.user_id).first()
    curtida = db.query(PostLike).filter(
        PostLike.post_id == post.id,
        PostLike.user_id == current_user.id
    ).first()
    
    return {
        "id": post.id,
        "user_id": post.user_id,
        "username": user.user if user else "Desconhecido",
        "conteudo": post.conteudo,
        "hashtags": post.hashtags,
        "imagem_url": post.imagem_url,
        "curtidas": post.curtidas,
        "comentarios_count": post.comentarios_count,
        "encaminhamentos": post.encaminhamentos,
        "created_at": post.created_at,
        "expires_at": post.expires_at,
        "user_curtiu": curtida is not None
    }


@router_feed.delete("/{post_id}")
async def deletar_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta um post (apenas o autor pode deletar)"""
    
    post = db.query(Post).filter(
        Post.id == post_id,
        Post.user_id == current_user.id
    ).first()
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post não encontrado ou você não tem permissão para deletá-lo"
        )
    
    db.delete(post)
    db.commit()
    
    return {"success": True, "message": "Post deletado"}


@router_feed.post("/{post_id}/curtir")
async def curtir_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Curte um post"""
    
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post não encontrado"
        )
    
    # Verificar se já curtiu
    curtida_existente = db.query(PostLike).filter(
        PostLike.post_id == post_id,
        PostLike.user_id == current_user.id
    ).first()
    
    if curtida_existente:
        # Remover curtida
        db.delete(curtida_existente)
        post.curtidas = max(0, post.curtidas - 1)
        db.commit()
        
        return {"success": True, "curtiu": False, "total_curtidas": post.curtidas}
    else:
        # Adicionar curtida
        nova_curtida = PostLike(
            post_id=post_id,
            user_id=current_user.id
        )
        db.add(nova_curtida)
        post.curtidas += 1
        db.commit()
        
        return {"success": True, "curtiu": True, "total_curtidas": post.curtidas}


@router_feed.post("/{post_id}/comentar", response_model=ComentarioResponse)
async def comentar_post(
    post_id: int,
    comentario: ComentarioCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Adiciona um comentário ao post"""
    
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post não encontrado"
        )
    
    novo_comentario = Comentario(
        post_id=post_id,
        user_id=current_user.id,
        conteudo=comentario.conteudo
    )
    
    db.add(novo_comentario)
    post.comentarios_count += 1
    db.commit()
    db.refresh(novo_comentario)
    
    return {
        "id": novo_comentario.id,
        "post_id": novo_comentario.post_id,
        "user_id": novo_comentario.user_id,
        "username": current_user.user,
        "conteudo": novo_comentario.conteudo,
        "created_at": novo_comentario.created_at
    }


@router_feed.get("/{post_id}/comentarios", response_model=List[ComentarioResponse])
async def listar_comentarios(
    post_id: int,
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lista comentários de um post"""
    
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post não encontrado"
        )
    
    comentarios = db.query(Comentario).filter(
        Comentario.post_id == post_id
    ).order_by(Comentario.created_at).offset(skip).limit(limit).all()
    
    response_comentarios = []
    for com in comentarios:
        user = db.query(User).filter(User.id == com.user_id).first()
        response_comentarios.append({
            "id": com.id,
            "post_id": com.post_id,
            "user_id": com.user_id,
            "username": user.user if user else "Desconhecido",
            "conteudo": com.conteudo,
            "created_at": com.created_at
        })
    
    return response_comentarios


@router_feed.post("/{post_id}/encaminhar")
async def encaminhar_post(
    post_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Encaminha/compartilha um post"""
    
    post = db.query(Post).filter(Post.id == post_id).first()
    
    if not post:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Post não encontrado"
        )
    
    post.encaminhamentos += 1
    db.commit()
    
    return {
        "success": True,
        "total_encaminhamentos": post.encaminhamentos,
        "message": "Post encaminhado"
    }


@router_feed.get("/hashtag/{hashtag}", response_model=List[PostResponse])
async def buscar_por_hashtag(
    hashtag: str,
    skip: int = 0,
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Busca posts por hashtag"""
    
    agora = datetime.now()
    
    posts = db.query(Post).filter(
        Post.hashtags.like(f"%{hashtag}%"),
        Post.expires_at > agora
    ).order_by(Post.created_at.desc()).offset(skip).limit(limit).all()
    
    response_posts = []
    for post in posts:
        # Verificar permissão
        if not verificar_vinculo_ou_oficial(current_user.id, post.user_id, db):
            continue
        
        user = db.query(User).filter(User.id == post.user_id).first()
        curtida = db.query(PostLike).filter(
            PostLike.post_id == post.id,
            PostLike.user_id == current_user.id
        ).first()
        
        response_posts.append({
            "id": post.id,
            "user_id": post.user_id,
            "username": user.user if user else "Desconhecido",
            "conteudo": post.conteudo,
            "hashtags": post.hashtags,
            "imagem_url": post.imagem_url,
            "curtidas": post.curtidas,
            "comentarios_count": post.comentarios_count,
            "encaminhamentos": post.encaminhamentos,
            "created_at": post.created_at,
            "expires_at": post.expires_at,
            "user_curtiu": curtida is not None
        })
    
    return response_posts
