from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from typing import List, Optional
from datetime import datetime, timedelta
import json

from DB.database import get_db
from Modelos.user import User
from Modelos.location import LocationLive, LocationHistory, UserBond, MeetingInvite
from Modelos.notification import Notification
from Modelos.location_schemas import (
    LocationShare,
    LocationUpdate,
    LocationResponse,
    NearbyUser,
    NearbyUsersResponse,
    BondRequest,
    BondResponse,
    BondAction,
    MeetingInviteCreate,
    MeetingInviteResponse,
    MeetingInviteAction,
    MeetingWithLocation
)
from Modelos.auth import get_current_user
from Tools.geolocation import (
    haversine_distance,
    get_bounding_box,
    calculate_expiration_time,
    is_expired,
    validate_coordinates
)

# Routers
router = APIRouter(prefix="/location", tags=["Localização"])
router_meeting = APIRouter(prefix="/meeting", tags=["Encontros"])

# ═══════════════════════════════════════════════════════════
# ROTAS DE LOCALIZAÇÃO
# ═══════════════════════════════════════════════════════════

@router.post("/share", response_model=LocationResponse, status_code=201)
async def share_location(
    location_data: LocationShare,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Compartilha sua localização em tempo real"""
    
    if not validate_coordinates(location_data.latitude, location_data.longitude):
        raise HTTPException(400, "Coordenadas inválidas")
    
    expires_at = calculate_expiration_time(location_data.duration_minutes)
    
    db.query(LocationLive).filter(
        LocationLive.user_id == current_user.id,
        LocationLive.is_active == True
    ).update({"is_active": False})
    
    new_location = LocationLive(
        user_id=current_user.id,
        latitude=location_data.latitude,
        longitude=location_data.longitude,
        accuracy=location_data.accuracy,
        expires_at=expires_at,
        visibility_radius=location_data.visibility_radius,
        is_public=location_data.is_public,
        device_info=location_data.device_info,
        is_active=True
    )
    
    db.add(new_location)
    db.commit()
    db.refresh(new_location)
    
    return LocationResponse.from_orm(new_location)


@router.patch("/update", response_model=LocationResponse)
async def update_location(
    location_data: LocationUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Atualiza sua localização"""
    
    if not validate_coordinates(location_data.latitude, location_data.longitude):
        raise HTTPException(400, "Coordenadas inválidas")
    
    active_location = db.query(LocationLive).filter(
        LocationLive.user_id == current_user.id,
        LocationLive.is_active == True
    ).first()
    
    if not active_location:
        raise HTTPException(404, "Nenhuma localização ativa")
    
    if is_expired(active_location.expires_at):
        active_location.is_active = False
        db.commit()
        raise HTTPException(410, "Compartilhamento expirado")
    
    active_location.latitude = location_data.latitude
    active_location.longitude = location_data.longitude
    if location_data.accuracy:
        active_location.accuracy = location_data.accuracy
    
    db.commit()
    db.refresh(active_location)
    
    return LocationResponse.from_orm(active_location)


@router.get("/my", response_model=Optional[LocationResponse])
async def get_my_location(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém sua localização atual"""
    
    location = db.query(LocationLive).filter(
        LocationLive.user_id == current_user.id,
        LocationLive.is_active == True
    ).first()
    
    if not location:
        return None
    
    if is_expired(location.expires_at):
        history = LocationHistory(
            user_id=location.user_id,
            latitude=location.latitude,
            longitude=location.longitude,
            shared_at=location.created_at,
            expired_at=location.expires_at
        )
        db.add(history)
        location.is_active = False
        db.commit()
        return None
    
    return LocationResponse.from_orm(location)


@router.delete("/stop")
async def stop_sharing(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Para compartilhamento"""
    
    location = db.query(LocationLive).filter(
        LocationLive.user_id == current_user.id,
        LocationLive.is_active == True
    ).first()
    
    if not location:
        raise HTTPException(404, "Nenhuma localização ativa")
    
    history = LocationHistory(
        user_id=location.user_id,
        latitude=location.latitude,
        longitude=location.longitude,
        shared_at=location.created_at,
        expired_at=datetime.utcnow()
    )
    db.add(history)
    location.is_active = False
    db.commit()
    
    return {"message": "Compartilhamento parado"}


@router.get("/nearby", response_model=NearbyUsersResponse)
async def get_nearby_users(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    radius_meters: float = Query(1000, ge=100, le=50000)
):
    """Busca usuários próximos"""
    
    my_location = db.query(LocationLive).filter(
        LocationLive.user_id == current_user.id,
        LocationLive.is_active == True
    ).first()
    
    if not my_location:
        raise HTTPException(400, "Você precisa estar compartilhando sua localização")
    
    if is_expired(my_location.expires_at):
        my_location.is_active = False
        db.commit()
        raise HTTPException(410, "Seu compartilhamento expirou")
    
    min_lat, max_lat, min_lon, max_lon = get_bounding_box(
        my_location.latitude,
        my_location.longitude,
        radius_meters
    )
    
    bonds = db.query(UserBond).filter(
        or_(UserBond.user_id_1 == current_user.id, UserBond.user_id_2 == current_user.id),
        UserBond.status == "accepted"
    ).all()
    
    bonded_user_ids = set()
    for bond in bonds:
        bonded_user_ids.add(bond.user_id_1 if bond.user_id_2 == current_user.id else bond.user_id_2)
    
    nearby_locations = db.query(LocationLive, User).join(
        User, LocationLive.user_id == User.id
    ).filter(
        LocationLive.user_id != current_user.id,
        LocationLive.is_active == True,
        LocationLive.latitude >= min_lat,
        LocationLive.latitude <= max_lat,
        LocationLive.longitude >= min_lon,
        LocationLive.longitude <= max_lon,
        LocationLive.expires_at > datetime.utcnow()
    ).all()
    
    nearby_users = []
    
    for location, user in nearby_locations:
        if not location.is_public and user.id not in bonded_user_ids:
            continue
        
        distance = haversine_distance(
            my_location.latitude,
            my_location.longitude,
            location.latitude,
            location.longitude
        )
        
        if distance <= radius_meters:
            nearby_users.append(NearbyUser(
                user_id=user.id,
                username=user.user,
                distance_meters=round(distance, 2),
                latitude=location.latitude,
                longitude=location.longitude,
                last_update=location.created_at
            ))
    
    nearby_users.sort(key=lambda x: x.distance_meters)
    
    return NearbyUsersResponse(
        nearby_users=nearby_users,
        total_count=len(nearby_users),
        search_radius=radius_meters
    )


# ═══════════════════════════════════════════════════════════
# VÍNCULOS
# ═══════════════════════════════════════════════════════════

@router.post("/bond/request", response_model=BondResponse, status_code=201)
async def request_bond(
    bond_data: BondRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Solicita vínculo com outro usuário"""
    
    target_user = db.query(User).filter(User.id == bond_data.target_user_id).first()
    if not target_user:
        raise HTTPException(404, "Usuário não encontrado")
    
    if target_user.id == current_user.id:
        raise HTTPException(400, "Não pode criar vínculo consigo mesmo")
    
    existing = db.query(UserBond).filter(
        or_(
            and_(UserBond.user_id_1 == current_user.id, UserBond.user_id_2 == target_user.id),
            and_(UserBond.user_id_1 == target_user.id, UserBond.user_id_2 == current_user.id)
        )
    ).first()
    
    if existing:
        if existing.status == "accepted":
            raise HTTPException(400, "Vínculo já existe")
        elif existing.status == "pending":
            raise HTTPException(400, "Solicitação pendente")
    
    new_bond = UserBond(
        user_id_1=current_user.id,
        user_id_2=target_user.id,
        status="pending",
        initiated_by=current_user.id,
        bond_type=bond_data.bond_type,
        notes=bond_data.notes
    )
    
    db.add(new_bond)
    db.commit()
    db.refresh(new_bond)
    
    notif = Notification(
        notification_type="user_specific",
        user_id=target_user.id,
        title="Nova solicitação de vínculo",
        message=f"{current_user.user} enviou solicitação de vínculo",
        priority="normal",
        category="bond",
        created_by=current_user.id
    )
    db.add(notif)
    db.commit()
    
    return BondResponse.from_orm(new_bond)


@router.patch("/bond/{bond_id}/respond", response_model=BondResponse)
async def respond_bond(
    bond_id: str,
    action: BondAction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Responde solicitação de vínculo"""
    
    bond = db.query(UserBond).filter(UserBond.id == bond_id).first()
    
    if not bond:
        raise HTTPException(404, "Solicitação não encontrada")
    
    if bond.user_id_2 != current_user.id:
        raise HTTPException(403, "Sem permissão")
    
    if bond.status != "pending":
        raise HTTPException(400, f"Já respondida: {bond.status}")
    
    if action.action == "accept":
        bond.status = "accepted"
        bond.accepted_at = datetime.utcnow()
        msg = "aceitou seu pedido de vínculo"
    else:
        bond.status = "rejected"
        msg = "rejeitou seu pedido de vínculo"
    
    notif = Notification(
        notification_type="user_specific",
        user_id=bond.user_id_1,
        title=f"Vínculo {action.action}o",
        message=f"{current_user.user} {msg}",
        priority="normal",
        category="bond",
        created_by=current_user.id
    )
    db.add(notif)
    
    db.commit()
    db.refresh(bond)
    
    return BondResponse.from_orm(bond)


@router.get("/bonds", response_model=List[BondResponse])
async def list_bonds(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(None)
):
    """Lista vínculos"""
    
    query = db.query(UserBond).filter(
        or_(UserBond.user_id_1 == current_user.id, UserBond.user_id_2 == current_user.id)
    )
    
    if status_filter:
        query = query.filter(UserBond.status == status_filter)
    
    bonds = query.order_by(UserBond.created_at.desc()).all()
    
    return [BondResponse.from_orm(b) for b in bonds]


@router.delete("/bond/{bond_id}")
async def delete_bond(
    bond_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Remove vínculo"""
    
    bond = db.query(UserBond).filter(UserBond.id == bond_id).first()
    
    if not bond:
        raise HTTPException(404, "Vínculo não encontrado")
    
    if bond.user_id_1 != current_user.id and bond.user_id_2 != current_user.id:
        raise HTTPException(403, "Sem permissão")
    
    db.delete(bond)
    db.commit()
    
    return {"message": "Vínculo removido"}


# ═══════════════════════════════════════════════════════════
# ENCONTROS
# ═══════════════════════════════════════════════════════════

@router_meeting.post("/invite", response_model=MeetingInviteResponse, status_code=201)
async def create_invite(
    invite_data: MeetingInviteCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Cria convite de encontro"""
    
    receiver = db.query(User).filter(User.id == invite_data.receiver_id).first()
    if not receiver:
        raise HTTPException(404, "Usuário não encontrado")
    
    if receiver.id == current_user.id:
        raise HTTPException(400, "Não pode convidar a si mesmo")
    
    expires_at = datetime.utcnow() + timedelta(hours=invite_data.duration_hours)
    
    invite = MeetingInvite(
        sender_id=current_user.id,
        receiver_id=invite_data.receiver_id,
        meeting_latitude=invite_data.meeting_latitude,
        meeting_longitude=invite_data.meeting_longitude,
        meeting_place_name=invite_data.meeting_place_name,
        message=invite_data.message,
        status="pending",
        expires_at=expires_at,
        share_sender_location=invite_data.share_sender_location
    )
    
    db.add(invite)
    db.commit()
    db.refresh(invite)
    
    msg = f"{current_user.user} convidou você para um encontro!"
    if invite_data.meeting_place_name:
        msg += f" Local: {invite_data.meeting_place_name}"
    
    notif = Notification(
        notification_type="user_specific",
        user_id=receiver.id,
        title="Novo convite de encontro!",
        message=msg,
        priority="high",
        category="meeting",
        created_by=current_user.id
    )
    db.add(notif)
    db.commit()
    
    return MeetingInviteResponse.from_orm(invite)


@router_meeting.get("/invites/received", response_model=List[MeetingInviteResponse])
async def get_received(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(None)
):
    """Lista convites recebidos"""
    
    query = db.query(MeetingInvite).filter(MeetingInvite.receiver_id == current_user.id)
    
    if status_filter:
        query = query.filter(MeetingInvite.status == status_filter)
    
    invites = query.order_by(MeetingInvite.created_at.desc()).all()
    
    for inv in invites:
        if inv.status == "pending" and datetime.utcnow() > inv.expires_at:
            inv.status = "expired"
    
    db.commit()
    
    return [MeetingInviteResponse.from_orm(i) for i in invites]


@router_meeting.get("/invites/sent", response_model=List[MeetingInviteResponse])
async def get_sent(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    status_filter: Optional[str] = Query(None)
):
    """Lista convites enviados"""
    
    query = db.query(MeetingInvite).filter(MeetingInvite.sender_id == current_user.id)
    
    if status_filter:
        query = query.filter(MeetingInvite.status == status_filter)
    
    invites = query.order_by(MeetingInvite.created_at.desc()).all()
    
    for inv in invites:
        if inv.status == "pending" and datetime.utcnow() > inv.expires_at:
            inv.status = "expired"
    
    db.commit()
    
    return [MeetingInviteResponse.from_orm(i) for i in invites]


@router_meeting.get("/invite/{invite_id}", response_model=MeetingWithLocation)
async def get_invite_details(
    invite_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Obtém detalhes do convite com localização"""
    
    invite = db.query(MeetingInvite).filter(MeetingInvite.id == invite_id).first()
    
    if not invite:
        raise HTTPException(404, "Convite não encontrado")
    
    if invite.sender_id != current_user.id and invite.receiver_id != current_user.id:
        raise HTTPException(403, "Sem permissão")
    
    if invite.status == "pending" and datetime.utcnow() > invite.expires_at:
        invite.status = "expired"
        db.commit()
    
    sender = db.query(User).filter(User.id == invite.sender_id).first()
    
    sender_location = None
    if current_user.id == invite.receiver_id and invite.share_sender_location:
        sender_loc = db.query(LocationLive).filter(
            LocationLive.user_id == invite.sender_id,
            LocationLive.is_active == True,
            LocationLive.expires_at > datetime.utcnow()
        ).first()
        
        if sender_loc:
            sender_location = LocationResponse.from_orm(sender_loc)
    
    return MeetingWithLocation(
        invite=MeetingInviteResponse.from_orm(invite),
        sender_location=sender_location,
        sender_username=sender.user
    )


@router_meeting.patch("/invite/{invite_id}/respond", response_model=MeetingInviteResponse)
async def respond_invite(
    invite_id: str,
    action: MeetingInviteAction,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Responde convite"""
    
    invite = db.query(MeetingInvite).filter(MeetingInvite.id == invite_id).first()
    
    if not invite:
        raise HTTPException(404, "Convite não encontrado")
    
    if datetime.utcnow() > invite.expires_at:
        invite.status = "expired"
        db.commit()
        raise HTTPException(410, "Convite expirado")
    
    if action.action == "cancel":
        if invite.sender_id != current_user.id:
            raise HTTPException(403, "Apenas remetente pode cancelar")
        invite.status = "cancelled"
        invite.responded_at = datetime.utcnow()
    else:
        if invite.receiver_id != current_user.id:
            raise HTTPException(403, "Apenas destinatário pode aceitar/rejeitar")
        
        if invite.status != "pending":
            raise HTTPException(400, f"Já {invite.status}")
        
        invite.status = action.action + "ed"
        invite.responded_at = datetime.utcnow()
        
        notif = Notification(
            notification_type="user_specific",
            user_id=invite.sender_id,
            title=f"Convite {action.action}o!",
            message=f"{current_user.user} {action.action}ou seu convite",
            priority="high" if action.action == "accept" else "low",
            category="meeting",
            created_by=current_user.id
        )
        db.add(notif)
    
    db.commit()
    db.refresh(invite)
    
    return MeetingInviteResponse.from_orm(invite)


@router_meeting.delete("/invite/{invite_id}")
async def delete_invite(
    invite_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Deleta convite"""
    
    invite = db.query(MeetingInvite).filter(MeetingInvite.id == invite_id).first()
    
    if not invite:
        raise HTTPException(404, "Convite não encontrado")
    
    if invite.sender_id != current_user.id and invite.receiver_id != current_user.id:
        raise HTTPException(403, "Sem permissão")
    
    db.delete(invite)
    db.commit()
    
    return {"message": "Convite deletado"}
