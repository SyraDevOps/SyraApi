"""
Middleware para verificar IPs banidos e verificação de usuário admin
"""
from fastapi import HTTPException, status
from Modelos.user import User


def verify_admin(current_user: User):
    """
    Verifica se usuário é administrador
    Usuários com ID 1 ou 2 são admins por padrão
    """
    # IDs 1 e 2 são sempre admins
    if current_user.id in [1, 2]:
        return current_user
    
    # TODO: Implementar sistema de roles/permissões no futuro
    # if current_user.role == "admin":
    #     return current_user
    
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Acesso negado. Apenas administradores podem acessar este recurso."
    )


async def check_banned_ip_middleware(request, call_next):
    """
    Middleware para verificar se IP está banido
    Importa banned_ip_manager localmente para evitar circular import
    """
    from Modelos.admin_routes import banned_ip_manager
    
    client_ip = request.client.host
    
    if banned_ip_manager.is_banned(client_ip):
        from fastapi.responses import JSONResponse
        return JSONResponse(
            status_code=403,
            content={"detail": f"Acesso negado. IP {client_ip} foi banido."}
        )
    
    response = await call_next(request)
    return response
