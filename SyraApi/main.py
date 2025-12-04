import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
import uvicorn

from DB.database import init_db
from Modelos.auth import router as auth_router
from Modelos.selene_routes import router as selene_router
from Modelos.luna_routes import router as luna_router
from Modelos.notification_routes import router as notification_router
from Modelos.location_routes import router as location_router, router_meeting
from Modelos.keypair_routes import router as keypair_router, router_qr as qrcode_router
from Modelos.registry_routes import router_devices, router_nodes, router_apis, router_summary
from Modelos.temp_messages_routes import router as temp_messages_router
from Modelos.ai_routes_part1 import router_ai_models, router_datasets
from Modelos.ai_routes_part2 import router_knowledge, router_commands, router_chat
from Modelos.ai_routes_part3 import router_training, router_selene
from Modelos.selene_training_routes import router_selene_train
from Modelos.admin_routes import router_admin, banned_ip_manager
from Modelos.admin_model_routes import router_admin_models
from Modelos.agenda_routes import router_agenda
from Modelos.drive_routes import router_drive
from Modelos.notes_routes import router_notes
from Modelos.feed_routes import router_feed
from Modelos.user_routes import router_user
from Tools.file_manager import ensure_user_data_directory
from Tools.middleware import check_banned_ip_middleware

# ──────────────────────────────────────────────
# Diretórios necessários
# ──────────────────────────────────────────────
REQUIRED_DIRS = ["Modelos", "DB", "Tools"]

def ensure_directories():
    for d in REQUIRED_DIRS:
        if not os.path.exists(d):
            os.makedirs(d)
            print(f"[+] Diretório criado: {d}")
        else:
            print(f"[=] Diretório já existe: {d}")
    
    # Garante diretório de dados dos usuários
    ensure_user_data_directory()

# ──────────────────────────────────────────────
# Inicia API
# ──────────────────────────────────────────────
app = FastAPI(
    title="Syra System API",
    description="Sistema completo com autenticação JWT, IA, localização e UserNode (chaves X25519)",
    version="3.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# Configuração CORS COMPLETA para smartphones e aplicações externas
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Permite todos os domínios (smartphones, apps, web)
    allow_credentials=False,  # False para permitir allow_origins=["*"]
    allow_methods=["*"],  # GET, POST, PUT, DELETE, PATCH, OPTIONS
    allow_headers=["*"],  # Authorization, Content-Type, etc
    expose_headers=["*"],  # Expõe todos os headers nas respostas
    max_age=3600,  # Cache de preflight por 1 hora
)

# Middleware para verificar IPs banidos
@app.middleware("http")
async def check_banned_ip(request, call_next):
    """Verifica se IP está banido antes de processar requisição"""
    return await check_banned_ip_middleware(request, call_next)

# Registra routers
app.include_router(auth_router)
app.include_router(selene_router)
app.include_router(luna_router)
app.include_router(notification_router)
app.include_router(location_router)
app.include_router(router_meeting)

# UserNode routers (chaves, QR codes, devices, nodes, APIs)
app.include_router(keypair_router)
app.include_router(qrcode_router)
app.include_router(router_devices)
app.include_router(router_nodes)
app.include_router(router_apis)
app.include_router(router_summary)

# IA personalizada routers (mensagens temporárias, modelos, conhecimento, comandos, treino)
app.include_router(temp_messages_router)
app.include_router(router_ai_models)
app.include_router(router_datasets)
app.include_router(router_knowledge)
app.include_router(router_commands)
app.include_router(router_chat)
app.include_router(router_training)
app.include_router(router_selene)
app.include_router(router_selene_train)

# Admin routers (gerenciamento de usuários, IPs e modelos)
app.include_router(router_admin)
app.include_router(router_admin_models)

# Sistema Social routers (agenda, drive, notas, feed)
app.include_router(router_agenda)
app.include_router(router_drive)
app.include_router(router_notes)
app.include_router(router_feed)
app.include_router(router_user)

@app.get("/")
def root():
    return {
        "status": "online",
        "message": "API Syra funcionando perfeitamente.",
        "version": "3.0.0",
        "cors_enabled": True,
        "features": [
            "Autenticação JWT",
            "Conversas com IA (Selene & Luna)",
            "Sistema de Notificações",
            "Localização em Tempo Real (OpenStreetMap)",
            "Sistema de Vínculos e Encontros",
            "UserNode: Chaves X25519, QR Codes, Devices, Nodes, APIs",
            "Criptografia AES-256-GCM para dados sensíveis",
            "Mensagens Temporárias com Auto-Expiração",
            "IA Personalizada por Usuário com Selene",
            "Base de Conhecimento e Comandos Customizáveis",
            "Upload e Treinamento de Modelos de IA"
        ],
        "endpoints": {
            "docs": "/docs",
            "redoc": "/redoc",
            "openapi": "/openapi.json",
            "health": "/health",
            "auth": "/auth",
            "register": "/auth/register",
            "login": "/auth/login",
            "profile": "/auth/me",
            "selene_chat": "/selene/chat",
            "luna_chat": "/luna/chat",
            "notifications": "/notifications",
            "location_share": "/location/share",
            "location_nearby": "/location/nearby",
            "location_bonds": "/location/bonds",
            "meeting_invite": "/meeting/invite",
            "user_node_keys": "/user-node/keys",
            "user_node_qrcodes": "/user-node/qrcodes",
            "user_node_devices": "/user-node/devices",
            "user_node_nodes": "/user-node/nodes",
            "user_node_apis": "/user-node/apis",
            "user_node_summary": "/user-node/summary",
            "temp_messages_send": "/temp-messages/send",
            "temp_messages_inbox": "/temp-messages/inbox",
            "ai_create_model": "/ai/models",
            "ai_upload_dataset": "/ai/datasets/upload",
            "ai_add_knowledge": "/ai/models/{model_id}/knowledge",
            "ai_create_command": "/ai/models/{model_id}/commands",
            "ai_chat": "/ai/models/{model_id}/chat",
            "ai_train": "/ai/models/{model_id}/training/start",
            "ai_selene_status": "/ai/selene/status"
        },
        "database_tables": [
            "users", "conversations", "messages", "notifications",
            "locations_live", "locations_history", "user_bonds", "meeting_invites",
            "x25519_keypairs", "qrcodes", "devices", "node_registry", "api_registry",
            "temporary_messages", "user_ai_models", "ai_knowledge_base",
            "ai_commands", "ai_conversations", "user_datasets"
        ]
    }


@app.get("/health")
def health_check():
    """Endpoint de health check para monitoramento"""
    return {
        "status": "healthy",
        "service": "Syra API",
        "version": "3.0.0",
        "timestamp": datetime.now().isoformat()
    }


@app.get("/api-info")
def api_info():
    """Informações detalhadas da API para desenvolvedores"""
    return {
        "api_name": "Syra System API",
        "version": "3.0.0",
        "description": "API completa com autenticação JWT, IA conversacional, localização em tempo real e sistema UserNode",
        "base_url": "http://0.0.0.0:80",
        "documentation": {
            "swagger": "/docs",
            "redoc": "/redoc",
            "openapi_schema": "/openapi.json"
        },
        "authentication": {
            "type": "JWT Bearer Token",
            "header": "Authorization: Bearer <token>",
            "endpoints": {
                "register": "POST /auth/register",
                "login": "POST /auth/login",
                "get_profile": "GET /auth/me"
            }
        },
        "features": {
            "ai_conversations": {
                "selene": "POST /selene/chat",
                "luna": "POST /luna/chat"
            },
            "notifications": {
                "create_global": "POST /notifications/global",
                "get_user_notifications": "GET /notifications/my"
            },
            "location": {
                "share_location": "POST /location/share",
                "find_nearby": "GET /location/nearby",
                "create_bond": "POST /location/bond/request",
                "send_meeting_invite": "POST /meeting/invite"
            },
            "user_node": {
                "store_x25519_key": "POST /user-node/keys/generate",
                "store_qrcode": "POST /user-node/qrcodes",
                "register_device": "POST /user-node/devices",
                "register_node": "POST /user-node/nodes",
                "register_api": "POST /user-node/apis",
                "dashboard": "GET /user-node/summary"
            },
            "temp_messages": {
                "send_message": "POST /temp-messages/send",
                "inbox": "GET /temp-messages/inbox",
                "sent": "GET /temp-messages/sent",
                "delete": "DELETE /temp-messages/{id}"
            },
            "ai_personalized": {
                "create_model": "POST /ai/models",
                "upload_dataset": "POST /ai/datasets/upload",
                "add_knowledge": "POST /ai/models/{model_id}/knowledge",
                "create_command": "POST /ai/models/{model_id}/commands",
                "chat_with_ai": "POST /ai/models/{model_id}/chat",
                "train_model": "POST /ai/models/{model_id}/training/start",
                "check_training": "GET /ai/models/{model_id}/training/status/{task_id}",
                "load_selene": "POST /ai/selene/load-to-model/{model_id}"
            }
        },
        "security": {
            "encryption": "AES-256-GCM para chaves privadas e API keys",
            "password_hashing": "Bcrypt",
            "token_type": "JWT",
            "cors": "Habilitado para todas as origens"
        }
    }

# Inicializa banco de dados na importação
print("[*] Inicializando sistema...")
init_db()
print("[✓] Sistema pronto!")

# ──────────────────────────────────────────────
# Start automático com uvicorn
# ──────────────────────────────────────────────
if __name__ == "__main__":
    ensure_directories()

    # Em servidor real (NGINX / domínio), use host 0.0.0.0 e porta 80
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=80,  # Porta padrão HTTP → domínio SEM porta
        reload=False
    )
