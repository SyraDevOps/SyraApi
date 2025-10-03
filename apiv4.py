# -*- coding: utf-8 -*-
"""
API Syra - Versão 4.0.0 (pronta para deploy no Render)
Inclui:
- Inicialização automática do banco (criação de tabelas) ao importar o módulo
- Rotas de autenticação (register/verify/login) com TOTP + QR
- Persistência de notificações e logs em SQLite
- Sistema de seguir/não seguir usuários
- Bio personalizável para usuários
- Perfis públicos de usuários com QR codes
- Sumário do perfil com estatísticas
- Envio de notificações entre usuários
- Sistema de validação RIGOROSA de blocos minerados (apenas blocos com 'Syra')
- Recompensa FIXA de 1 token por bloco validado
- Ranking de mineradores (leaderboard)
- Sistema de carteiras com códigos de segurança CRIPTOGRAFADOS
- Transferências de tokens entre usuários com segurança aprimorada
- Sistema completo de MAPAS e EVENTOS georreferenciados
- Localização de usuários com raio de notificações
- Criação, participação e gerenciamento de eventos
- Sistema de CATEGORIAS para eventos
- Sistema de COMENTÁRIOS com threads para eventos
- QR CODES para compartilhamento de eventos
- Sistema de CHECK-IN com validação temporal (30s)
- Códigos de presença e hash identificadores
- Sistema completo de CONFIGURAÇÕES de usuário
- Sistema de MODERAÇÃO (relatórios/denúncias)
- Sistema de BLOQUEIO de usuários
- BUSCA GLOBAL unificada e inteligente
- ANALYTICS para criadores de eventos
- Consultas geoespaciais OTIMIZADAS com bounding box
- Notificações automáticas por proximidade geográfica
- Desativação automática de eventos expirados
- Rate limiting baseado em banco de dados (suporte a múltiplos workers)
- Associação de blocos validados aos usuários
- Tratamento melhorado de concorrência
- Proteção por JWT e rota de administração com token
- Trivial rota raiz e handler de erros para respostas JSON

Para rodar em produção (Render):
- Build Command: pip install -r requirements.txt
- Start Command: gunicorn -w 4 -b 0.0.0.0:5000 api:app

OTIMIZAÇÕES PARA ESCALA:
- Para alta escala, migre para PostgreSQL + PostGIS para consultas geoespaciais nativas
- Use Redis para cache de consultas frequentes
- Implemente CDN para arquivos estáticos
- Configure load balancer para múltiplas instâncias

NOTA: Gunicorn importa o módulo. Por isso init_db() é chamado no nível do módulo para garantir
que as tabelas existam antes dos workers atenderem requisições.
"""

import sqlite3
import pyotp
import qrcode
import io
import base64
import jwt
import json
import os
import secrets
import time
import logging
import random
import hashlib
import hmac
import math
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room

# --- Configuração da Aplicação ---
DB_NAME = os.getenv("DATABASE_PATH", "syra_v2_2.db")  # pode ser sobrescrito via env
APP_NAME = os.getenv("APP_NAME", "Syra")

# --- CHAVES SECRETAS ---
JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", secrets.token_hex(32))
ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", secrets.token_hex(32))
JWT_ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")

# --- Configuração de Rate Limiting ---
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "10"))  # Requisições
RATE_LIMIT_DURATION = int(os.getenv("RATE_LIMIT_DURATION", "60"))  # Segundos

# --- Chave para criptografia de dados sensíveis ---
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", secrets.token_hex(32))

# --- Inicialização do Flask ---
app = Flask(__name__)
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Config logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("syra_api")

# --- Funções do Banco de Dados (SQLite) ---

def get_db_connection():
    """Estabelece uma conexão com o banco de dados SQLite com melhor tratamento de concorrência."""
    # timeout aumentado e configurações para melhor concorrência
    conn = sqlite3.connect(DB_NAME, timeout=60)
    conn.row_factory = sqlite3.Row
    
    # Configurações para melhorar concorrência
    conn.execute('PRAGMA journal_mode=WAL')  # Write-Ahead Logging
    conn.execute('PRAGMA synchronous=NORMAL')  # Balanceamento entre segurança e performance
    conn.execute('PRAGMA cache_size=10000')  # Cache maior
    conn.execute('PRAGMA temp_store=memory')  # Tabelas temporárias em memória
    conn.execute('PRAGMA busy_timeout=30000')  # 30 segundos de timeout para locks
    
    return conn


def get_db():
    """Obtém conexão do banco para a requisição atual"""
    if 'db' not in g:
        g.db = get_db_connection()
    return g.db


@app.before_request
def before_request():
    """Executa antes de cada requisição"""
    # A conexão será criada apenas quando necessário via get_db()
    pass


@app.teardown_appcontext
def close_db(error):
    """Fecha conexão do banco após cada requisição"""
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Inicializa o banco de dados e cria todas as tabelas, se não existirem."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        logger.info("Inicializando o banco de dados: %s", DB_NAME)

        # Tabela de Usuários (users)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                secret TEXT NOT NULL,
                bio TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Registros Pendentes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pending_registrations (
                username TEXT PRIMARY KEY,
                secret TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')



        # Tabela de Notificações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS notifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                type TEXT NOT NULL,
                content TEXT NOT NULL,
                is_read INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Logs de Atividade
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                username TEXT,
                details TEXT,
                ip_address TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Blocos Minerados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mined_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                block_index INTEGER NOT NULL,
                block_hash TEXT NOT NULL UNIQUE,
                hash_parts TEXT NOT NULL,
                block_date TEXT NOT NULL,
                username TEXT NOT NULL,
                validated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                syra_count INTEGER DEFAULT 0,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Carteiras
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                wallet_code TEXT NOT NULL UNIQUE,
                security_code TEXT NOT NULL,
                balance INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Transações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS transactions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                from_username TEXT NOT NULL,
                to_username TEXT NOT NULL,
                amount INTEGER NOT NULL,
                transaction_type TEXT NOT NULL DEFAULT 'transfer',
                description TEXT,
                status TEXT DEFAULT 'completed',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (from_username) REFERENCES users (username),
                FOREIGN KEY (to_username) REFERENCES users (username)
            )
        ''')

        # Tabela de Rate Limiting
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                endpoint TEXT NOT NULL,
                request_count INTEGER DEFAULT 1,
                window_start TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_request TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Coordenadas de Usuários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_locations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                city TEXT,
                state TEXT,
                country TEXT,
                notification_radius INTEGER DEFAULT 50,
                is_public INTEGER DEFAULT 1,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                creator_username TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                category_id INTEGER,
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                address TEXT,
                start_date TIMESTAMP NOT NULL,
                end_date TIMESTAMP,
                max_participants INTEGER,
                qr_code_data TEXT,
                is_private INTEGER DEFAULT 0,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (creator_username) REFERENCES users (username),
                FOREIGN KEY (category_id) REFERENCES event_categories (id)
            )
        ''')

        # Tabela de Participações em Eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_participants (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'confirmed',
                FOREIGN KEY (event_id) REFERENCES events (id),
                FOREIGN KEY (username) REFERENCES users (username),
                UNIQUE(event_id, username)
            )
        ''')

        # Tabela de Categorias de Eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_categories (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                color TEXT DEFAULT '#007bff',
                icon TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Tabela de Comentários de Eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                content TEXT NOT NULL,
                parent_comment_id INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id),
                FOREIGN KEY (username) REFERENCES users (username),
                FOREIGN KEY (parent_comment_id) REFERENCES event_comments (id)
            )
        ''')

        # Tabela de Check-ins de Eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_checkins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                validation_code TEXT NOT NULL,
                hash_identifier TEXT NOT NULL,
                checked_in_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id),
                FOREIGN KEY (username) REFERENCES users (username),
                UNIQUE(event_id, username)
            )
        ''')

        # Tabela de Códigos de Validação Temporários
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS validation_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                creator_username TEXT NOT NULL,
                token TEXT NOT NULL UNIQUE,
                expires_at TIMESTAMP NOT NULL,
                is_used INTEGER DEFAULT 0,
                used_by TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id),
                FOREIGN KEY (creator_username) REFERENCES users (username)
            )
        ''')

        # Tabela de Configurações de Usuário
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_settings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                notifications TEXT DEFAULT '{}',
                privacy TEXT DEFAULT '{}',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (username) REFERENCES users (username)
            )
        ''')

        # Tabela de Relatórios/Denúncias
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reporter_username TEXT NOT NULL,
                target_type TEXT NOT NULL,
                target_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                details TEXT,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved_at TIMESTAMP,
                resolved_by TEXT,
                FOREIGN KEY (reporter_username) REFERENCES users (username)
            )
        ''')

        # Tabela de Usuários Bloqueados
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_blocks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                blocker_username TEXT NOT NULL,
                blocked_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (blocker_username) REFERENCES users (username),
                FOREIGN KEY (blocked_username) REFERENCES users (username),
                UNIQUE(blocker_username, blocked_username)
            )
        ''')

        # Tabela de Seguidores (substituindo campo JSON)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS followers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                follower_username TEXT NOT NULL,
                followed_username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (follower_username) REFERENCES users (username),
                FOREIGN KEY (followed_username) REFERENCES users (username),
                UNIQUE(follower_username, followed_username)
            )
        ''')

        # Tabela de Convites para Eventos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS event_invites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id INTEGER NOT NULL,
                inviter_username TEXT NOT NULL,
                invited_username TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                responded_at TIMESTAMP,
                FOREIGN KEY (event_id) REFERENCES events (id),
                FOREIGN KEY (inviter_username) REFERENCES users (username),
                FOREIGN KEY (invited_username) REFERENCES users (username),
                UNIQUE(event_id, invited_username)
            )
        ''')

        # Tabela de mensagens diretas
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_username TEXT NOT NULL,
                receiver_username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_read BOOLEAN DEFAULT 0,
                FOREIGN KEY (sender_username) REFERENCES users (username),
                FOREIGN KEY (receiver_username) REFERENCES users (username)
            )
        ''')
        
        # Tabela de grupos/comunidades
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                description TEXT,
                creator_username TEXT NOT NULL,
                is_private BOOLEAN DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (creator_username) REFERENCES users (username)
            )
        ''')
        
        # Tabela de membros de grupos
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS group_members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                role TEXT DEFAULT 'member', -- 'member', 'moderator', 'admin'
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (group_id) REFERENCES groups (id),
                FOREIGN KEY (username) REFERENCES users (username),
                UNIQUE(group_id, username)
            )
        ''')
        
        # Tabela de posts/publicações
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS posts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                author_username TEXT NOT NULL,
                content TEXT NOT NULL,
                group_id INTEGER, -- NULL para posts pessoais
                image_url TEXT,
                latitude REAL,
                longitude REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (author_username) REFERENCES users (username),
                FOREIGN KEY (group_id) REFERENCES groups (id)
            )
        ''')
        
        # Tabela de curtidas/likes
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_likes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                username TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES posts (id),
                FOREIGN KEY (username) REFERENCES users (username),
                UNIQUE(post_id, username)
            )
        ''')
        
        # Tabela de comentários em posts
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS post_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                post_id INTEGER NOT NULL,
                author_username TEXT NOT NULL,
                content TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (post_id) REFERENCES posts (id),
                FOREIGN KEY (author_username) REFERENCES users (username)
            )
        ''')

        # Índices úteis
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications (username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_user ON mined_blocks (username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_blocks_hash ON mined_blocks (block_hash)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_wallets_user ON wallets (username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_wallets_code ON wallets (wallet_code)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_from ON transactions (from_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_transactions_to ON transactions (to_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits (ip_address, endpoint)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_rate_limits_window ON rate_limits (window_start)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_locations_coords ON user_locations (latitude, longitude)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_coords ON events (latitude, longitude)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_creator ON events (creator_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_dates ON events (start_date, end_date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_events_category ON events (category_id)')
        
        # Índices para novas tabelas
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_followers_follower ON followers(follower_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_followers_followed ON followers(followed_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_invites_event ON event_invites(event_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_invites_user ON event_invites(invited_username)')
        
        # Índices para mensagens
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_receiver ON messages(receiver_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_conversation ON messages(sender_username, receiver_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_messages_created ON messages(created_at)')
        
        # Índices para grupos
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_group_members_group ON group_members(group_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_groups_creator ON groups(creator_username)')
        
        # Índices para posts
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_author ON posts(author_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_group ON posts(group_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_posts_created ON posts(created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_post_likes_post ON post_likes(post_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_post_likes_user ON post_likes(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_post_comments_post ON post_comments(post_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_participants ON event_participants (event_id, username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_comments ON event_comments (event_id, created_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_comments_parent ON event_comments (parent_comment_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_checkins ON event_checkins (event_id, username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_validation_tokens ON validation_tokens (token, expires_at)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_reports ON reports (target_type, target_id, status)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_blocks ON user_blocks (blocker_username, blocked_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_followers ON followers (follower_username, followed_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_followed ON followers (followed_username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_invites ON event_invites (event_id, invited_username, status)')

        conn.commit()
        
        # Insere categorias padrão se não existirem
        default_categories = [
            ('Social', 'Eventos sociais e networking', '#28a745', '👥'),
            ('Tecnologia', 'Eventos técnicos e desenvolvimento', '#007bff', '💻'),
            ('Esportes', 'Atividades esportivas e exercícios', '#fd7e14', '⚽'),
            ('Educação', 'Workshops, cursos e palestras', '#6f42c1', '📚'),
            ('Negócios', 'Eventos corporativos e empreendedorismo', '#dc3545', '💼'),
            ('Arte', 'Eventos culturais e artísticos', '#e83e8c', '🎨'),
            ('Mineração', 'Eventos relacionados à mineração Syra', '#ffc107', '⛏️'),
            ('Outros', 'Eventos diversos', '#6c757d', '📌')
        ]
        
        for name, description, color, icon in default_categories:
            conn.execute(
                'INSERT OR IGNORE INTO event_categories (name, description, color, icon) VALUES (?, ?, ?, ?)',
                (name, description, color, icon)
            )
        
        conn.commit()
        logger.info("Banco de dados '%s' pronto para uso.", DB_NAME)
        logger.info("🔑 Token de Admin (advice: armazene em env var ADMIN_TOKEN): %s", ADMIN_TOKEN)
    except sqlite3.Error as e:
        logger.exception("Erro ao inicializar o banco de dados: %s", e)
    finally:
        try:
            conn.close()
        except Exception:
            pass


# Chama init_db no import do módulo (importante para Gunicorn)
init_db()

# --- Funções Auxiliares e Decorators ---

def log_action(action, username=None, details="", ip_address=None):
    """Registra uma ação no banco de dados de logs."""
    try:
        # ip pode vir do cabeçalho X-Forwarded-For ou do request remoto
        ip = ip_address
        if ip is None:
            try:
                ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            except RuntimeError:
                ip = None

        conn = get_db_connection()
        conn.execute(
            'INSERT INTO logs (action, username, details, ip_address) VALUES (?, ?, ?, ?)',
            (action, username, details, ip)
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Falha ao registrar log: %s %s", action, username)


def emit_user_event(username, event_name, data):
    """Emite eventos em tempo real para um usuário autenticado via WebSocket."""
    try:
        socketio.emit(event_name, data, room=f"user:{username}")
    except Exception:
        logger.exception("Falha ao emitir evento '%s' para %s", event_name, username)


def broadcast_notification(username, notif_type, content, extra=None):
    """Envia notificação persistente e em tempo real."""
    extra = extra or {}
    db = get_db()
    cursor = db.execute(
        'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
        (username, notif_type, content)
    )
    db.commit()
    notification_id = cursor.lastrowid
    payload = {
        "id": notification_id,
        "type": notif_type,
        "content": content,
        "extra": extra
    }
    emit_user_event(username, 'notification', payload)
    return notification_id


def hash_security_code(security_code):
    """Gera hash seguro do código de segurança usando HMAC-SHA256"""
    return hmac.new(
        ENCRYPTION_KEY.encode('utf-8'),
        security_code.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()


def verify_security_code(provided_code, stored_hash):
    """Verifica se o código fornecido corresponde ao hash armazenado"""
    provided_hash = hash_security_code(provided_code)
    return hmac.compare_digest(provided_hash, stored_hash)


def cleanup_old_rate_limits():
    """Remove registros antigos de rate limiting para manter a tabela limpa"""
    try:
        cutoff_time = datetime.utcnow() - timedelta(seconds=RATE_LIMIT_DURATION * 2)
        conn = get_db_connection()
        conn.execute(
            'DELETE FROM rate_limits WHERE window_start < ?',
            (cutoff_time.isoformat(),)
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Erro ao limpar rate limits antigos")


def rate_limited(f):
    """Decorator para limitar a taxa de requisições usando banco de dados."""
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        except RuntimeError:
            ip = 'unknown'

        endpoint = request.endpoint or 'unknown'
        now = datetime.utcnow()
        window_start = now - timedelta(seconds=RATE_LIMIT_DURATION)

        try:
            conn = get_db_connection()
            
            # Limpa registros antigos periodicamente (1% de chance)
            if random.randint(1, 100) == 1:
                cleanup_old_rate_limits()
            
            # Busca requisições recentes para este IP e endpoint
            recent_requests = conn.execute(
                '''SELECT request_count FROM rate_limits 
                   WHERE ip_address = ? AND endpoint = ? AND window_start > ?''',
                (ip, endpoint, window_start.isoformat())
            ).fetchall()
            
            total_requests = sum(row['request_count'] for row in recent_requests)
            
            if total_requests >= RATE_LIMIT_REQUESTS:
                conn.close()
                return jsonify({"error": "Limite de requisições excedido. Tente novamente mais tarde."}), 429
            
            # Registra esta requisição
            conn.execute(
                '''INSERT INTO rate_limits (ip_address, endpoint, request_count, window_start, last_request) 
                   VALUES (?, ?, 1, ?, ?)''',
                (ip, endpoint, now.isoformat(), now.isoformat())
            )
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.exception("Erro no rate limiting: %s", e)
            # Em caso de erro, permite a requisição (fail-open)

        return f(*args, **kwargs)
    return decorated


# --- WebSocket Handlers ---

@socketio.on('connect')
def handle_connect():
    emit('connected', {'status': 'ok'})


@socketio.on('authenticate')
def handle_authenticate(data):
    token = (data or {}).get('token')
    if not token:
        emit('auth_error', {'error': 'Token ausente'})
        return
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        username = payload.get('username')
        if not username:
            raise jwt.InvalidTokenError("username missing")
        join_room(f'user:{username}')
        emit('authenticated', {'username': username})
        logger.info("WebSocket autenticado para usuário %s", username)
    except jwt.ExpiredSignatureError:
        emit('auth_error', {'error': 'Token expirado'})
    except jwt.InvalidTokenError:
        emit('auth_error', {'error': 'Token inválido'})
    except Exception:
        logger.exception("Erro durante autenticação via WebSocket")
        emit('auth_error', {'error': 'Falha na autenticação'})


@socketio.on('disconnect')
def handle_disconnect():
    logger.info("Cliente WebSocket desconectado")


def token_required(f):
    """Decorator para proteger rotas que exigem um token JWT válido."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            token = auth_header.split(" ")[1]

        if not token:
            return jsonify({"error": "Token de autenticação não fornecido"}), 401

        try:
            data = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
            db = get_db()
            current_user = db.execute('SELECT id, username, bio, created_at FROM users WHERE username = ?', (data['username'],)).fetchone()
            if not current_user:
                return jsonify({"error": "Usuário do token não encontrado"}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({"error": "Token expirado. Por favor, faça login novamente."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"error": "Token inválido."}), 401
        except Exception:
            logger.exception("Erro ao validar token")
            return jsonify({"error": "Erro ao validar token."}), 401

        # converte Row para dict para isolamento
        user_dict = dict(current_user)
        return f(user_dict, *args, **kwargs)
    return decorated


def admin_required(f):
    """Decorator para proteger rotas de administração."""
    @wraps(f)
    def decorated(*args, **kwargs):
        admin_token = request.headers.get('X-Admin-Token')
        if not admin_token or not secrets.compare_digest(admin_token, ADMIN_TOKEN):
            log_action("ADMIN_ACCESS_DENIED", details="Token inválido ou ausente")
            return jsonify({"error": "Acesso não autorizado."}), 403
        return f(*args, **kwargs)
    return decorated


def generate_security_code():
    """Gera um código de segurança no formato xxx-xxx-xxx"""
    code = ''.join([str(random.randint(0, 9)) for _ in range(9)])
    formatted_code = f"{code[:3]}-{code[3:6]}-{code[6:9]}"
    return formatted_code, hash_security_code(formatted_code)


def create_wallet_for_user(username):
    """Cria uma carteira para o usuário se ela não existir"""
    try:
        conn = get_db_connection()
        
        # Verifica se já existe carteira
        existing_wallet = conn.execute(
            'SELECT wallet_code FROM wallets WHERE username = ?',
            (username,)
        ).fetchone()
        
        if existing_wallet:
            conn.close()
            return existing_wallet['wallet_code']
        
        # Gera códigos únicos
        while True:
            wallet_code = f"{username}#{secrets.token_hex(4).upper()}"
            security_code, security_hash = generate_security_code()
            
            # Verifica se o wallet_code é único
            if not conn.execute('SELECT id FROM wallets WHERE wallet_code = ?', (wallet_code,)).fetchone():
                break
        
        # Cria a carteira com hash do código de segurança
        conn.execute(
            'INSERT INTO wallets (username, wallet_code, security_code) VALUES (?, ?, ?)',
            (username, wallet_code, security_hash)
        )
        conn.commit()
        conn.close()
        
        # Nota: Em uma implementação real, o código em texto seria enviado
        # por email/SMS e não retornado diretamente
        logger.info(f"Carteira criada para {username}. Código: {security_code}")
        return wallet_code
        
    except Exception:
        logger.exception("Erro ao criar carteira para usuário %s", username)
        return None


def generate_user_qr_code(username):
    """Gera QR code com informações do perfil do usuário"""
    try:
        # Dados do perfil para o QR code
        profile_data = {
            "username": username,
            "profile_url": f"/users/{username}/profile",
            "app": APP_NAME,
            "type": "user_profile"
        }
        
        # Converte para JSON
        qr_data = json.dumps(profile_data)
        
        # Gera QR code
        img = qrcode.make(qr_data)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        return f"data:image/png;base64,{qr_code_b64}"
        
    except Exception:
        logger.exception("Erro ao gerar QR code para usuário %s", username)
        return None


def generate_user_qr_code(username):
    """Gera QR code com informações do perfil do usuário"""
    try:
        # Dados do perfil para o QR code
        profile_data = {
            "username": username,
            "profile_url": f"/users/{username}/profile",
            "app": APP_NAME,
            "type": "user_profile"
        }
        
        # Converte para JSON
        qr_data = json.dumps(profile_data)
        
        # Gera QR code
        img = qrcode.make(qr_data)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        return f"data:image/png;base64,{qr_code_b64}"
        
    except Exception:
        logger.exception("Erro ao gerar QR code para usuário %s", username)
        return None


def calculate_distance(lat1, lon1, lat2, lon2):
    """Calcula a distância entre duas coordenadas usando a fórmula de Haversine"""
    # Converte graus para radianos
    lat1, lon1, lat2, lon2 = map(math.radians, [lat1, lon1, lat2, lon2])
    
    # Fórmula de Haversine
    dlat = lat2 - lat1
    dlon = lon2 - lon1
    a = math.sin(dlat/2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon/2)**2
    c = 2 * math.asin(math.sqrt(a))
    
    # Raio da Terra em km
    r = 6371
    
    return c * r


def notify_users_in_radius(event_latitude, event_longitude, event_title, event_id, creator_username):
    """Notifica usuários dentro do raio de notificação sobre novo evento"""
    try:
        conn = get_db_connection()
        
        # Busca todos os usuários com localização definida
        users_with_location = conn.execute(
            '''SELECT username, latitude, longitude, notification_radius 
               FROM user_locations 
               WHERE is_public = 1 AND username != ?''',
            (creator_username,)
        ).fetchall()
        
        notified_users = []
        
        for user in users_with_location:
            distance = calculate_distance(
                event_latitude, event_longitude,
                user['latitude'], user['longitude']
            )
            
            # Se a distância for menor que o raio de notificação do usuário
            if distance <= user['notification_radius']:
                conn.execute(
                    '''INSERT INTO notifications (username, type, content) 
                       VALUES (?, ?, ?)''',
                    (user['username'], 'nearby_event', 
                     f"Novo evento '{event_title}' criado a {distance:.1f}km de você!")
                )
                notified_users.append(user['username'])
        
        conn.commit()
        conn.close()
        
        return notified_users
        
    except Exception:
        logger.exception("Erro ao notificar usuários sobre evento")
        return []


def generate_event_qr_code(event_id, title):
    """Gera QR code para compartilhamento do evento"""
    try:
        event_data = {
            "event_id": event_id,
            "title": title,
            "type": "event_share",
            "app": APP_NAME,
            "url": f"/events/{event_id}"
        }
        
        qr_data = json.dumps(event_data)
        img = qrcode.make(qr_data)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
        
        return f"data:image/png;base64,{qr_code_b64}"
        
    except Exception:
        logger.exception("Erro ao gerar QR code para evento %s", event_id)
        return None


def generate_validation_token():
    """Gera token de validação temporário de 6 dígitos"""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


def cleanup_expired_tokens():
    """Remove tokens de validação expirados"""
    try:
        conn = get_db_connection()
        conn.execute(
            'DELETE FROM validation_tokens WHERE expires_at < CURRENT_TIMESTAMP'
        )
        conn.commit()
        conn.close()
    except Exception:
        logger.exception("Erro ao limpar tokens expirados")


def deactivate_expired_events():
    """Desativa eventos que já terminaram"""
    try:
        conn = get_db_connection()
        result = conn.execute(
            '''UPDATE events SET is_active = 0 
               WHERE (end_date IS NOT NULL AND end_date < CURRENT_TIMESTAMP)
               OR (end_date IS NULL AND start_date < datetime(CURRENT_TIMESTAMP, '-4 hours'))
               AND is_active = 1'''
        )
        conn.commit()
        deactivated_count = result.rowcount
        conn.close()
        
        if deactivated_count > 0:
            logger.info(f"Desativados {deactivated_count} eventos expirados")
            
        return deactivated_count
    except Exception:
        logger.exception("Erro ao desativar eventos expirados")
        return 0


def get_default_user_settings():
    """Retorna configurações padrão do usuário"""
    return {
        "notifications": {
            "new_follower": True,
            "event_comment": True,
            "event_join": True,
            "nearby_event": True,
            "token_received": True,
            "comment_reply": True
        },
        "privacy": {
            "show_location_on_map": "everyone",  # everyone, followers, none
            "profile_visibility": "public"  # public, followers_only
        }
    }


# --- ROTAS DA API ---

@app.route('/')
def root():
    return jsonify({"message": f"{APP_NAME} API running", "version": "4.0.0"})

# --- 0. Rota de Saúde da API ---
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "version": "4.0.0", "timestamp": datetime.utcnow().isoformat()})

# --- 1. Rotas de Autenticação (/auth) ---
@app.route('/auth/register', methods=['POST'])
@rate_limited
def register():
    data = request.get_json()
    if not data or not data.get('username'):
        return jsonify({"error": "O campo 'username' é obrigatório"}), 400

    username = data['username'].strip().lower()
    conn = get_db_connection()
    try:
        if conn.execute('SELECT id FROM users WHERE username = ?', (username,)).fetchone():
            return jsonify({"error": "Este nome de usuário já está em uso"}), 409

        secret = pyotp.random_base32()
        # Salva o registro pendente no banco de dados
        conn.execute('INSERT OR REPLACE INTO pending_registrations (username, secret) VALUES (?, ?)', (username, secret))
        conn.commit()

        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name=APP_NAME)
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        qr_code_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        log_action("REGISTER_INITIATED", username)
        return jsonify({
            "message": "Escaneie o QR Code com seu app de autenticação e use /auth/verify para confirmar. O pedido expira em 15 minutos.",
            "secret_backup_key": secret,
            "qr_code_image": f"data:image/png;base64,{qr_code_b64}"
        })
    except Exception:
        logger.exception("Erro em /auth/register")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        conn.close()


@app.route('/auth/verify', methods=['POST'])
@rate_limited
def verify():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    conn = get_db_connection()
    try:
        pending_user = conn.execute('SELECT secret, created_at FROM pending_registrations WHERE username = ?', (username,)).fetchone()

        if not pending_user:
            return jsonify({"error": "Registro não iniciado ou expirado. Use /auth/register primeiro."}), 404

        # Tentativa de parse robusto para created_at
        created_at_raw = pending_user['created_at']
        try:
            expiration_time = datetime.strptime(created_at_raw, '%Y-%m-%d %H:%M:%S') + timedelta(minutes=15)
        except Exception:
            # fallback, sem segundos
            try:
                expiration_time = datetime.strptime(created_at_raw, '%Y-%m-%d %H:%M') + timedelta(minutes=15)
            except Exception:
                expiration_time = datetime.utcnow() + timedelta(minutes=15)

        if datetime.utcnow() > expiration_time:
            conn.execute('DELETE FROM pending_registrations WHERE username = ?', (username,))
            conn.commit()
            return jsonify({"error": "Pedido de registro expirado."}), 401

        secret = pending_user['secret']
        if pyotp.TOTP(secret).verify(totp_code):
            try:
                conn.execute('INSERT INTO users (username, secret) VALUES (?, ?)', (username, secret))
                conn.execute('DELETE FROM pending_registrations WHERE username = ?', (username,))
                conn.commit()
                log_action("REGISTER_COMPLETED", username)
                return jsonify({"status": "success", "message": "Usuário registrado com sucesso!"}), 201
            except sqlite3.IntegrityError:
                return jsonify({"error": "Este nome de usuário já está em uso"}), 409
        else:
            log_action("VERIFY_FAILED", username)
            return jsonify({"error": "Código de verificação inválido"}), 401
    except Exception:
        logger.exception("Erro em /auth/verify")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        conn.close()


@app.route('/auth/login', methods=['POST'])
@rate_limited
def login():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('totp_code'):
        return jsonify({"error": "Os campos 'username' e 'totp_code' são obrigatórios"}), 400

    username = data['username'].strip().lower()
    totp_code = data['totp_code'].strip()

    conn = get_db_connection()
    try:
        user = conn.execute('SELECT secret FROM users WHERE username = ?', (username,)).fetchone()

        if not user or not pyotp.TOTP(user['secret']).verify(totp_code):
            log_action("LOGIN_FAILED", username)
            return jsonify({"error": "Credenciais inválidas"}), 401

        token = jwt.encode({
            'username': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

        log_action("LOGIN_SUCCESS", username)
        return jsonify({"status": "success", "token": token})
    except Exception:
        logger.exception("Erro em /auth/login")
        return jsonify({"error": "Erro interno"}), 500
    finally:
        conn.close()


# --- 2. Rotas de Perfil e Notificações (/me) ---
@app.route('/me/profile', methods=['GET'])
@token_required
def get_my_profile(current_user):
    try:
        db = get_db()
        
        # Busca contadores de seguidores
        following_count = db.execute(
            'SELECT COUNT(*) as count FROM followers WHERE follower_username = ?',
            (current_user['username'],)
        ).fetchone()['count']
        
        followers_count = db.execute(
            'SELECT COUNT(*) as count FROM followers WHERE followed_username = ?',
            (current_user['username'],)
        ).fetchone()['count']
        
        profile = dict(current_user)
        profile['following_count'] = following_count
        profile['followers_count'] = followers_count
        
        return jsonify(profile)
    except Exception:
        logger.exception("Erro em /me/profile")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/summary', methods=['GET'])
@token_required
def get_my_summary(current_user):
    try:
        db = get_db()

        unread_notifications = db.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE username = ? AND is_read = 0',
            (current_user['username'],)
        ).fetchone()['count']

        following_count = db.execute(
            'SELECT COUNT(*) as count FROM followers WHERE follower_username = ?',
            (current_user['username'],)
        ).fetchone()['count']

        followers_count = db.execute(
            'SELECT COUNT(*) as count FROM followers WHERE followed_username = ?',
            (current_user['username'],)
        ).fetchone()['count']
        
        summary = {
            "username": current_user['username'],
            "bio": current_user.get('bio', ''),
            "following_count": following_count,
            "followers_count": followers_count,
            "unread_notifications": unread_notifications,
            "member_since": current_user['created_at']
        }
        
        return jsonify(summary)
    except Exception:
        logger.exception("Erro em /me/summary")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/notifications', methods=['GET'])
@token_required
def get_my_notifications(current_user):
    try:
        conn = get_db_connection()
        notifications_cursor = conn.execute(
            'SELECT id, type, content, created_at FROM notifications WHERE username = ? AND is_read = 0 ORDER BY created_at DESC',
            (current_user['username'],)
        ).fetchall()

        notifications = [dict(row) for row in notifications_cursor]

        if notifications:
            notification_ids = tuple(n['id'] for n in notifications)
            placeholders = ','.join('?' for _ in notification_ids)
            conn.execute(f'UPDATE notifications SET is_read = 1 WHERE id IN ({placeholders})', notification_ids)
            conn.commit()

        conn.close()
        return jsonify(notifications)
    except Exception:
        logger.exception("Erro em /me/notifications")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/bio', methods=['PUT'])
@token_required
def update_bio(current_user):
    try:
        data = request.get_json()
        if not data or 'bio' not in data:
            return jsonify({"error": "O campo 'bio' é obrigatório"}), 400
        
        bio = data['bio'].strip()
        if len(bio) > 500:  # Limite de caracteres para a bio
            return jsonify({"error": "Bio deve ter no máximo 500 caracteres"}), 400
        
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET bio = ? WHERE username = ?',
            (bio, current_user['username'])
        )
        conn.commit()
        conn.close()
        
        log_action("BIO_UPDATED", current_user['username'])
        return jsonify({"status": "success", "message": "Bio atualizada com sucesso", "bio": bio})
    except Exception:
        logger.exception("Erro em /me/bio")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/notifications/send', methods=['POST'])
@token_required
@rate_limited
def send_notification(current_user):
    try:
        data = request.get_json()
        if not data or not data.get('to_username') or not data.get('content'):
            return jsonify({"error": "Campos 'to_username' e 'content' são obrigatórios"}), 400
        
        to_username = data['to_username'].strip().lower()
        content = data['content'].strip()
        notification_type = data.get('type', 'general')  # tipo padrão
        
        if to_username == current_user['username']:
            return jsonify({"error": "Você não pode enviar notificações para si mesmo"}), 400
        
        conn = get_db_connection()
        
        # Verifica se o usuário destinatário existe
        if not conn.execute('SELECT id FROM users WHERE username = ?', (to_username,)).fetchone():
            conn.close()
            return jsonify({"error": f"Usuário '{to_username}' não encontrado"}), 404
        
        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (to_username, notification_type, f"{current_user['username']}: {content}")
        )
        conn.commit()
        conn.close()
        
        log_action("NOTIFICATION_SENT", current_user['username'], f"Para: {to_username}")
        return jsonify({"status": "success", "message": "Notificação enviada com sucesso"})
    except Exception:
        logger.exception("Erro em /notifications/send")
        return jsonify({"error": "Erro interno"}), 500


# --- 3. Rotas de Interação com Usuários (/users) ---
@app.route('/users', methods=['GET'])
@token_required
def list_users(current_user):
    try:
        conn = get_db_connection()
        users = conn.execute('SELECT username, bio FROM users WHERE username != ?', (current_user['username'],)).fetchall()
        conn.close()
        return jsonify({"users": [{'username': row['username'], 'bio': row['bio']} for row in users]})
    except Exception:
        logger.exception("Erro em /users")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/follow', methods=['POST'])
@token_required
def follow_user(current_user, target_username):
    try:
        target_username = target_username.lower()
        my_username = current_user['username']
        
        if target_username == my_username:
            return jsonify({"error": "Você não pode seguir a si mesmo"}), 400
        
        db = get_db()
        
        # Verifica se o usuário existe
        if not db.execute('SELECT id FROM users WHERE username = ?', (target_username,)).fetchone():
            return jsonify({"error": f"Usuário '{target_username}' não encontrado"}), 404
        
        # Verifica se já segue
        existing_follow = db.execute(
            'SELECT id FROM followers WHERE follower_username = ? AND followed_username = ?',
            (my_username, target_username)
        ).fetchone()
        
        if existing_follow:
            return jsonify({"error": f"Você já segue '{target_username}'"}), 409
        
        # Adiciona seguidor
        db.execute(
            'INSERT INTO followers (follower_username, followed_username) VALUES (?, ?)',
            (my_username, target_username)
        )
        
        # Envia notificação para o usuário seguido
        db.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (target_username, 'new_follower', my_username)
        )
        
        db.commit()
        
        log_action("USER_FOLLOWED", my_username, f"Seguindo: {target_username}")
        return jsonify({"status": "success", "message": f"Você agora segue '{target_username}'"})
    except Exception:
        logger.exception("Erro em follow_user")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/unfollow', methods=['DELETE'])
@token_required
def unfollow_user(current_user, target_username):
    try:
        target_username = target_username.lower()
        my_username = current_user['username']
        
        db = get_db()
        
        # Remove o follow
        result = db.execute(
            'DELETE FROM followers WHERE follower_username = ? AND followed_username = ?',
            (my_username, target_username)
        )
        
        if result.rowcount == 0:
            return jsonify({"error": f"Você não segue '{target_username}'"}), 404
        
        db.commit()
        
        log_action("USER_UNFOLLOWED", my_username, f"Parou de seguir: {target_username}")
        return jsonify({"status": "success", "message": f"Você parou de seguir '{target_username}'"})
    except Exception:
        logger.exception("Erro em unfollow_user")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/following', methods=['GET'])
@token_required
def get_my_following(current_user):
    try:
        db = get_db()
        
        # Busca quem o usuário segue
        following_list = db.execute(
            'SELECT followed_username FROM followers WHERE follower_username = ? ORDER BY created_at DESC',
            (current_user['username'],)
        ).fetchall()
        
        following_usernames = [row['followed_username'] for row in following_list]
        return jsonify({"following": following_usernames, "count": len(following_usernames)})
    except Exception:
        logger.exception("Erro em /me/following")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/followers', methods=['GET'])
@token_required
def get_my_followers(current_user):
    try:
        db = get_db()
        
        # Busca quem segue o usuário
        followers_list = db.execute(
            'SELECT follower_username FROM followers WHERE followed_username = ? ORDER BY created_at DESC',
            (current_user['username'],)
        ).fetchall()
        
        follower_usernames = [row['follower_username'] for row in followers_list]
        return jsonify({"followers": follower_usernames, "count": len(follower_usernames)})
    except Exception:
        logger.exception("Erro em get_my_followers")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/check-following', methods=['GET'])
@token_required
def check_following(current_user, target_username):
    try:
        target_username = target_username.lower()
        my_username = current_user['username']
        
        db = get_db()
        
        # Verifica se segue o usuário
        is_following = db.execute(
            'SELECT id FROM followers WHERE follower_username = ? AND followed_username = ?',
            (my_username, target_username)
        ).fetchone() is not None
        
        # Verifica se é seguido pelo usuário
        follows_me = db.execute(
            'SELECT id FROM followers WHERE follower_username = ? AND followed_username = ?',
            (target_username, my_username)
        ).fetchone() is not None
        
        return jsonify({
            "following": is_following,
            "followed_by": follows_me
        })
    except Exception:
        logger.exception("Erro em check_following")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/profile', methods=['GET'])
@token_required
def get_user_profile(current_user, target_username):
    """Retorna perfil público de um usuário"""
    try:
        target_username = target_username.lower()
        db = get_db()
        
        # Busca dados do usuário
        user = db.execute(
            'SELECT username, bio, created_at FROM users WHERE username = ?',
            (target_username,)
        ).fetchone()
        
        if not user:
            return jsonify({"error": f"Usuário '{target_username}' não encontrado"}), 404
        
        user_dict = dict(user)
        
        # Busca estatísticas de mineração
        mining_stats = db.execute(
            '''SELECT COUNT(*) as total_blocks, 
                      SUM(syra_count) as total_syra,
                      MAX(validated_at) as last_mining
               FROM mined_blocks WHERE username = ?''',
            (target_username,)
        ).fetchone()
        
        # Busca saldo da carteira
        wallet = db.execute(
            'SELECT balance FROM wallets WHERE username = ?',
            (target_username,)
        ).fetchone()
        
        # Conta seguidores e seguindo usando nova tabela
        followers_count = db.execute(
            'SELECT COUNT(*) as count FROM followers WHERE followed_username = ?',
            (target_username,)
        ).fetchone()['count']
        
        following_count = db.execute(
            'SELECT COUNT(*) as count FROM followers WHERE follower_username = ?',
            (target_username,)
        ).fetchone()['count']
        
        # Gera QR code do perfil
        qr_code = generate_user_qr_code(target_username)
        
        # Verifica se o usuário atual segue este perfil
        is_following = db.execute(
            'SELECT id FROM followers WHERE follower_username = ? AND followed_username = ?',
            (current_user['username'], target_username)
        ).fetchone() is not None
        
        profile = {
            "username": user_dict['username'],
            "bio": user_dict['bio'],
            "created_at": user_dict['created_at'],
            "mining_stats": {
                "total_blocks": mining_stats['total_blocks'] or 0,
                "total_syra_found": mining_stats['total_syra'] or 0,
                "last_mining": mining_stats['last_mining']
            },
            "wallet_balance": wallet['balance'] if wallet else 0,
            "social_stats": {
                "followers_count": followers_count,
                "following_count": following_count
            },
            "qr_code": qr_code,
            "is_following": is_following,
            "is_own_profile": target_username == current_user['username']
        }
        
        return jsonify(profile)
        
    except Exception:
        logger.exception("Erro em get_user_profile")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/qr-code', methods=['GET'])
@token_required
def get_my_qr_code(current_user):
    """Retorna QR code do perfil do usuário atual"""
    try:
        qr_code = generate_user_qr_code(current_user['username'])
        
        if not qr_code:
            return jsonify({"error": "Erro ao gerar QR code"}), 500
        
        return jsonify({
            "username": current_user['username'],
            "qr_code": qr_code,
            "message": "Compartilhe este QR code para que outros usuários possam acessar seu perfil"
        })
        
    except Exception:
        logger.exception("Erro em get_my_qr_code")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/location', methods=['PUT'])
@token_required
def update_my_location(current_user):
    """Atualiza localização base do usuário"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dados de localização são obrigatórios"}), 400
        
        required_fields = ['latitude', 'longitude']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Campo '{field}' é obrigatório"}), 400
        
        latitude = data['latitude']
        longitude = data['longitude']
        city = data.get('city', '')
        state = data.get('state', '')
        country = data.get('country', '')
        notification_radius = data.get('notification_radius', 50)
        is_public = data.get('is_public', True)
        
        # Validações
        if not isinstance(latitude, (int, float)) or not (-90 <= latitude <= 90):
            return jsonify({"error": "Latitude deve ser um número entre -90 e 90"}), 400
        
        if not isinstance(longitude, (int, float)) or not (-180 <= longitude <= 180):
            return jsonify({"error": "Longitude deve ser um número entre -180 e 180"}), 400
        
        if not isinstance(notification_radius, int) or not (1 <= notification_radius <= 1000):
            return jsonify({"error": "Raio de notificação deve ser entre 1 e 1000 km"}), 400
        
        conn = get_db_connection()
        
        # Verifica se já existe localização
        existing_location = conn.execute(
            'SELECT id FROM user_locations WHERE username = ?',
            (current_user['username'],)
        ).fetchone()
        
        if existing_location:
            # Atualiza localização existente
            conn.execute(
                '''UPDATE user_locations 
                   SET latitude = ?, longitude = ?, city = ?, state = ?, country = ?, 
                       notification_radius = ?, is_public = ?, updated_at = CURRENT_TIMESTAMP 
                   WHERE username = ?''',
                (latitude, longitude, city, state, country, 
                 notification_radius, 1 if is_public else 0, current_user['username'])
            )
        else:
            # Cria nova localização
            conn.execute(
                '''INSERT INTO user_locations 
                   (username, latitude, longitude, city, state, country, notification_radius, is_public) 
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
                (current_user['username'], latitude, longitude, city, state, country, 
                 notification_radius, 1 if is_public else 0)
            )
        
        conn.commit()
        conn.close()
        
        log_action("LOCATION_UPDATED", current_user['username'], 
                  f"Lat: {latitude}, Lon: {longitude}")
        
        return jsonify({
            "status": "success",
            "message": "Localização atualizada com sucesso!",
            "location": {
                "latitude": latitude,
                "longitude": longitude,
                "city": city,
                "state": state,
                "country": country,
                "notification_radius": notification_radius,
                "is_public": is_public
            }
        })
        
    except Exception:
        logger.exception("Erro em update_my_location")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/location', methods=['GET'])
@token_required
def get_my_location(current_user):
    """Retorna localização do usuário atual"""
    try:
        conn = get_db_connection()
        
        location = conn.execute(
            '''SELECT latitude, longitude, city, state, country, 
                      notification_radius, is_public, updated_at 
               FROM user_locations WHERE username = ?''',
            (current_user['username'],)
        ).fetchone()
        
        conn.close()
        
        if not location:
            return jsonify({"message": "Localização não definida"}), 404
        
        return jsonify(dict(location))
        
    except Exception:
        logger.exception("Erro em get_my_location")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/blocks/validate', methods=['POST'])
@token_required
@rate_limited
def validate_block(current_user):
    """Valida um bloco minerado e o associa ao usuário"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dados do bloco são obrigatórios"}), 400
        
        # Validação dos campos obrigatórios
        required_fields = ['index', 'hash', 'hash_parts', 'date', 'contains_syra']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Campo '{field}' é obrigatório"}), 400
        
        block_index = data['index']
        block_hash = data['hash']
        hash_parts = data['hash_parts']
        block_date = data['date']
        contains_syra = data['contains_syra']
        
        # Validação de tipos
        if not isinstance(block_index, int) or block_index <= 0:
            return jsonify({"error": "Index deve ser um número inteiro positivo"}), 400
        
        if not isinstance(hash_parts, list) or len(hash_parts) != 4:
            return jsonify({"error": "hash_parts deve ser uma lista com exatamente 4 elementos"}), 400
        
        if not isinstance(contains_syra, bool):
            return jsonify({"error": "contains_syra deve ser um valor booleano"}), 400
        
        # Validação da data
        try:
            block_datetime = datetime.strptime(block_date, "%d/%m/%Y")
            current_datetime = datetime.now()
            
            # Verifica se a data não é futura
            if block_datetime.date() > current_datetime.date():
                return jsonify({"error": "Não é possível validar blocos de datas futuras"}), 400
                
        except ValueError:
            return jsonify({"error": "Formato de data inválido. Use dd/mm/aaaa"}), 400
        
        # Validação do hash (deve obrigatoriamente conter 'Syra')
        if not contains_syra or 'Syra' not in block_hash:
            return jsonify({"error": "Apenas blocos que contenham 'Syra' no hash são aceitos"}), 400
        
        # Contagem de ocorrências de 'Syra' no hash (deve ter pelo menos 1)
        syra_count = block_hash.count('Syra')
        if syra_count == 0:
            return jsonify({"error": "Hash deve conter pelo menos uma ocorrência de 'Syra'"}), 400
        
        conn = get_db_connection()
        
        # Verifica se o hash já foi validado
        existing_block = conn.execute(
            'SELECT username FROM mined_blocks WHERE block_hash = ?',
            (block_hash,)
        ).fetchone()
        
        if existing_block:
            conn.close()
            return jsonify({
                "error": f"Este bloco já foi validado pelo usuário '{existing_block['username']}'"
            }), 409
        
        # Salva o bloco validado
        conn.execute(
            '''INSERT INTO mined_blocks 
               (block_index, block_hash, hash_parts, block_date, username, syra_count) 
               VALUES (?, ?, ?, ?, ?, ?)''',
            (block_index, block_hash, json.dumps(hash_parts), block_date, 
             current_user['username'], syra_count)
        )
        
        # Cria carteira se não existir e credita 1 token por bloco válido
        wallet_code = create_wallet_for_user(current_user['username'])
        if wallet_code:
            # Recompensa fixa: 1 token por bloco validado (independente da quantidade de 'Syra')
            tokens_earned = 1
            conn.execute(
                'UPDATE wallets SET balance = balance + ? WHERE username = ?',
                (tokens_earned, current_user['username'])
            )
            
            # Registra transação de mineração
            conn.execute(
                '''INSERT INTO transactions 
                   (from_username, to_username, amount, transaction_type, description) 
                   VALUES (?, ?, ?, ?, ?)''',
                ('system', current_user['username'], tokens_earned, 'mining', 
                 f'Mineração do bloco {block_index} - {syra_count} Syra(s) encontrada(s)')
            )
        
        conn.commit()
        conn.close()
        
        log_action("BLOCK_VALIDATED", current_user['username'], 
                  f"Index: {block_index}, Syra count: {syra_count}")
        
        return jsonify({
            "status": "success",
            "message": "Bloco validado com sucesso!",
            "block_info": {
                "index": block_index,
                "hash": block_hash,
                "date": block_date,
                "syra_count": syra_count,
                "tokens_earned": 1,  # Sempre 1 token por bloco
                "validated_by": current_user['username']
            }
        }), 201
        
    except Exception:
        logger.exception("Erro em /blocks/validate")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/blocks', methods=['GET'])
@token_required
def get_my_blocks(current_user):
    """Retorna todos os blocos validados pelo usuário"""
    try:
        conn = get_db_connection()
        blocks_cursor = conn.execute(
            '''SELECT block_index, block_hash, hash_parts, block_date, 
                      syra_count, validated_at 
               FROM mined_blocks 
               WHERE username = ? 
               ORDER BY validated_at DESC''',
            (current_user['username'],)
        ).fetchall()
        
        blocks = []
        for row in blocks_cursor:
            block_dict = dict(row)
            block_dict['hash_parts'] = json.loads(block_dict['hash_parts'])
            blocks.append(block_dict)
        
        # Estatísticas
        total_blocks = len(blocks)
        total_syra = sum(block['syra_count'] for block in blocks)
        
        conn.close()
        
        return jsonify({
            "blocks": blocks,
            "statistics": {
                "total_blocks": total_blocks,
                "total_syra_found": total_syra
            }
        })
        
    except Exception:
        logger.exception("Erro em /me/blocks")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/blocks/leaderboard', methods=['GET'])
@token_required
def get_blocks_leaderboard(current_user):
    """Retorna ranking dos usuários por blocos minerados"""
    try:
        conn = get_db_connection()
        
        leaderboard_cursor = conn.execute(
            '''SELECT username, 
                      COUNT(*) as total_blocks,
                      SUM(syra_count) as total_syra,
                      MAX(validated_at) as last_block
               FROM mined_blocks 
               GROUP BY username 
               ORDER BY total_syra DESC, total_blocks DESC
               LIMIT 50'''
        ).fetchall()
        
        leaderboard = [dict(row) for row in leaderboard_cursor]
        
        conn.close()
        
        return jsonify({"leaderboard": leaderboard})
        
    except Exception:
        logger.exception("Erro em /blocks/leaderboard")
        return jsonify({"error": "Erro interno"}), 500


# --- 4. Rotas de Eventos e Mapas (/events) ---
@app.route('/events', methods=['POST'])
@token_required
@rate_limited
def create_event(current_user):
    """Cria um novo evento no mapa"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dados do evento são obrigatórios"}), 400
        
        required_fields = ['title', 'latitude', 'longitude', 'start_date']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Campo '{field}' é obrigatório"}), 400
        
        title = data['title'].strip()
        description = data.get('description', '').strip()
        category_id = data.get('category_id')
        latitude = data['latitude']
        longitude = data['longitude']
        address = data.get('address', '').strip()
        start_date = data['start_date']
        end_date = data.get('end_date')
        max_participants = data.get('max_participants')
        
        # Validações
        if len(title) < 3 or len(title) > 200:
            return jsonify({"error": "Título deve ter entre 3 e 200 caracteres"}), 400
        
        if description and len(description) > 1000:
            return jsonify({"error": "Descrição deve ter no máximo 1000 caracteres"}), 400
        
        if not isinstance(latitude, (int, float)) or not (-90 <= latitude <= 90):
            return jsonify({"error": "Latitude deve ser um número entre -90 e 90"}), 400
        
        if not isinstance(longitude, (int, float)) or not (-180 <= longitude <= 180):
            return jsonify({"error": "Longitude deve ser um número entre -180 e 180"}), 400
        
        # Validação de data
        try:
            start_datetime = datetime.strptime(start_date, "%Y-%m-%d %H:%M:%S")
            if start_datetime <= datetime.utcnow():
                return jsonify({"error": "Data de início deve ser futura"}), 400
        except ValueError:
            return jsonify({"error": "Formato de data inválido. Use YYYY-MM-DD HH:MM:SS"}), 400
        
        if end_date:
            try:
                end_datetime = datetime.strptime(end_date, "%Y-%m-%d %H:%M:%S")
                if end_datetime <= start_datetime:
                    return jsonify({"error": "Data de fim deve ser posterior à data de início"}), 400
            except ValueError:
                return jsonify({"error": "Formato de data de fim inválido. Use YYYY-MM-DD HH:MM:SS"}), 400
        
        if max_participants and (not isinstance(max_participants, int) or max_participants < 1):
            return jsonify({"error": "Número máximo de participantes deve ser um inteiro positivo"}), 400
        
        conn = get_db_connection()
        
        # Verifica se a categoria existe (se especificada)
        if category_id:
            category = conn.execute('SELECT id FROM event_categories WHERE id = ?', (category_id,)).fetchone()
            if not category:
                conn.close()
                return jsonify({"error": "Categoria não encontrada"}), 404
        
        # Cria o evento
        cursor = conn.execute(
            '''INSERT INTO events 
               (creator_username, title, description, category_id, latitude, longitude, address, 
                start_date, end_date, max_participants) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (current_user['username'], title, description, category_id, latitude, longitude, 
             address, start_date, end_date, max_participants)
        )
        
        event_id = cursor.lastrowid
        
        # Gera QR code para o evento
        qr_code_data = generate_event_qr_code(event_id, title)
        if qr_code_data:
            conn.execute(
                'UPDATE events SET qr_code_data = ? WHERE id = ?',
                (qr_code_data, event_id)
            )
        qr_code_data = generate_event_qr_code(event_id, title)
        if qr_code_data:
            conn.execute(
                'UPDATE events SET qr_code_data = ? WHERE id = ?',
                (qr_code_data, event_id)
            )
        
        # Adiciona o criador como participante automático
        conn.execute(
            'INSERT INTO event_participants (event_id, username, status) VALUES (?, ?, ?)',
            (event_id, current_user['username'], 'creator')
        )
        
        conn.commit()
        conn.close()
        
        # Notifica usuários próximos
        notified_users = notify_users_in_radius(
            latitude, longitude, title, event_id, current_user['username']
        )
        
        log_action("EVENT_CREATED", current_user['username'], 
                  f"Evento: {title}, ID: {event_id}")
        
        return jsonify({
            "status": "success",
            "message": "Evento criado com sucesso!",
            "event": {
                "id": event_id,
                "title": title,
                "description": description,
                "latitude": latitude,
                "longitude": longitude,
                "address": address,
                "start_date": start_date,
                "end_date": end_date,
                "max_participants": max_participants,
                "creator": current_user['username']
            },
            "notifications_sent": len(notified_users)
        }), 201
        
    except Exception:
        logger.exception("Erro em create_event")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events', methods=['GET'])
@token_required
def list_events(current_user):
    """Lista todos os eventos ativos no mapa"""
    try:
        # Parâmetros de filtragem opcionais
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        radius = request.args.get('radius', type=float)
        limit = request.args.get('limit', 50, type=int)
        
        conn = get_db_connection()
        
        if lat and lon and radius:
            # Busca eventos dentro de um raio específico
            # Primeira filtragem por bounding box (mais eficiente)
            lat_delta = radius / 111.32  # Aproximação: 1 grau = 111.32 km
            lon_delta = radius / (111.32 * abs(math.cos(math.radians(lat))))
            
            min_lat, max_lat = lat - lat_delta, lat + lat_delta
            min_lon, max_lon = lon - lon_delta, lon + lon_delta
            
            events_cursor = conn.execute(
                '''SELECT e.*, u.bio as creator_bio, c.name as category_name, c.color as category_color,
                         COUNT(ep.username) as participant_count
                   FROM events e
                   LEFT JOIN users u ON e.creator_username = u.username
                   LEFT JOIN event_categories c ON e.category_id = c.id
                   LEFT JOIN event_participants ep ON e.id = ep.event_id
                   WHERE e.is_active = 1 AND e.start_date > CURRENT_TIMESTAMP
                   AND e.latitude BETWEEN ? AND ? AND e.longitude BETWEEN ? AND ?
                   GROUP BY e.id
                   ORDER BY e.start_date ASC
                   LIMIT ?''',
                (min_lat, max_lat, min_lon, max_lon, limit * 2)  # Busca mais para filtrar depois
            ).fetchall()
            
            # Filtra por distância exata usando Python
            filtered_events = []
            for event in events_cursor:
                distance = calculate_distance(lat, lon, event['latitude'], event['longitude'])
                if distance <= radius:
                    event_dict = dict(event)
                    event_dict['distance_km'] = round(distance, 2)
                    filtered_events.append(event_dict)
            
            events = sorted(filtered_events, key=lambda x: x['distance_km'])[:limit]
        else:
            # Busca todos os eventos ativos
            category_filter = request.args.get('category')
            where_clause = 'e.is_active = 1 AND e.start_date > CURRENT_TIMESTAMP'
            params = []
            
            if category_filter:
                where_clause += ' AND c.name = ?'
                params.append(category_filter)
            
            params.append(limit)
            
            events_cursor = conn.execute(
                f'''SELECT e.*, u.bio as creator_bio, c.name as category_name, c.color as category_color,
                          COUNT(ep.username) as participant_count
                    FROM events e
                    LEFT JOIN users u ON e.creator_username = u.username
                    LEFT JOIN event_categories c ON e.category_id = c.id
                    LEFT JOIN event_participants ep ON e.id = ep.event_id
                    WHERE {where_clause}
                    GROUP BY e.id
                    ORDER BY e.start_date ASC
                    LIMIT ?''',
                params
            ).fetchall()
            
            events = [dict(event) for event in events_cursor]
        
        conn.close()
        
        return jsonify({
            "events": events,
            "total_count": len(events),
            "filters_applied": {
                "location_filter": bool(lat and lon and radius),
                "radius_km": radius if radius else None
            }
        })
        
    except Exception:
        logger.exception("Erro em list_events")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>', methods=['GET'])
@token_required
def get_event_details(current_user, event_id):
    """Retorna detalhes completos de um evento"""
    try:
        conn = get_db_connection()
        
        # Busca o evento
        event = conn.execute(
            '''SELECT e.*, u.bio as creator_bio, c.name as category_name, c.color as category_color
               FROM events e
               LEFT JOIN users u ON e.creator_username = u.username
               LEFT JOIN event_categories c ON e.category_id = c.id
               WHERE e.id = ?''',
            (event_id,)
        ).fetchone()
        
        if not event:
            conn.close()
            return jsonify({"error": "Evento não encontrado"}), 404
        
        event_dict = dict(event)
        
        # Busca participantes
        participants = conn.execute(
            '''SELECT ep.username, ep.joined_at, ep.status, u.bio
               FROM event_participants ep
               LEFT JOIN users u ON ep.username = u.username
               WHERE ep.event_id = ?
               ORDER BY ep.joined_at ASC''',
            (event_id,)
        ).fetchall()
        
        # Busca estatísticas de comentários
        comment_stats = conn.execute(
            'SELECT COUNT(*) as total_comments FROM event_comments WHERE event_id = ?',
            (event_id,)
        ).fetchone()
        
        event_dict['participants'] = [dict(p) for p in participants]
        event_dict['participant_count'] = len(participants)
        event_dict['comment_count'] = comment_stats['total_comments']
        
        # Verifica se o usuário atual é participante
        is_participant = any(p['username'] == current_user['username'] for p in participants)
        event_dict['is_participant'] = is_participant
        event_dict['is_creator'] = event['creator_username'] == current_user['username']
        
        conn.close()
        
        return jsonify(event_dict)
        
    except Exception:
        logger.exception("Erro em get_event_details")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/join', methods=['POST'])
@token_required
def join_event(current_user, event_id):
    """Participa de um evento"""
    try:
        conn = get_db_connection()
        
        # Verifica se o evento existe e está ativo
        event = conn.execute(
            'SELECT title, max_participants, creator_username FROM events WHERE id = ? AND is_active = 1',
            (event_id,)
        ).fetchone()
        
        if not event:
            conn.close()
            return jsonify({"error": "Evento não encontrado ou inativo"}), 404
        
        # Verifica se já é participante
        existing_participation = conn.execute(
            'SELECT id FROM event_participants WHERE event_id = ? AND username = ?',
            (event_id, current_user['username'])
        ).fetchone()
        
        if existing_participation:
            conn.close()
            return jsonify({"error": "Você já é participante deste evento"}), 409
        
        # Verifica limite de participantes
        if event['max_participants']:
            current_count = conn.execute(
                'SELECT COUNT(*) as count FROM event_participants WHERE event_id = ?',
                (event_id,)
            ).fetchone()['count']
            
            if current_count >= event['max_participants']:
                conn.close()
                return jsonify({"error": "Evento lotado"}), 400
        
        # Adiciona participação
        conn.execute(
            'INSERT INTO event_participants (event_id, username) VALUES (?, ?)',
            (event_id, current_user['username'])
        )
        
        # Notifica o criador do evento
        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (event['creator_username'], 'event_join', 
             f"{current_user['username']} se juntou ao seu evento '{event['title']}'")
        )
        
        conn.commit()
        conn.close()
        
        log_action("EVENT_JOINED", current_user['username'], f"Evento ID: {event_id}")
        
        return jsonify({
            "status": "success",
            "message": f"Você se juntou ao evento '{event['title']}' com sucesso!"
        })
        
    except Exception:
        logger.exception("Erro em join_event")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/leave', methods=['DELETE'])
@token_required
def leave_event(current_user, event_id):
    """Sai de um evento"""
    try:
        conn = get_db_connection()
        
        # Verifica se é participante
        participation = conn.execute(
            '''SELECT ep.id, e.title, e.creator_username
               FROM event_participants ep
               JOIN events e ON ep.event_id = e.id
               WHERE ep.event_id = ? AND ep.username = ?''',
            (event_id, current_user['username'])
        ).fetchone()
        
        if not participation:
            conn.close()
            return jsonify({"error": "Você não é participante deste evento"}), 404
        
        # Criador não pode sair do próprio evento
        if participation['creator_username'] == current_user['username']:
            conn.close()
            return jsonify({"error": "Criador do evento não pode sair. Use cancelar evento."}), 400
        
        # Remove participação
        conn.execute(
            'DELETE FROM event_participants WHERE id = ?',
            (participation['id'],)
        )
        
        # Notifica o criador
        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (participation['creator_username'], 'event_leave', 
             f"{current_user['username']} saiu do seu evento '{participation['title']}'")
        )
        
        conn.commit()
        conn.close()
        
        log_action("EVENT_LEFT", current_user['username'], f"Evento ID: {event_id}")
        
        return jsonify({
            "status": "success",
            "message": f"Você saiu do evento '{participation['title']}'"
        })
        
    except Exception:
        logger.exception("Erro em leave_event")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/map/markers', methods=['GET'])
@token_required
def get_map_markers(current_user):
    """Retorna todos os marcadores para exibição no mapa (eventos + usuários)"""
    try:
        conn = get_db_connection()
        
        # Busca eventos ativos
        events = conn.execute(
            '''SELECT id, title, description, latitude, longitude, 
                      start_date, creator_username, 
                      COUNT(ep.username) as participant_count
               FROM events e
               LEFT JOIN event_participants ep ON e.id = ep.event_id
               WHERE e.is_active = 1 AND e.start_date > CURRENT_TIMESTAMP
               GROUP BY e.id'''
        ).fetchall()
        
        # Busca usuários com localização pública
        users = conn.execute(
            '''SELECT ul.username, ul.latitude, ul.longitude, ul.city, ul.state,
                      u.bio
               FROM user_locations ul
               JOIN users u ON ul.username = u.username
               WHERE ul.is_public = 1'''
        ).fetchall()
        
        conn.close()
        
        map_data = {
            "events": [
                {
                    "type": "event",
                    "id": event['id'],
                    "title": event['title'],
                    "description": event['description'],
                    "latitude": event['latitude'],
                    "longitude": event['longitude'],
                    "start_date": event['start_date'],
                    "creator": event['creator_username'],
                    "participant_count": event['participant_count']
                }
                for event in events
            ],
            "users": [
                {
                    "type": "user",
                    "username": user['username'],
                    "latitude": user['latitude'],
                    "longitude": user['longitude'],
                    "city": user['city'],
                    "state": user['state'],
                    "bio": user['bio']
                }
                for user in users
            ]
        }
        
        return jsonify(map_data)
        
    except Exception:
        logger.exception("Erro em get_map_markers")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/categories', methods=['GET'])
@token_required
def get_event_categories(current_user):
    """Lista todas as categorias de eventos disponíveis"""
    try:
        conn = get_db_connection()
        
        categories = conn.execute(
            'SELECT id, name, description, color, icon FROM event_categories ORDER BY name'
        ).fetchall()
        
        conn.close()
        
        return jsonify({
            "categories": [dict(cat) for cat in categories]
        })
        
    except Exception:
        logger.exception("Erro em get_event_categories")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/comments', methods=['GET'])
@token_required
def get_event_comments(current_user, event_id):
    """Lista comentários de um evento"""
    try:
        conn = get_db_connection()
        
        # Verifica se o evento existe
        event = conn.execute('SELECT id FROM events WHERE id = ?', (event_id,)).fetchone()
        if not event:
            conn.close()
            return jsonify({"error": "Evento não encontrado"}), 404
        
        # Busca comentários
        comments = conn.execute(
            '''SELECT ec.id, ec.username, ec.content, ec.parent_comment_id, 
                      ec.created_at, ec.updated_at, u.bio as user_bio
               FROM event_comments ec
               LEFT JOIN users u ON ec.username = u.username
               WHERE ec.event_id = ?
               ORDER BY ec.created_at ASC''',
            (event_id,)
        ).fetchall()
        
        conn.close()
        
        # Organiza comentários em thread (principais e respostas)
        comment_dict = {}
        main_comments = []
        
        for comment in comments:
            comment_data = dict(comment)
            comment_data['replies'] = []
            comment_dict[comment['id']] = comment_data
            
            if comment['parent_comment_id'] is None:
                main_comments.append(comment_data)
            else:
                parent = comment_dict.get(comment['parent_comment_id'])
                if parent:
                    parent['replies'].append(comment_data)
        
        return jsonify({
            "comments": main_comments,
            "total_count": len(comments)
        })
        
    except Exception:
        logger.exception("Erro em get_event_comments")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/comments', methods=['POST'])
@token_required
@rate_limited
def add_event_comment(current_user, event_id):
    """Adiciona comentário a um evento"""
    try:
        data = request.get_json()
        if not data or not data.get('content'):
            return jsonify({"error": "Conteúdo do comentário é obrigatório"}), 400
        
        content = data['content'].strip()
        parent_comment_id = data.get('parent_comment_id')
        
        if len(content) < 1 or len(content) > 1000:
            return jsonify({"error": "Comentário deve ter entre 1 e 1000 caracteres"}), 400
        
        conn = get_db_connection()
        
        # Verifica se o evento existe
        event = conn.execute('SELECT title FROM events WHERE id = ?', (event_id,)).fetchone()
        if not event:
            conn.close()
            return jsonify({"error": "Evento não encontrado"}), 404
        
        # Verifica se o comentário pai existe (se especificado)
        if parent_comment_id:
            parent_comment = conn.execute(
                'SELECT id FROM event_comments WHERE id = ? AND event_id = ?',
                (parent_comment_id, event_id)
            ).fetchone()
            if not parent_comment:
                conn.close()
                return jsonify({"error": "Comentário pai não encontrado"}), 404
        
        # Adiciona o comentário
        cursor = conn.execute(
            '''INSERT INTO event_comments (event_id, username, content, parent_comment_id)
               VALUES (?, ?, ?, ?)''',
            (event_id, current_user['username'], content, parent_comment_id)
        )
        
        comment_id = cursor.lastrowid
        
        # Notifica o criador do evento (se não for o próprio)
        event_creator = conn.execute(
            'SELECT creator_username FROM events WHERE id = ?', (event_id,)
        ).fetchone()
        
        if event_creator and event_creator['creator_username'] != current_user['username']:
            notification_content = f"Novo comentário no seu evento '{event['title']}': {content[:50]}..."
            conn.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (event_creator['creator_username'], 'event_comment', notification_content)
            )
        
        # Se for resposta, notifica o autor do comentário pai
        if parent_comment_id:
            parent_author = conn.execute(
                'SELECT username FROM event_comments WHERE id = ?', (parent_comment_id,)
            ).fetchone()
            
            if parent_author and parent_author['username'] != current_user['username']:
                conn.execute(
                    'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                    (parent_author['username'], 'comment_reply', 
                     f"{current_user['username']} respondeu seu comentário: {content[:50]}...")
                )
        
        conn.commit()
        conn.close()
        
        log_action("COMMENT_ADDED", current_user['username'], f"Evento ID: {event_id}")
        
        return jsonify({
            "status": "success",
            "message": f"Comentário adicionado com sucesso!",
            "comment_id": comment_id
        }), 201
        
    except Exception:
        logger.exception("Erro em add_event_comment")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/generate-validation-token', methods=['POST'])
@token_required
def generate_event_validation_token(current_user, event_id):
    """Gera token de validação temporário para check-in (30 segundos)"""
    try:
        conn = get_db_connection()
        
        # Verifica se é o criador do evento
        event = conn.execute(
            'SELECT creator_username, title FROM events WHERE id = ? AND is_active = 1',
            (event_id,)
        ).fetchone()
        
        if not event:
            conn.close()
            return jsonify({"error": "Evento não encontrado ou inativo"}), 404
        
        if event['creator_username'] != current_user['username']:
            conn.close()
            return jsonify({"error": "Apenas o criador do evento pode gerar tokens de validação"}), 403
        
        # Limpa tokens expirados
        cleanup_expired_tokens()
        
        # Gera novo token
        token = generate_validation_token()
        expires_at = datetime.utcnow() + timedelta(seconds=30)
        
        conn.execute(
            '''INSERT INTO validation_tokens (event_id, creator_username, token, expires_at)
               VALUES (?, ?, ?, ?)''',
            (event_id, current_user['username'], token, expires_at.isoformat())
        )
        
        conn.commit()
        conn.close()
        
        log_action("VALIDATION_TOKEN_GENERATED", current_user['username'], f"Evento ID: {event_id}")
        
        return jsonify({
            "status": "success",
            "token": token,
            "expires_in_seconds": 30,
            "expires_at": expires_at.isoformat(),
            "message": f"Token gerado para validação de presença no evento '{event['title']}'"
        })
        
    except Exception:
        logger.exception("Erro em generate_event_validation_token")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/validate-attendance', methods=['POST'])
@token_required
def validate_event_attendance(current_user, event_id):
    """Valida presença do usuário no evento usando token temporário"""
    try:
        data = request.get_json()
        if not data or not data.get('token'):
            return jsonify({"error": "Token de validação é obrigatório"}), 400
        
        token = data['token'].strip()
        
        conn = get_db_connection()
        
        # Verifica o token
        validation = conn.execute(
            '''SELECT vt.*, e.title, e.creator_username
               FROM validation_tokens vt
               JOIN events e ON vt.event_id = e.id
               WHERE vt.token = ? AND vt.event_id = ? 
               AND vt.expires_at > CURRENT_TIMESTAMP AND vt.is_used = 0''',
            (token, event_id)
        ).fetchone()
        
        if not validation:
            conn.close()
            return jsonify({"error": "Token inválido, expirado ou já utilizado"}), 400
        
        # Verifica se já fez check-in
        existing_checkin = conn.execute(
            'SELECT id FROM event_checkins WHERE event_id = ? AND username = ?',
            (event_id, current_user['username'])
        ).fetchone()
        
        if existing_checkin:
            conn.close()
            return jsonify({"error": "Você já fez check-in neste evento"}), 409
        
        # Gera código único e hash identificador
        attendance_code = secrets.token_hex(8).upper()
        hash_identifier = hashlib.sha256(f"{event_id}{current_user['username']}{attendance_code}".encode()).hexdigest()[:16]
        
        # Registra check-in
        conn.execute(
            '''INSERT INTO event_checkins (event_id, username, validation_code, hash_identifier)
               VALUES (?, ?, ?, ?)''',
            (event_id, current_user['username'], attendance_code, hash_identifier)
        )
        
        # Marca token como usado
        conn.execute(
            'UPDATE validation_tokens SET is_used = 1, used_by = ? WHERE id = ?',
            (current_user['username'], validation['id'])
        )
        
        # Notifica o criador do evento
        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (validation['creator_username'], 'attendance_confirmed',
             f"{current_user['username']} confirmou presença no evento '{validation['title']}'")
        )
        
        conn.commit()
        conn.close()
        
        log_action("EVENT_ATTENDANCE_VALIDATED", current_user['username'], f"Evento ID: {event_id}")
        
        return jsonify({
            "status": "success",
            "message": f"Presença confirmada no evento '{validation['title']}'!",
            "attendance_code": attendance_code,
            "hash_identifier": hash_identifier,
            "event_title": validation['title']
        })
        
    except Exception:
        logger.exception("Erro em validate_event_attendance")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/settings', methods=['GET'])
@token_required
def get_user_settings(current_user):
    """Retorna configurações do usuário"""
    try:
        conn = get_db_connection()
        
        settings = conn.execute(
            'SELECT notifications, privacy FROM user_settings WHERE username = ?',
            (current_user['username'],)
        ).fetchone()
        
        conn.close()
        
        if settings:
            return jsonify({
                "notifications": json.loads(settings['notifications']),
                "privacy": json.loads(settings['privacy'])
            })
        else:
            # Retorna configurações padrão se não existirem
            return jsonify(get_default_user_settings())
        
    except Exception:
        logger.exception("Erro em get_user_settings")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/settings', methods=['PUT'])
@token_required
def update_user_settings(current_user):
    """Atualiza configurações do usuário"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dados de configuração são obrigatórios"}), 400
        
        # Valida estrutura das configurações
        notifications = data.get('notifications', {})
        privacy = data.get('privacy', {})
        
        # Valida opções de privacidade
        valid_location_options = ["everyone", "followers", "none"]
        valid_profile_options = ["public", "followers_only"]
        
        if privacy.get('show_location_on_map') and privacy['show_location_on_map'] not in valid_location_options:
            return jsonify({"error": "Opção de localização inválida"}), 400
        
        if privacy.get('profile_visibility') and privacy['profile_visibility'] not in valid_profile_options:
            return jsonify({"error": "Opção de visibilidade inválida"}), 400
        
        conn = get_db_connection()
        
        # Insere ou atualiza configurações
        conn.execute(
            '''INSERT OR REPLACE INTO user_settings (username, notifications, privacy, updated_at)
               VALUES (?, ?, ?, CURRENT_TIMESTAMP)''',
            (current_user['username'], json.dumps(notifications), json.dumps(privacy))
        )
        
        conn.commit()
        conn.close()
        
        log_action("SETTINGS_UPDATED", current_user['username'])
        
        return jsonify({
            "status": "success",
            "message": "Configurações atualizadas com sucesso",
            "settings": {
                "notifications": notifications,
                "privacy": privacy
            }
        })
        
    except Exception:
        logger.exception("Erro em update_user_settings")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/report', methods=['POST'])
@token_required
@rate_limited
def create_report(current_user):
    """Cria uma denúncia/relatório"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dados da denúncia são obrigatórios"}), 400
        
        required_fields = ['target_type', 'target_id', 'reason']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Campo '{field}' é obrigatório"}), 400
        
        target_type = data['target_type'].lower()
        target_id = data['target_id']
        reason = data['reason']
        details = data.get('details', '').strip()
        
        # Valida tipos de alvo
        valid_target_types = ['event', 'user', 'comment']
        if target_type not in valid_target_types:
            return jsonify({"error": "Tipo de alvo inválido"}), 400
        
        # Valida razões
        valid_reasons = ['spam_or_scam', 'hate_speech', 'inappropriate_content', 'harassment', 'fake_profile', 'other']
        if reason not in valid_reasons:
            return jsonify({"error": "Razão inválida"}), 400
        
        conn = get_db_connection()
        
        # Verifica se o alvo existe
        if target_type == 'event':
            target_exists = conn.execute('SELECT id FROM events WHERE id = ?', (target_id,)).fetchone()
        elif target_type == 'user':
            target_exists = conn.execute('SELECT username FROM users WHERE username = ?', (target_id,)).fetchone()
        elif target_type == 'comment':
            target_exists = conn.execute('SELECT id FROM event_comments WHERE id = ?', (target_id,)).fetchone()
        
        if not target_exists:
            conn.close()
            return jsonify({"error": "Alvo da denúncia não encontrado"}), 404
        
        # Cria a denúncia
        conn.execute(
            '''INSERT INTO reports (reporter_username, target_type, target_id, reason, details)
               VALUES (?, ?, ?, ?, ?)''',
            (current_user['username'], target_type, target_id, reason, details)
        )
        
        conn.commit()
        conn.close()
        
        log_action("REPORT_CREATED", current_user['username'], f"{target_type}:{target_id} - {reason}")
        
        return jsonify({
            "status": "success",
            "message": "Denúncia registrada com sucesso. Nossa equipe irá analisar em breve."
        }), 201
        
    except Exception:
        logger.exception("Erro em create_report")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/block', methods=['POST'])
@token_required
def block_user(current_user, target_username):
    """Bloqueia um usuário"""
    try:
        target_username = target_username.lower()
        my_username = current_user['username']
        
        if target_username == my_username:
            return jsonify({"error": "Você não pode bloquear a si mesmo"}), 400
        
        conn = get_db_connection()
        
        # Verifica se o usuário existe
        target_user = conn.execute('SELECT username FROM users WHERE username = ?', (target_username,)).fetchone()
        if not target_user:
            conn.close()
            return jsonify({"error": "Usuário não encontrado"}), 404
        
        # Verifica se já está bloqueado
        existing_block = conn.execute(
            'SELECT id FROM user_blocks WHERE blocker_username = ? AND blocked_username = ?',
            (my_username, target_username)
        ).fetchone()
        
        if existing_block:
            conn.close()
            return jsonify({"error": "Usuário já está bloqueado"}), 409
        
        # Bloqueia o usuário
        conn.execute(
            'INSERT INTO user_blocks (blocker_username, blocked_username) VALUES (?, ?)',
            (my_username, target_username)
        )
        
        conn.commit()
        conn.close()
        
        log_action("USER_BLOCKED", my_username, f"Bloqueado: {target_username}")
        
        return jsonify({
            "status": "success",
            "message": f"Usuário '{target_username}' foi bloqueado com sucesso"
        })
        
    except Exception:
        logger.exception("Erro em block_user")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/unblock', methods=['DELETE'])
@token_required
def unblock_user(current_user, target_username):
    """Desbloqueia um usuário"""
    try:
        target_username = target_username.lower()
        my_username = current_user['username']
        
        conn = get_db_connection()
        
        # Remove o bloqueio
        result = conn.execute(
            'DELETE FROM user_blocks WHERE blocker_username = ? AND blocked_username = ?',
            (my_username, target_username)
        )
        
        if result.rowcount == 0:
            conn.close()
            return jsonify({"error": "Usuário não estava bloqueado"}), 404
        
        conn.commit()
        conn.close()
        
        log_action("USER_UNBLOCKED", my_username, f"Desbloqueado: {target_username}")
        
        return jsonify({
            "status": "success",
            "message": f"Usuário '{target_username}' foi desbloqueado com sucesso"
        })
        
    except Exception:
        logger.exception("Erro em unblock_user")
        return jsonify({"error": "Erro interno"}), 500


# --- 5. Rotas de Carteira (/wallet) ---
@app.route('/wallet/create', methods=['POST'])
@token_required
def create_wallet(current_user):
    """Cria uma carteira para o usuário"""
    try:
        conn = get_db_connection()
        
        # Verifica se já existe carteira
        existing_wallet = conn.execute(
            'SELECT wallet_code FROM wallets WHERE username = ?',
            (current_user['username'],)
        ).fetchone()
        
        if existing_wallet:
            conn.close()
            return jsonify({
                "status": "exists",
                "message": "Você já possui uma carteira",
                "wallet_code": existing_wallet['wallet_code'],
                "note": "Código de segurança já foi enviado anteriormente"
            })
        
        # Gera códigos únicos
        while True:
            wallet_code = f"{current_user['username']}#{secrets.token_hex(4).upper()}"
            security_code, security_hash = generate_security_code()
            
            if not conn.execute('SELECT id FROM wallets WHERE wallet_code = ?', (wallet_code,)).fetchone():
                break
        
        # Cria a carteira com hash do código
        conn.execute(
            'INSERT INTO wallets (username, wallet_code, security_code) VALUES (?, ?, ?)',
            (current_user['username'], wallet_code, security_hash)
        )
        conn.commit()
        conn.close()
        
        log_action("WALLET_CREATED", current_user['username'])
        
        return jsonify({
            "status": "success",
            "message": "Carteira criada com sucesso!",
            "wallet_code": wallet_code,
            "security_code": security_code,
            "warning": "IMPORTANTE: Guarde seu código de segurança em local seguro! Ele não poderá ser recuperado.",
            "note": "Em uma implementação real, este código seria enviado por SMS/email"
        }), 201
        
    except Exception:
        logger.exception("Erro em /wallet/create")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/wallet/info', methods=['GET'])
@token_required
def get_wallet_info(current_user):
    """Retorna informações da carteira do usuário"""
    try:
        conn = get_db_connection()
        
        wallet = conn.execute(
            'SELECT wallet_code, balance, created_at FROM wallets WHERE username = ?',
            (current_user['username'],)
        ).fetchone()
        
        if not wallet:
            # Cria carteira automaticamente se não existir
            wallet_code = create_wallet_for_user(current_user['username'])
            if wallet_code:
                wallet = conn.execute(
                    'SELECT wallet_code, balance, created_at FROM wallets WHERE username = ?',
                    (current_user['username'],)
                ).fetchone()
        
        if not wallet:
            conn.close()
            return jsonify({"error": "Erro ao criar carteira"}), 500
        
        # Busca histórico de transações recentes
        transactions = conn.execute(
            '''SELECT from_username, to_username, amount, transaction_type, 
                      description, created_at 
               FROM transactions 
               WHERE from_username = ? OR to_username = ? 
               ORDER BY created_at DESC 
               LIMIT 10''',
            (current_user['username'], current_user['username'])
        ).fetchall()
        
        conn.close()
        
        return jsonify({
            "wallet_code": wallet['wallet_code'],
            "balance": wallet['balance'],
            "created_at": wallet['created_at'],
            "recent_transactions": [dict(tx) for tx in transactions]
        })
        
    except Exception:
        logger.exception("Erro em /wallet/info")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/wallet/transfer', methods=['POST'])
@token_required
@rate_limited
def transfer_tokens(current_user):
    """Transfere tokens entre usuários"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dados da transferência são obrigatórios"}), 400
        
        required_fields = ['to_username', 'amount', 'security_code']
        for field in required_fields:
            if field not in data:
                return jsonify({"error": f"Campo '{field}' é obrigatório"}), 400
        
        to_username = data['to_username'].strip().lower()
        amount = data['amount']
        security_code = data['security_code'].strip()
        description = data.get('description', '').strip()
        
        # Validações
        if not isinstance(amount, int) or amount <= 0:
            return jsonify({"error": "Quantidade deve ser um número inteiro positivo"}), 400
        
        if to_username == current_user['username']:
            return jsonify({"error": "Você não pode transferir para si mesmo"}), 400
        
        conn = get_db_connection()
        
        # Verifica carteira do remetente
        sender_wallet = conn.execute(
            'SELECT balance, security_code FROM wallets WHERE username = ?',
            (current_user['username'],)
        ).fetchone()
        
        if not sender_wallet:
            conn.close()
            return jsonify({"error": "Você não possui uma carteira"}), 404
        
        # Verifica código de segurança usando hash seguro
        if not verify_security_code(security_code, sender_wallet['security_code']):
            conn.close()
            log_action("TRANSFER_SECURITY_FAILED", current_user['username'])
            return jsonify({"error": "Código de segurança inválido"}), 401
        
        # Verifica saldo
        if sender_wallet['balance'] < amount:
            conn.close()
            return jsonify({"error": "Saldo insuficiente"}), 400
        
        # Verifica se o destinatário existe
        recipient = conn.execute(
            'SELECT username FROM users WHERE username = ?',
            (to_username,)
        ).fetchone()
        
        if not recipient:
            conn.close()
            return jsonify({"error": f"Usuário '{to_username}' não encontrado"}), 404
        
        # Cria carteira do destinatário se não existir
        recipient_wallet = conn.execute(
            'SELECT username FROM wallets WHERE username = ?',
            (to_username,)
        ).fetchone()
        
        if not recipient_wallet:
            create_wallet_for_user(to_username)
        
        # Executa a transferência em transação atômica
        try:
            conn.execute('BEGIN IMMEDIATE TRANSACTION')
            
            # Verifica saldo novamente dentro da transação (proteção contra condições de corrida)
            current_balance = conn.execute(
                'SELECT balance FROM wallets WHERE username = ?',
                (current_user['username'],)
            ).fetchone()['balance']
            
            if current_balance < amount:
                conn.execute('ROLLBACK')
                conn.close()
                return jsonify({"error": "Saldo insuficiente"}), 400
            
            # Executa transferência
            conn.execute(
                'UPDATE wallets SET balance = balance - ? WHERE username = ?',
                (amount, current_user['username'])
            )
            
            conn.execute(
                'UPDATE wallets SET balance = balance + ? WHERE username = ?',
                (amount, to_username)
            )
            
            # Registra a transação
            conn.execute(
                '''INSERT INTO transactions 
                   (from_username, to_username, amount, transaction_type, description) 
                   VALUES (?, ?, ?, ?, ?)''',
                (current_user['username'], to_username, amount, 'transfer', description)
            )
            
            # Notifica o destinatário
            conn.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (to_username, 'token_received', 
                 f"Você recebeu {amount} tokens de {current_user['username']}")
            )
            
            conn.execute('COMMIT')
            
        except Exception as e:
            conn.execute('ROLLBACK')
            conn.close()
            logger.exception("Erro na transferência: %s", e)
            return jsonify({"error": "Erro durante a transferência"}), 500
        conn.close()
        
        log_action("TOKENS_TRANSFERRED", current_user['username'], 
                  f"Para: {to_username}, Quantidade: {amount}")
        
        return jsonify({
            "status": "success",
            "message": f"Transferência de {amount} tokens para '{to_username}' realizada com sucesso!"
        })
        
    except Exception:
        logger.exception("Erro em /wallet/transfer")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/search', methods=['GET'])
@token_required
def global_search(current_user):
    """Busca global unificada"""
    try:
        query = request.args.get('q', '').strip()
        search_type = request.args.get('type', 'all').lower()
        lat = request.args.get('lat', type=float)
        lon = request.args.get('lon', type=float)
        radius = request.args.get('radius', type=float)
        limit = request.args.get('limit', 20, type=int)
        
        if not query and search_type == 'all':
            return jsonify({"error": "Parâmetro de busca 'q' é obrigatório"}), 400
        
        conn = get_db_connection()
        results = {}
        
        # Busca eventos
        if search_type in ['all', 'event']:
            event_query = '''
                SELECT e.*, c.name as category_name, COUNT(ep.username) as participant_count
                FROM events e
                LEFT JOIN event_categories c ON e.category_id = c.id
                LEFT JOIN event_participants ep ON e.id = ep.event_id
                WHERE e.is_active = 1 AND e.start_date > CURRENT_TIMESTAMP
            '''
            params = []
            
            if query:
                event_query += ' AND (e.title LIKE ? OR e.description LIKE ? OR c.name LIKE ?)'
                search_term = f'%{query}%'
                params.extend([search_term, search_term, search_term])
            
            if lat and lon and radius:
                lat_delta = radius / 111.32
                lon_delta = radius / (111.32 * abs(math.cos(math.radians(lat))))
                event_query += ' AND e.latitude BETWEEN ? AND ? AND e.longitude BETWEEN ? AND ?'
                params.extend([lat - lat_delta, lat + lat_delta, lon - lon_delta, lon + lon_delta])
            
            event_query += ' GROUP BY e.id ORDER BY e.start_date ASC LIMIT ?'
            params.append(limit)
            
            events = conn.execute(event_query, params).fetchall()
            results['events'] = [dict(event) for event in events]
        
        # Busca usuários
        if search_type in ['all', 'user']:
            if query:
                users = conn.execute(
                    'SELECT username, bio FROM users WHERE username LIKE ? OR bio LIKE ? LIMIT ?',
                    (f'%{query}%', f'%{query}%', limit)
                ).fetchall()
                results['users'] = [dict(user) for user in users]
        
        # Busca categorias
        if search_type in ['all', 'category']:
            if query:
                categories = conn.execute(
                    'SELECT * FROM event_categories WHERE name LIKE ? OR description LIKE ? LIMIT ?',
                    (f'%{query}%', f'%{query}%', limit)
                ).fetchall()
                results['categories'] = [dict(cat) for cat in categories]
        
        conn.close()
        
        return jsonify({
            "query": query,
            "search_type": search_type,
            "results": results,
            "filters": {
                "location_filter": bool(lat and lon and radius),
                "radius_km": radius if radius else None
            }
        })
        
    except Exception:
        logger.exception("Erro em global_search")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/analytics', methods=['GET'])
@token_required
def get_event_analytics(current_user, event_id):
    """Analytics do evento (apenas para criador)"""
    try:
        conn = get_db_connection()
        
        # Verifica se é o criador do evento
        event = conn.execute(
            'SELECT creator_username, title FROM events WHERE id = ?',
            (event_id,)
        ).fetchone()
        
        if not event:
            conn.close()
            return jsonify({"error": "Evento não encontrado"}), 404
        
        if event['creator_username'] != current_user['username']:
            conn.close()
            return jsonify({"error": "Apenas o criador pode ver analytics do evento"}), 403
        
        # Coleta métricas
        participant_count = conn.execute(
            'SELECT COUNT(*) as count FROM event_participants WHERE event_id = ?',
            (event_id,)
        ).fetchone()['count']
        
        checkin_count = conn.execute(
            'SELECT COUNT(*) as count FROM event_checkins WHERE event_id = ?',
            (event_id,)
        ).fetchone()['count']
        
        comment_count = conn.execute(
            'SELECT COUNT(*) as count FROM event_comments WHERE event_id = ?',
            (event_id,)
        ).fetchone()['count']
        
        # Participantes por dia (últimos 7 dias)
        daily_joins = conn.execute(
            '''SELECT DATE(joined_at) as join_date, COUNT(*) as joins
               FROM event_participants 
               WHERE event_id = ? AND joined_at >= date('now', '-7 days')
               GROUP BY DATE(joined_at)
               ORDER BY join_date''',
            (event_id,)
        ).fetchall()
        
        conn.close()
        
        analytics = {
            "event_id": event_id,
            "event_title": event['title'],
            "participant_count": participant_count,
            "checkin_count": checkin_count,
            "comment_count": comment_count,
            "attendance_rate": round((checkin_count / participant_count * 100), 2) if participant_count > 0 else 0,
            "daily_joins": [dict(row) for row in daily_joins]
        }
        
        return jsonify(analytics)
        
    except Exception:
        logger.exception("Erro em get_event_analytics")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/status', methods=['GET'])
def api_status():
    """Status público da API"""
    try:
        # Verifica saúde do banco
        conn = get_db_connection()
        conn.execute('SELECT 1').fetchone()
        conn.close()
        
        # Limpa dados expirados
        deactivated_count = deactivate_expired_events()
        cleanup_expired_tokens()
        
        return jsonify({
            "status": "operational",
            "version": "4.0.0",
            "message": "Todos os sistemas estão operando normalmente.",
            "timestamp": datetime.utcnow().isoformat(),
            "maintenance": {
                "expired_events_cleaned": deactivated_count
            }
        })
        
    except Exception as e:
        logger.exception("Erro em api_status: %s", e)
        return jsonify({
            "status": "degraded_performance",
            "version": "4.0.0", 
            "message": "Alguns sistemas podem estar instáveis.",
            "timestamp": datetime.utcnow().isoformat()
        }), 503


# --- 6. Rotas de Administração (/admin) ---
@app.route('/admin/logs', methods=['GET'])
@admin_required
def view_logs():
    try:
        limit = request.args.get('limit', 100, type=int)
        conn = get_db_connection()
        logs = conn.execute('SELECT * FROM logs ORDER BY timestamp DESC LIMIT ?', (limit,)).fetchall()
        conn.close()
        log_action("ADMIN_VIEW_LOGS", "admin")
        return jsonify([dict(row) for row in logs])
    except Exception:
        logger.exception("Erro em view_logs")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/admin/db/reset', methods=['POST'])
@admin_required
def admin_reset_db():
    try:
        if os.path.exists(DB_NAME):
            os.remove(DB_NAME)
        init_db()
        log_action("ADMIN_DB_RESET", "admin")
        return jsonify({"status": "success", "message": "Banco de dados resetado e reinicializado."})
    except Exception as e:
        logger.exception("Erro em admin_reset_db: %s", e)
        log_action("ADMIN_DB_RESET_FAILED", "admin", str(e))
        return jsonify({"error": f"Falha ao resetar o banco de dados: {e}"}), 500


# --- Rotas de Convites para Eventos ---
@app.route('/events/<int:event_id>/invite', methods=['POST'])
@token_required
def invite_to_event(current_user, event_id):
    """Convida usuários para um evento privado"""
    try:
        data = request.get_json()
        usernames = data.get('usernames', [])
        
        if not usernames:
            return jsonify({"error": "Lista de usuários é obrigatória"}), 400
        
        db = get_db()
        
        # Verifica se o evento existe e é do usuário
        event = db.execute(
            'SELECT creator_username, title, is_private FROM events WHERE id = ?',
            (event_id,)
        ).fetchone()
        
        if not event:
            return jsonify({"error": "Evento não encontrado"}), 404
        
        if event['creator_username'] != current_user['username']:
            return jsonify({"error": "Apenas o criador pode convidar usuários"}), 403
        
        if not event['is_private']:
            return jsonify({"error": "Apenas eventos privados permitem convites"}), 400
        
        invited_count = 0
        errors = []
        
        for username in usernames:
            try:
                # Verifica se o usuário existe
                user_exists = db.execute(
                    'SELECT id FROM users WHERE username = ?', (username,)
                ).fetchone()
                
                if not user_exists:
                    errors.append(f"Usuário '{username}' não encontrado")
                    continue
                
                # Verifica se já foi convidado
                existing_invite = db.execute(
                    'SELECT id FROM event_invites WHERE event_id = ? AND invited_username = ?',
                    (event_id, username)
                ).fetchone()
                
                if existing_invite:
                    errors.append(f"Usuário '{username}' já foi convidado")
                    continue
                
                # Cria o convite
                db.execute(
                    'INSERT INTO event_invites (event_id, inviter_username, invited_username) VALUES (?, ?, ?)',
                    (event_id, current_user['username'], username)
                )
                
                # Notifica o usuário
                broadcast_notification(
                    username,
                    'event_invite',
                    f"Convite para evento: {event['title']}",
                    {"event_id": event_id}
                )
                
                invited_count += 1
                
            except Exception as e:
                errors.append(f"Erro ao convidar '{username}': {str(e)}")
        
        db.commit()
        
        result = {
            "status": "success",
            "invited_count": invited_count,
            "total_requested": len(usernames)
        }
        
        if errors:
            result["errors"] = errors
        
        return jsonify(result)
        
    except Exception:
        logger.exception("Erro em invite_to_event")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/invites', methods=['GET'])
@token_required
def get_my_event_invites(current_user):
    """Lista convites de eventos pendentes"""
    try:
        db = get_db()
        
        invites = db.execute(
            '''SELECT ei.id, ei.event_id, ei.inviter_username, ei.created_at, ei.status,
                      e.title, e.description, e.start_date, e.latitude, e.longitude
               FROM event_invites ei
               JOIN events e ON ei.event_id = e.id
               WHERE ei.invited_username = ? AND ei.status = 'pending'
               ORDER BY ei.created_at DESC''',
            (current_user['username'],)
        ).fetchall()
        
        return jsonify([dict(invite) for invite in invites])
        
    except Exception:
        logger.exception("Erro em get_my_event_invites")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/invites/<int:invite_id>/respond', methods=['POST'])
@token_required
def respond_to_invite(current_user, invite_id):
    """Responde a um convite de evento"""
    try:
        data = request.get_json()
        response = data.get('response')  # 'accepted' ou 'declined'
        
        if response not in ['accepted', 'declined']:
            return jsonify({"error": "Resposta deve ser 'accepted' ou 'declined'"}), 400
        
        db = get_db()
        
        # Verifica se o convite existe e é do usuário
        invite = db.execute(
            '''SELECT ei.id, ei.event_id, ei.status, e.title, e.max_participants,
                      COUNT(ec.id) as current_participants
               FROM event_invites ei
               JOIN events e ON ei.event_id = e.id
               LEFT JOIN event_checkins ec ON e.id = ec.event_id
               WHERE ei.id = ? AND ei.invited_username = ? AND ei.status = 'pending'
               GROUP BY ei.id''',
            (invite_id, current_user['username'])
        ).fetchone()
        
        if not invite:
            return jsonify({"error": "Convite não encontrado ou já respondido"}), 404
        
        # Se aceito, verifica capacidade do evento
        if response == 'accepted':
            if invite['current_participants'] >= invite['max_participants']:
                return jsonify({"error": "Evento lotado"}), 409
        
        # Atualiza o status do convite
        db.execute(
            'UPDATE event_invites SET status = ?, responded_at = CURRENT_TIMESTAMP WHERE id = ?',
            (response, invite_id)
        )
        
        db.commit()
        
        log_action("EVENT_INVITE_RESPONDED", current_user['username'], 
                  f"Resposta: {response} para evento: {invite['title']}")
        
        return jsonify({
            "status": "success",
            "message": f"Convite {response} com sucesso",
            "event_name": invite['title']
        })
        
    except Exception:
        logger.exception("Erro em respond_to_invite")
        return jsonify({"error": "Erro interno"}), 500


# --- Rotas de Moderação de Eventos ---
@app.route('/events/<int:event_id>/comments/<int:comment_id>', methods=['DELETE'])
@token_required
def delete_event_comment(current_user, event_id, comment_id):
    """Permite que o criador do evento apague comentários inadequados"""
    try:
        db = get_db()
        
        # Verifica se o comentário existe e obtém dados do evento
        comment_data = db.execute(
            '''SELECT ec.id, ec.author_username, e.creator_username, e.title
               FROM event_comments ec
               JOIN events e ON ec.event_id = e.id
               WHERE ec.id = ? AND e.id = ?''',
            (comment_id, event_id)
        ).fetchone()
        
        if not comment_data:
            return jsonify({"error": "Comentário ou evento não encontrado"}), 404
        
        # Verifica se o usuário atual é o criador do evento
        if comment_data['creator_username'] != current_user['username']:
            return jsonify({"error": "Apenas o criador do evento pode apagar comentários"}), 403
        
        # Remove o comentário
        db.execute('DELETE FROM event_comments WHERE id = ?', (comment_id,))
        db.commit()
        
        # Notifica o autor do comentário removido
        if comment_data['author_username'] != current_user['username']:
            db.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (comment_data['author_username'], 'comment_removed', 
                 f"Seu comentário foi removido do evento: {comment_data['title']}")
            )
            db.commit()
        
        log_action("COMMENT_DELETED", current_user['username'], 
                  f"Comentário removido do evento {event_id}")
        
        return jsonify({"status": "success", "message": "Comentário removido com sucesso"})
        
    except Exception:
        logger.exception("Erro em delete_event_comment")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/events/<int:event_id>/participants/<string:username>', methods=['DELETE'])
@token_required
def remove_event_participant(current_user, event_id, username):
    """Remove/expulsa um participante do evento"""
    try:
        db = get_db()
        
        # Verifica se o evento existe e se o usuário é o criador
        event = db.execute(
            'SELECT creator_username, title FROM events WHERE id = ?',
            (event_id,)
        ).fetchone()
        
        if not event:
            return jsonify({"error": "Evento não encontrado"}), 404
        
        if event['creator_username'] != current_user['username']:
            return jsonify({"error": "Apenas o criador pode remover participantes"}), 403
        
        # Remove o participante (check-ins)
        result = db.execute(
            'DELETE FROM event_checkins WHERE event_id = ? AND username = ?',
            (event_id, username)
        )
        
        if result.rowcount == 0:
            return jsonify({"error": "Usuário não está participando do evento"}), 404
        
        db.commit()
        
        # Notifica o usuário removido
        db.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (username, 'removed_from_event', 
             f"Você foi removido do evento: {event['title']}")
        )
        db.commit()
        
        log_action("PARTICIPANT_REMOVED", current_user['username'], 
                  f"Usuário {username} removido do evento {event_id}")
        
        return jsonify({"status": "success", "message": f"Usuário {username} removido do evento"})
        
    except Exception:
        logger.exception("Erro em remove_event_participant")
        return jsonify({"error": "Erro interno"}), 500


# --- Rotas de Usuários Bloqueados ---
@app.route('/me/blocked-users', methods=['GET'])
@token_required
def get_blocked_users(current_user):
    """Lista usuários bloqueados pelo usuário atual"""
    try:
        db = get_db()
        
        blocked_users = db.execute(
            'SELECT blocked_username, created_at FROM user_blocks WHERE blocker_username = ? ORDER BY created_at DESC',
            (current_user['username'],)
        ).fetchall()
        
        return jsonify({
            "blocked_users": [dict(user) for user in blocked_users],
            "count": len(blocked_users)
        })
        
    except Exception:
        logger.exception("Erro em get_blocked_users")
        return jsonify({"error": "Erro interno"}), 500


# --- Rotas de Histórico de Eventos ---
@app.route('/me/events/history', methods=['GET'])
@token_required
def get_events_history(current_user):
    """Lista eventos passados nos quais o usuário fez check-in"""
    try:
        db = get_db()
        
        # Busca eventos passados com check-in do usuário
        events_history = db.execute(
            '''SELECT e.id, e.title, e.description, e.start_date, e.end_date,
                      e.latitude, e.longitude, e.address, ec.checkin_time,
                      cat.name as category_name
               FROM event_checkins ec
               JOIN events e ON ec.event_id = e.id
               LEFT JOIN event_categories cat ON e.category_id = cat.id
               WHERE ec.username = ? AND e.end_date < datetime('now')
               ORDER BY e.end_date DESC''',
            (current_user['username'],)
        ).fetchall()
        
        return jsonify({
            "events_history": [dict(event) for event in events_history],
            "count": len(events_history)
        })
        
    except Exception:
        logger.exception("Erro em get_events_history")
        return jsonify({"error": "Erro interno"}), 500


# --- Rotas de Carteira/Tokens ---
@app.route('/me/wallet/tokens', methods=['GET'])
@token_required
def get_wallet_tokens(current_user):
    """Lista tokens/blocos minerados na carteira do usuário"""
    try:
        db = get_db()
        
        # Busca dados da carteira
        wallet = db.execute(
            'SELECT balance, wallet_code FROM wallets WHERE username = ?',
            (current_user['username'],)
        ).fetchone()
        
        if not wallet:
            return jsonify({"error": "Carteira não encontrada"}), 404
        
        # Busca blocos minerados pelo usuário
        mined_blocks = db.execute(
            '''SELECT block_hash, syra_count, validated_at, difficulty_level
               FROM mined_blocks 
               WHERE username = ? 
               ORDER BY validated_at DESC''',
            (current_user['username'],)
        ).fetchall()
        
        # Busca transações recentes
        recent_transactions = db.execute(
            '''SELECT transaction_id, from_username, to_username, amount, created_at
               FROM transactions 
               WHERE from_username = ? OR to_username = ?
               ORDER BY created_at DESC
               LIMIT 10''',
            (current_user['username'], current_user['username'])
        ).fetchall()
        
        return jsonify({
            "wallet": {
                "balance": wallet['balance'],
                "wallet_code": wallet['wallet_code']
            },
            "mined_blocks": [dict(block) for block in mined_blocks],
            "recent_transactions": [dict(tx) for tx in recent_transactions],
            "total_blocks": len(mined_blocks)
        })
        
    except Exception:
        logger.exception("Erro em get_wallet_tokens")
        return jsonify({"error": "Erro interno"}), 500


# --- Sistema de Mensagens Diretas ---
@app.route('/messages/send', methods=['POST'])
@token_required
def send_message(current_user):
    """Envia mensagem direta para outro usuário"""
    try:
        data = request.get_json()
        to_username = data.get('to_username')
        content = data.get('content')
        
        if not to_username or not content:
            return jsonify({"error": "Destinatário e conteúdo são obrigatórios"}), 400
        
        if len(content.strip()) == 0:
            return jsonify({"error": "Conteúdo não pode estar vazio"}), 400
        
        if len(content) > 1000:
            return jsonify({"error": "Mensagem muito longa (máximo 1000 caracteres)"}), 400
        
        db = get_db()
        
        # Verifica se o destinatário existe
        recipient = db.execute(
            'SELECT username FROM users WHERE username = ?', (to_username,)
        ).fetchone()
        
        if not recipient:
            return jsonify({"error": "Usuário destinatário não encontrado"}), 404
        
        # Verifica se não está bloqueado
        is_blocked = db.execute(
            'SELECT id FROM user_blocks WHERE blocker_username = ? AND blocked_username = ?',
            (to_username, current_user['username'])
        ).fetchone()
        
        if is_blocked:
            return jsonify({"error": "Não é possível enviar mensagem para este usuário"}), 403
        
        # Envia a mensagem
        cursor = db.execute(
            'INSERT INTO messages (sender_username, receiver_username, content) VALUES (?, ?, ?)',
            (current_user['username'], to_username, content.strip())
        )
        
        message_id = cursor.lastrowid
        db.commit()
        
        # Envia notificação
        db.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (to_username, 'new_message', f"Nova mensagem de {current_user['username']}")
        )
        db.commit()
        
        log_action("MESSAGE_SENT", current_user['username'], f"Para: {to_username}")
        
        return jsonify({
            "status": "success",
            "message": "Mensagem enviada com sucesso",
            "message_id": message_id
        })
        
    except Exception:
        logger.exception("Erro em send_message")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/messages/conversation/<string:username>', methods=['GET'])
@token_required
def get_conversation(current_user, username):
    """Lista histórico de mensagens com um usuário específico"""
    try:
        limit = request.args.get('limit', 50, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        db = get_db()
        
        # Busca mensagens da conversa
        messages = db.execute(
            '''SELECT id, sender_username, receiver_username, content, created_at, is_read
               FROM messages 
               WHERE (sender_username = ? AND receiver_username = ?) 
                  OR (sender_username = ? AND receiver_username = ?)
               ORDER BY created_at DESC
               LIMIT ? OFFSET ?''',
            (current_user['username'], username, username, current_user['username'], limit, offset)
        ).fetchall()
        
        # Marca mensagens recebidas como lidas
        db.execute(
            'UPDATE messages SET is_read = 1 WHERE sender_username = ? AND receiver_username = ? AND is_read = 0',
            (username, current_user['username'])
        )
        db.commit()
        
        return jsonify({
            "conversation": [dict(msg) for msg in reversed(messages)],
            "count": len(messages),
            "with_user": username
        })
        
    except Exception:
        logger.exception("Erro em get_conversation")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/messages/inbox', methods=['GET'])
@token_required
def get_message_inbox(current_user):
    """Lista todas as conversas do usuário"""
    try:
        db = get_db()
        
        # Busca últimas mensagens de cada conversa
        conversations = db.execute(
            '''SELECT 
                   CASE 
                       WHEN sender_username = ? THEN receiver_username 
                       ELSE sender_username 
                   END as other_user,
                   MAX(created_at) as last_message_time,
                   (SELECT content FROM messages m2 
                    WHERE ((m2.sender_username = ? AND m2.receiver_username = other_user) 
                           OR (m2.sender_username = other_user AND m2.receiver_username = ?))
                    ORDER BY m2.created_at DESC LIMIT 1) as last_message,
                   (SELECT COUNT(*) FROM messages m3
                    WHERE m3.sender_username = other_user AND m3.receiver_username = ? AND m3.is_read = 0) as unread_count
               FROM messages 
               WHERE sender_username = ? OR receiver_username = ?
               GROUP BY other_user
               ORDER BY last_message_time DESC''',
            (current_user['username'], current_user['username'], current_user['username'], 
             current_user['username'], current_user['username'], current_user['username'])
        ).fetchall()
        
        return jsonify({
            "conversations": [dict(conv) for conv in conversations],
            "count": len(conversations)
        })
        
    except Exception:
        logger.exception("Erro em get_message_inbox")
        return jsonify({"error": "Erro interno"}), 500


# --- Rotas de Grupos/Comunidades ---
@app.route('/groups', methods=['POST'])
@token_required
def create_group(current_user):
    """Cria um novo grupo/comunidade"""
    try:
        data = request.get_json()
        name = data.get('name')
        description = data.get('description', '')
        is_private = data.get('is_private', False)
        
        if not name or len(name.strip()) == 0:
            return jsonify({"error": "Nome do grupo é obrigatório"}), 400
        
        if len(name) > 100:
            return jsonify({"error": "Nome muito longo (máximo 100 caracteres)"}), 400
        
        db = get_db()
        
        # Verifica se nome já existe
        existing = db.execute(
            'SELECT id FROM groups WHERE name = ?', (name.strip(),)
        ).fetchone()
        
        if existing:
            return jsonify({"error": "Já existe um grupo com este nome"}), 409
        
        # Cria o grupo
        cursor = db.execute(
            'INSERT INTO groups (name, description, creator_username, is_private) VALUES (?, ?, ?, ?)',
            (name.strip(), description.strip(), current_user['username'], is_private)
        )
        
        group_id = cursor.lastrowid
        
        # Adiciona o criador como admin do grupo
        db.execute(
            'INSERT INTO group_members (group_id, username, role) VALUES (?, ?, ?)',
            (group_id, current_user['username'], 'admin')
        )
        
        db.commit()
        
        log_action("GROUP_CREATED", current_user['username'], f"Grupo: {name}")
        
        return jsonify({
            "status": "success",
            "message": "Grupo criado com sucesso",
            "group_id": group_id,
            "name": name
        })
        
    except Exception:
        logger.exception("Erro em create_group")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/groups/<int:group_id>/join', methods=['POST'])
@token_required
def join_group(current_user, group_id):
    """Entra em um grupo"""
    try:
        db = get_db()
        
        # Verifica se o grupo existe
        group = db.execute(
            'SELECT name, is_private FROM groups WHERE id = ?', (group_id,)
        ).fetchone()
        
        if not group:
            return jsonify({"error": "Grupo não encontrado"}), 404
        
        # Verifica se já é membro
        existing_member = db.execute(
            'SELECT id FROM group_members WHERE group_id = ? AND username = ?',
            (group_id, current_user['username'])
        ).fetchone()
        
        if existing_member:
            return jsonify({"error": "Você já é membro deste grupo"}), 409
        
        # Para grupos privados, seria necessário lógica de convite (simplificado aqui)
        if group['is_private']:
            return jsonify({"error": "Este é um grupo privado. É necessário convite."}), 403
        
        # Adiciona como membro
        db.execute(
            'INSERT INTO group_members (group_id, username) VALUES (?, ?)',
            (group_id, current_user['username'])
        )
        db.commit()
        
        log_action("GROUP_JOINED", current_user['username'], f"Grupo ID: {group_id}")
        
        return jsonify({
            "status": "success",
            "message": f"Você entrou no grupo '{group['name']}'"
        })
        
    except Exception:
        logger.exception("Erro em join_group")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/groups/<int:group_id>/create-event', methods=['POST'])
@token_required
def create_group_event(current_user, group_id):
    """Cria um evento associado a um grupo"""
    try:
        data = request.get_json()
        required_fields = ['name', 'description', 'start_time', 'latitude', 'longitude']
        for field in required_fields:
            if not data.get(field):
                return jsonify({"error": f"Campo '{field}' é obrigatório"}), 400
        
        db = get_db()
        
        # Verifica se é membro do grupo
        member = db.execute(
            'SELECT role FROM group_members WHERE group_id = ? AND username = ?',
            (group_id, current_user['username'])
        ).fetchone()
        
        if not member:
            return jsonify({"error": "Você não é membro deste grupo"}), 403
        
        # Validação da data
        start_time = data['start_time']
        try:
            datetime.fromisoformat(start_time.replace('Z', '+00:00'))
        except ValueError:
            return jsonify({"error": "Formato de data inválido. Use ISO 8601."}), 400
        
        # Validação de coordenadas
        try:
            lat = float(data['latitude'])
            lng = float(data['longitude'])
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                raise ValueError
        except ValueError:
            return jsonify({"error": "Coordenadas inválidas"}), 400
        
        # Cria o evento (assumindo que a tabela events tem um campo group_id)
        max_participants = data.get('max_participants', 100)
        category_id = data.get('category_id')
        
        cursor = db.execute(
            '''INSERT INTO events 
               (creator_username, title, description, start_date, latitude, longitude, 
                category_id, max_participants) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)''',
            (current_user['username'], data['name'], data['description'], 
             start_time, lat, lng, category_id, max_participants)
        )
        
        event_id = cursor.lastrowid
        db.commit()
        
        # Notifica membros do grupo
        group_members = db.execute(
            'SELECT username FROM group_members WHERE group_id = ? AND username != ?',
            (group_id, current_user['username'])
        ).fetchall()
        
        for member in group_members:
            db.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (member['username'], 'group_event', f"Novo evento no grupo: {data['name']}")
            )
        
        db.commit()
        
        log_action("GROUP_EVENT_CREATED", current_user['username'], f"Evento: {data['name']} no grupo {group_id}")
        
        return jsonify({
            "status": "success", 
            "message": "Evento do grupo criado com sucesso",
            "event_id": event_id
        })
        
    except Exception:
        logger.exception("Erro em create_group_event")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/groups/<int:group_id>/feed', methods=['GET'])
@token_required
def get_group_feed(current_user, group_id):
    """Obtém feed de posts do grupo"""
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        db = get_db()
        
        # Verifica se é membro do grupo
        member = db.execute(
            'SELECT id FROM group_members WHERE group_id = ? AND username = ?',
            (group_id, current_user['username'])
        ).fetchone()
        
        if not member:
            return jsonify({"error": "Você não é membro deste grupo"}), 403
        
        # Busca posts do grupo
        posts = db.execute(
            '''SELECT p.id, p.author_username, p.content, p.image_url, p.latitude, p.longitude, p.created_at,
                      COUNT(pl.id) as likes_count,
                      COUNT(pc.id) as comments_count,
                      EXISTS(SELECT 1 FROM post_likes pl2 WHERE pl2.post_id = p.id AND pl2.username = ?) as user_liked
               FROM posts p
               LEFT JOIN post_likes pl ON p.id = pl.post_id
               LEFT JOIN post_comments pc ON p.id = pc.post_id
               WHERE p.group_id = ?
               GROUP BY p.id
               ORDER BY p.created_at DESC
               LIMIT ? OFFSET ?''',
            (current_user['username'], group_id, limit, offset)
        ).fetchall()
        
        return jsonify({
            "posts": [dict(post) for post in posts],
            "count": len(posts)
        })
        
    except Exception:
        logger.exception("Erro em get_group_feed")
        return jsonify({"error": "Erro interno"}), 500


# --- Rotas de Posts/Publicações ---
@app.route('/posts', methods=['POST'])
@token_required
def create_post(current_user):
    """Cria um novo post pessoal ou em grupo"""
    try:
        data = request.get_json()
        content = data.get('content')
        group_id = data.get('group_id')  # None para post pessoal
        image_url = data.get('image_url')
        latitude = data.get('latitude')
        longitude = data.get('longitude')
        
        if not content or len(content.strip()) == 0:
            return jsonify({"error": "Conteúdo é obrigatório"}), 400
        
        if len(content) > 2000:
            return jsonify({"error": "Post muito longo (máximo 2000 caracteres)"}), 400
        
        db = get_db()
        
        # Se for post em grupo, verifica se é membro
        if group_id:
            member = db.execute(
                'SELECT id FROM group_members WHERE group_id = ? AND username = ?',
                (group_id, current_user['username'])
            ).fetchone()
            
            if not member:
                return jsonify({"error": "Você não é membro deste grupo"}), 403
        
        # Cria o post
        cursor = db.execute(
            'INSERT INTO posts (author_username, content, group_id, image_url, latitude, longitude) VALUES (?, ?, ?, ?, ?, ?)',
            (current_user['username'], content.strip(), group_id, image_url, latitude, longitude)
        )
        
        post_id = cursor.lastrowid
        db.commit()
        
        # Notifica seguidores se for post pessoal
        if not group_id:
            followers = db.execute(
                'SELECT follower_username FROM followers WHERE followed_username = ?',
                (current_user['username'],)
            ).fetchall()
            
            for follower in followers:
                db.execute(
                    'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                    (follower['follower_username'], 'new_post', f"{current_user['username']} fez uma nova publicação")
                )
            
            db.commit()
        
        log_action("POST_CREATED", current_user['username'], f"Post ID: {post_id}")
        
        return jsonify({
            "status": "success",
            "message": "Post criado com sucesso",
            "post_id": post_id
        })
        
    except Exception:
        logger.exception("Erro em create_post")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/posts/<int:post_id>/like', methods=['POST'])
@token_required
def like_post(current_user, post_id):
    """Curte ou descurte um post"""
    try:
        db = get_db()
        
        # Verifica se o post existe
        post = db.execute(
            'SELECT author_username FROM posts WHERE id = ?', (post_id,)
        ).fetchone()
        
        if not post:
            return jsonify({"error": "Post não encontrado"}), 404
        
        # Verifica se já curtiu
        existing_like = db.execute(
            'SELECT id FROM post_likes WHERE post_id = ? AND username = ?',
            (post_id, current_user['username'])
        ).fetchone()
        
        if existing_like:
            # Remove curtida
            db.execute(
                'DELETE FROM post_likes WHERE post_id = ? AND username = ?',
                (post_id, current_user['username'])
            )
            action = "descurtido"
        else:
            # Adiciona curtida
            db.execute(
                'INSERT INTO post_likes (post_id, username) VALUES (?, ?)',
                (post_id, current_user['username'])
            )
            
            # Notifica autor se não for ele mesmo
            if post['author_username'] != current_user['username']:
                db.execute(
                    'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                    (post['author_username'], 'post_liked', f"{current_user['username']} curtiu sua publicação")
                )
            
            action = "curtido"
        
        db.commit()
        
        return jsonify({
            "status": "success",
            "message": f"Post {action} com sucesso"
        })
        
    except Exception:
        logger.exception("Erro em like_post")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/posts/<int:post_id>/comments', methods=['POST'])
@token_required
def comment_on_post(current_user, post_id):
    """Comenta em um post"""
    try:
        data = request.get_json()
        content = data.get('content')
        
        if not content or len(content.strip()) == 0:
            return jsonify({"error": "Comentário não pode estar vazio"}), 400
        
        if len(content) > 500:
            return jsonify({"error": "Comentário muito longo (máximo 500 caracteres)"}), 400
        
        db = get_db()
        
        # Verifica se o post existe
        post = db.execute(
            'SELECT author_username FROM posts WHERE id = ?', (post_id,)
        ).fetchone()
        
        if not post:
            return jsonify({"error": "Post não encontrado"}), 404
        
        # Adiciona comentário
        cursor = db.execute(
            'INSERT INTO post_comments (post_id, author_username, content) VALUES (?, ?, ?)',
            (post_id, current_user['username'], content.strip())
        )
        
        comment_id = cursor.lastrowid
        
        # Notifica autor do post se não for ele mesmo
        if post['author_username'] != current_user['username']:
            db.execute(
                'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
                (post['author_username'], 'post_commented', f"{current_user['username']} comentou em sua publicação")
            )
        
        db.commit()
        
        return jsonify({
            "status": "success",
            "message": "Comentário adicionado com sucesso",
            "comment_id": comment_id
        })
        
    except Exception:
        logger.exception("Erro em comment_on_post")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/feed', methods=['GET'])
@token_required
def get_personal_feed(current_user):
    """Obtém feed personalizado com posts de quem o usuário segue"""
    try:
        limit = request.args.get('limit', 20, type=int)
        offset = request.args.get('offset', 0, type=int)
        
        db = get_db()
        
        # Busca posts de pessoas que o usuário segue + próprios posts
        posts = db.execute(
            '''SELECT p.id, p.author_username, p.content, p.image_url, p.latitude, p.longitude, p.created_at,
                      COUNT(DISTINCT pl.id) as likes_count,
                      COUNT(DISTINCT pc.id) as comments_count,
                      EXISTS(SELECT 1 FROM post_likes pl2 WHERE pl2.post_id = p.id AND pl2.username = ?) as user_liked,
                      g.name as group_name
               FROM posts p
               LEFT JOIN post_likes pl ON p.id = pl.post_id
               LEFT JOIN post_comments pc ON p.id = pc.post_id
               LEFT JOIN groups g ON p.group_id = g.id
               WHERE (p.author_username IN (
                   SELECT followed_username FROM followers WHERE follower_username = ?
               ) OR p.author_username = ?)
               AND (p.group_id IS NULL OR p.group_id IN (
                   SELECT group_id FROM group_members WHERE username = ?
               ))
               GROUP BY p.id
               ORDER BY p.created_at DESC
               LIMIT ? OFFSET ?''',
            (current_user['username'], current_user['username'], current_user['username'], 
             current_user['username'], limit, offset)
        ).fetchall()
        
        return jsonify({
            "feed": [dict(post) for post in posts],
            "count": len(posts)
        })
        
    except Exception:
        logger.exception("Erro em get_personal_feed")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/groups', methods=['GET'])
@token_required
def list_groups(current_user):
    """Lista grupos disponíveis ou do usuário"""
    try:
        my_groups_only = request.args.get('my_groups', 'false').lower() == 'true'
        
        db = get_db()
        
        if my_groups_only:
            # Lista apenas grupos do usuário
            groups = db.execute(
                '''SELECT g.id, g.name, g.description, g.creator_username, g.is_private, g.created_at,
                          COUNT(gm.id) as member_count,
                          gm.role as user_role
                   FROM groups g
                   JOIN group_members gm ON g.id = gm.group_id
                   LEFT JOIN group_members gm2 ON g.id = gm2.group_id
                   WHERE gm.username = ?
                   GROUP BY g.id
                   ORDER BY g.created_at DESC''',
                (current_user['username'],)
            ).fetchall()
        else:
            # Lista grupos públicos
            groups = db.execute(
                '''SELECT g.id, g.name, g.description, g.creator_username, g.is_private, g.created_at,
                          COUNT(gm.id) as member_count,
                          EXISTS(SELECT 1 FROM group_members gm2 WHERE gm2.group_id = g.id AND gm2.username = ?) as is_member
                   FROM groups g
                   LEFT JOIN group_members gm ON g.id = gm.group_id
                   WHERE g.is_private = 0
                   GROUP BY g.id
                   ORDER BY member_count DESC, g.created_at DESC''',
                (current_user['username'],)
            ).fetchall()
        
        return jsonify({
            "groups": [dict(group) for group in groups],
            "count": len(groups)
        })
        
    except Exception:
        logger.exception("Erro em list_groups")
        return jsonify({"error": "Erro interno"}), 500


# --- Handlers de erro gerais ---
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Rota não encontrada"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.exception("Internal server error: %s", e)
    return jsonify({"error": "Erro interno do servidor"}), 500


# --- Bloco de Execução Principal (apenas para run local) ---
if __name__ == '__main__':
    # porta para desenvolvimento — Render/Gunicorn define PORT e não executa esse bloco
    port = int(os.getenv('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)