# -*- coding: utf-8 -*-
"""
API Syra - Versão 2.9.0 (pronta para deploy no Render)
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
- Notificações automáticas por proximidade geográfica
- Rate limiting baseado em banco de dados (suporte a múltiplos workers)
- Associação de blocos validados aos usuários
- Tratamento melhorado de concorrência
- Proteção por JWT e rota de administração com token
- Trivial rota raiz e handler de erros para respostas JSON

Para rodar em produção (Render):
- Build Command: pip install -r requirements.txt
- Start Command: gunicorn -w 4 -b 0.0.0.0:5000 api:app

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
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS

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
                following TEXT DEFAULT '[]',
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
                latitude REAL NOT NULL,
                longitude REAL NOT NULL,
                address TEXT,
                start_date TIMESTAMP NOT NULL,
                end_date TIMESTAMP,
                max_participants INTEGER,
                is_active INTEGER DEFAULT 1,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (creator_username) REFERENCES users (username)
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
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_event_participants ON event_participants (event_id, username)')

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
            conn = get_db_connection()
            current_user = conn.execute('SELECT id, username, bio, following, created_at FROM users WHERE username = ?', (data['username'],)).fetchone()
            conn.close()
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


# --- ROTAS DA API ---

@app.route('/')
def root():
    return jsonify({"message": f"{APP_NAME} API running", "version": "2.9.0"})

# --- 0. Rota de Saúde da API ---
@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({"status": "ok", "version": "2.9.0", "timestamp": datetime.utcnow().isoformat()})

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
        # Converte following de JSON string para lista
        if current_user.get('following'):
            current_user['following'] = json.loads(current_user['following'])
        else:
            current_user['following'] = []
        return jsonify(current_user)
    except Exception:
        logger.exception("Erro em /me/profile")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/summary', methods=['GET'])
@token_required
def get_my_summary(current_user):
    try:
        conn = get_db_connection()
        
        # Conta notificações não lidas
        unread_notifications = conn.execute(
            'SELECT COUNT(*) as count FROM notifications WHERE username = ? AND is_read = 0',
            (current_user['username'],)
        ).fetchone()['count']
        
        # Converte following de JSON para lista para contar
        following_list = json.loads(current_user.get('following', '[]'))
        following_count = len(following_list)
        
        # Conta quantos usuários seguem este usuário
        followers_cursor = conn.execute(
            'SELECT COUNT(*) as count FROM users WHERE following LIKE ?',
            (f'%"{current_user["username"]}"%',)
        ).fetchone()
        followers_count = followers_cursor['count'] if followers_cursor else 0
        
        conn.close()
        
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
        
        conn = get_db_connection()
        
        # Verifica se o usuário existe
        if not conn.execute('SELECT id FROM users WHERE username = ?', (target_username,)).fetchone():
            conn.close()
            return jsonify({"error": f"Usuário '{target_username}' não encontrado"}), 404
        
        # Obtém lista atual de usuários seguidos
        following_list = json.loads(current_user.get('following', '[]'))
        
        if target_username in following_list:
            conn.close()
            return jsonify({"error": f"Você já segue '{target_username}'"}), 409
        
        # Adiciona à lista
        following_list.append(target_username)
        
        conn.execute(
            'UPDATE users SET following = ? WHERE username = ?',
            (json.dumps(following_list), my_username)
        )
        
        # Envia notificação para o usuário seguido
        conn.execute(
            'INSERT INTO notifications (username, type, content) VALUES (?, ?, ?)',
            (target_username, 'new_follower', my_username)
        )
        
        conn.commit()
        conn.close()
        
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
        
        # Obtém lista atual de usuários seguidos
        following_list = json.loads(current_user.get('following', '[]'))
        
        if target_username not in following_list:
            return jsonify({"error": f"Você não segue '{target_username}'"}), 404
        
        # Remove da lista
        following_list.remove(target_username)
        
        conn = get_db_connection()
        conn.execute(
            'UPDATE users SET following = ? WHERE username = ?',
            (json.dumps(following_list), my_username)
        )
        conn.commit()
        conn.close()
        
        log_action("USER_UNFOLLOWED", my_username, f"Parou de seguir: {target_username}")
        return jsonify({"status": "success", "message": f"Você parou de seguir '{target_username}'"})
    except Exception:
        logger.exception("Erro em unfollow_user")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/me/following', methods=['GET'])
@token_required
def get_my_following(current_user):
    try:
        following_list = json.loads(current_user.get('following', '[]'))
        return jsonify({"following": following_list, "count": len(following_list)})
    except Exception:
        logger.exception("Erro em /me/following")
        return jsonify({"error": "Erro interno"}), 500


@app.route('/users/<string:target_username>/profile', methods=['GET'])
@token_required
def get_user_profile(current_user, target_username):
    """Retorna perfil público de um usuário"""
    try:
        target_username = target_username.lower()
        conn = get_db_connection()
        
        # Busca dados do usuário
        user = conn.execute(
            'SELECT username, bio, created_at FROM users WHERE username = ?',
            (target_username,)
        ).fetchone()
        
        if not user:
            conn.close()
            return jsonify({"error": f"Usuário '{target_username}' não encontrado"}), 404
        
        user_dict = dict(user)
        
        # Busca estatísticas de mineração
        mining_stats = conn.execute(
            '''SELECT COUNT(*) as total_blocks, 
                      SUM(syra_count) as total_syra,
                      MAX(validated_at) as last_mining
               FROM mined_blocks WHERE username = ?''',
            (target_username,)
        ).fetchone()
        
        # Busca saldo da carteira
        wallet = conn.execute(
            'SELECT balance FROM wallets WHERE username = ?',
            (target_username,)
        ).fetchone()
        
        # Conta seguidores e seguindo
        followers_count = conn.execute(
            'SELECT COUNT(*) as count FROM users WHERE following LIKE ?',
            (f'%"{target_username}"%',)
        ).fetchone()['count']
        
        following_count = 0
        following_data = conn.execute(
            'SELECT following FROM users WHERE username = ?',
            (target_username,)
        ).fetchone()
        
        if following_data and following_data['following']:
            following_list = json.loads(following_data['following'])
            following_count = len(following_list)
        
        conn.close()
        
        # Gera QR code do perfil
        qr_code = generate_user_qr_code(target_username)
        
        # Verifica se o usuário atual segue este perfil
        current_following = json.loads(current_user.get('following', '[]'))
        is_following = target_username in current_following
        
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
        
        # Cria o evento
        cursor = conn.execute(
            '''INSERT INTO events 
               (creator_username, title, description, latitude, longitude, address, 
                start_date, end_date, max_participants) 
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
            (current_user['username'], title, description, latitude, longitude, 
             address, start_date, end_date, max_participants)
        )
        
        event_id = cursor.lastrowid
        
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
            # Nota: Esta é uma aproximação simples, para produção usar PostGIS
            events_cursor = conn.execute(
                '''SELECT e.*, u.bio as creator_bio,
                         COUNT(ep.username) as participant_count
                   FROM events e
                   LEFT JOIN users u ON e.creator_username = u.username
                   LEFT JOIN event_participants ep ON e.id = ep.event_id
                   WHERE e.is_active = 1 AND e.start_date > CURRENT_TIMESTAMP
                   GROUP BY e.id
                   ORDER BY e.start_date ASC
                   LIMIT ?''',
                (limit,)
            ).fetchall()
            
            # Filtra por distância usando Python
            filtered_events = []
            for event in events_cursor:
                distance = calculate_distance(lat, lon, event['latitude'], event['longitude'])
                if distance <= radius:
                    event_dict = dict(event)
                    event_dict['distance_km'] = round(distance, 2)
                    filtered_events.append(event_dict)
            
            events = sorted(filtered_events, key=lambda x: x['distance_km'])
        else:
            # Busca todos os eventos ativos
            events_cursor = conn.execute(
                '''SELECT e.*, u.bio as creator_bio,
                         COUNT(ep.username) as participant_count
                   FROM events e
                   LEFT JOIN users u ON e.creator_username = u.username
                   LEFT JOIN event_participants ep ON e.id = ep.event_id
                   WHERE e.is_active = 1 AND e.start_date > CURRENT_TIMESTAMP
                   GROUP BY e.id
                   ORDER BY e.start_date ASC
                   LIMIT ?''',
                (limit,)
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
            '''SELECT e.*, u.bio as creator_bio
               FROM events e
               LEFT JOIN users u ON e.creator_username = u.username
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
        
        event_dict['participants'] = [dict(p) for p in participants]
        event_dict['participant_count'] = len(participants)
        
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