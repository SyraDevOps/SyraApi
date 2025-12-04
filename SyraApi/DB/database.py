from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os

# Caminho do banco de dados SQLite
DATABASE_PATH = os.path.join(os.path.dirname(__file__), "syra_users.db")
DATABASE_URL = f"sqlite:///{DATABASE_PATH}"

# Engine e sessão
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},  # Necessário para SQLite
    echo=False  # Mude para True se quiser ver SQL logs
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base para os modelos
Base = declarative_base()

def get_db():
    """
    Dependency para obter sessão do banco de dados
    Uso: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def init_db():
    """
    Inicializa o banco de dados criando todas as tabelas
    """
    from Modelos.user import User
    from Modelos.conversation import Conversation, Message
    from Modelos.notification import Notification
    from Modelos.location import LocationLive, LocationHistory, UserBond, MeetingInvite
    from Modelos.user_node import X25519KeyPair, QRCode, Device, NodeRegistry, APIRegistry
    from Modelos.temp_messages import TemporaryMessage
    from Modelos.ai_models import UserAIModel, AIKnowledgeBase, AICommand, AIConversation, UserDataset
    from Modelos.agenda import Compromisso
    from Modelos.social_models import UserFile, UserNote, Post, Comentario, PostLike
    
    # Cria todas as tabelas usando a Base única
    Base.metadata.create_all(bind=engine)
    
    # Executa migrações para adicionar novas colunas
    try:
        from DB.migrate import migrate_database
        migrate_database()
    except Exception as e:
        print(f"[!] Aviso: Migração não executada: {e}")
    
    print("[+] Banco de dados inicializado com sucesso!")
    print("[+] Tabelas criadas: users, conversations, messages, notifications,")
    print("    locations_live, locations_history, user_bonds, meeting_invites,")
    print("    x25519_keypairs, qrcodes, devices, node_registry, api_registry,")
    print("    temporary_messages, user_ai_models, ai_knowledge_base, ai_commands,")
    print("    ai_conversations, user_datasets, compromissos, user_files,")
    print("    user_notes, posts, comentarios, post_likes")

