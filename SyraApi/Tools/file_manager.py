import os
import shutil
from typing import Optional

# Diretório base para pastas dos usuários
USER_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "DB", "user_data")

def ensure_user_data_directory():
    """
    Garante que o diretório principal de dados dos usuários existe
    """
    if not os.path.exists(USER_DATA_DIR):
        os.makedirs(USER_DATA_DIR)
        print(f"[+] Diretório de dados de usuários criado: {USER_DATA_DIR}")

def create_user_directory(user_hash: str) -> str:
    """
    Cria diretório pessoal para um usuário usando seu hash único
    Retorna o caminho completo do diretório
    """
    ensure_user_data_directory()
    
    user_dir = os.path.join(USER_DATA_DIR, user_hash)
    
    if not os.path.exists(user_dir):
        os.makedirs(user_dir)
        
        # Cria subpastas padrão
        subdirs = ["uploads", "documents", "images", "temp"]
        for subdir in subdirs:
            os.makedirs(os.path.join(user_dir, subdir), exist_ok=True)
        
        print(f"[+] Diretório do usuário criado: {user_dir}")
    
    return user_dir

def delete_user_directory(user_hash: str) -> bool:
    """
    Remove o diretório de um usuário
    """
    user_dir = os.path.join(USER_DATA_DIR, user_hash)
    
    if os.path.exists(user_dir):
        try:
            shutil.rmtree(user_dir)
            print(f"[+] Diretório do usuário removido: {user_dir}")
            return True
        except Exception as e:
            print(f"[-] Erro ao remover diretório: {e}")
            return False
    
    return False

def get_user_directory(user_hash: str) -> Optional[str]:
    """
    Retorna o caminho do diretório do usuário se existir
    """
    user_dir = os.path.join(USER_DATA_DIR, user_hash)
    
    if os.path.exists(user_dir):
        return user_dir
    
    return None

def save_user_file(user_hash: str, file_content: bytes, filename: str, subfolder: str = "uploads") -> Optional[str]:
    """
    Salva um arquivo no diretório do usuário
    Retorna o caminho completo do arquivo salvo
    """
    user_dir = get_user_directory(user_hash)
    
    if not user_dir:
        return None
    
    file_path = os.path.join(user_dir, subfolder, filename)
    
    try:
        with open(file_path, "wb") as f:
            f.write(file_content)
        return file_path
    except Exception as e:
        print(f"[-] Erro ao salvar arquivo: {e}")
        return None
