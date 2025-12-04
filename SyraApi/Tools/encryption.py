"""
Utilitários de criptografia para proteção de dados sensíveis
AES-256-GCM para criptografar chaves privadas e API keys
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import base64
import secrets


class EncryptionManager:
    """
    Gerenciador de criptografia AES-256-GCM
    Utiliza PBKDF2 para derivação de chave a partir de senha mestra
    """
    
    def __init__(self, master_password: str = None):
        """
        Inicializa o gerenciador com senha mestra
        Se não fornecida, usa variável de ambiente SYRA_MASTER_KEY
        """
        if master_password is None:
            master_password = os.getenv("SYRA_MASTER_KEY", "SYRA_DEFAULT_MASTER_KEY_CHANGE_IN_PRODUCTION")
        
        self.master_password = master_password.encode('utf-8')
    
    def _derive_key(self, salt: bytes) -> bytes:
        """
        Deriva uma chave AES-256 (32 bytes) a partir da senha mestra usando PBKDF2
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(self.master_password)
    
    def encrypt(self, plaintext: str) -> str:
        """
        Criptografa texto usando AES-256-GCM
        Retorna: base64(salt:nonce:ciphertext:tag)
        """
        # Gerar salt e nonce aleatórios
        salt = os.urandom(16)
        nonce = os.urandom(12)
        
        # Derivar chave
        key = self._derive_key(salt)
        
        # Criptografar
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        
        # Formato: salt:nonce:ciphertext (ciphertext já inclui tag)
        encrypted_data = salt + nonce + ciphertext
        
        # Retornar em base64
        return base64.b64encode(encrypted_data).decode('utf-8')
    
    def decrypt(self, encrypted_base64: str) -> str:
        """
        Descriptografa texto cifrado com AES-256-GCM
        """
        try:
            # Decodificar de base64
            encrypted_data = base64.b64decode(encrypted_base64.encode('utf-8'))
            
            # Extrair componentes
            salt = encrypted_data[:16]
            nonce = encrypted_data[16:28]
            ciphertext = encrypted_data[28:]
            
            # Derivar chave
            key = self._derive_key(salt)
            
            # Descriptografar
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
            
            return plaintext.decode('utf-8')
        except Exception as e:
            raise ValueError(f"Falha ao descriptografar: {str(e)}")
    
    def encrypt_dict(self, data: dict) -> str:
        """
        Criptografa um dicionário convertendo para JSON
        """
        import json
        json_str = json.dumps(data, ensure_ascii=False)
        return self.encrypt(json_str)
    
    def decrypt_dict(self, encrypted_base64: str) -> dict:
        """
        Descriptografa e retorna um dicionário
        """
        import json
        decrypted_str = self.decrypt(encrypted_base64)
        return json.loads(decrypted_str)


def generate_secure_token(length: int = 32) -> str:
    """
    Gera um token seguro aleatório
    """
    return secrets.token_urlsafe(length)


def hash_data(data: str) -> str:
    """
    Gera hash SHA256 de dados (para verificação de integridade)
    """
    from hashlib import sha256
    return sha256(data.encode('utf-8')).hexdigest()


# Singleton global
_encryption_manager = None

def get_encryption_manager() -> EncryptionManager:
    """
    Retorna instância singleton do gerenciador de criptografia
    """
    global _encryption_manager
    if _encryption_manager is None:
        _encryption_manager = EncryptionManager()
    return _encryption_manager


# Funções de conveniência
def encrypt_sensitive_data(plaintext: str) -> str:
    """Criptografa dado sensível (chave privada, API key, etc)"""
    return get_encryption_manager().encrypt(plaintext)


def decrypt_sensitive_data(encrypted: str) -> str:
    """Descriptografa dado sensível"""
    return get_encryption_manager().decrypt(encrypted)


def encrypt_json(data: dict) -> str:
    """Criptografa objeto JSON"""
    return get_encryption_manager().encrypt_dict(data)


def decrypt_json(encrypted: str) -> dict:
    """Descriptografa objeto JSON"""
    return get_encryption_manager().decrypt_dict(encrypted)
