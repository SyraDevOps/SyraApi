"""
Script de migração de banco de dados
Adiciona novas colunas sem perder dados existentes
"""
import sqlite3
import os

DATABASE_PATH = os.path.join(os.path.dirname(__file__), "syra_users.db")


def get_table_columns(cursor, table_name):
    """Retorna lista de colunas de uma tabela"""
    cursor.execute(f"PRAGMA table_info({table_name})")
    return [row[1] for row in cursor.fetchall()]


def add_column_if_not_exists(cursor, table_name, column_name, column_type, default=None):
    """Adiciona coluna se não existir"""
    columns = get_table_columns(cursor, table_name)
    if column_name not in columns:
        if default is not None:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type} DEFAULT {default}")
        else:
            cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")
        print(f"  [+] Coluna '{column_name}' adicionada à tabela '{table_name}'")
        return True
    return False


def migrate_database():
    """Executa migrações do banco de dados"""
    if not os.path.exists(DATABASE_PATH):
        print("[!] Banco de dados não encontrado. Será criado na primeira execução.")
        return
    
    print("[*] Iniciando migração do banco de dados...")
    
    conn = sqlite3.connect(DATABASE_PATH)
    cursor = conn.cursor()
    
    migrations_applied = 0
    
    # Verificar se tabela user_ai_models existe
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_ai_models'")
    if cursor.fetchone():
        # Migração: Adicionar training_config e total_training_time
        if add_column_if_not_exists(cursor, "user_ai_models", "training_config", "TEXT"):
            migrations_applied += 1
        if add_column_if_not_exists(cursor, "user_ai_models", "total_training_time", "REAL"):
            migrations_applied += 1
    
    # Verificar outras tabelas e adicionar colunas se necessário
    # (adicione mais migrações aqui conforme necessário)
    
    conn.commit()
    conn.close()
    
    if migrations_applied > 0:
        print(f"[✓] Migração concluída. {migrations_applied} alteração(ões) aplicada(s).")
    else:
        print("[=] Banco de dados já está atualizado.")


if __name__ == "__main__":
    migrate_database()
