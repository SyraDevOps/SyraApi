"""
Gerenciador de modelos de IA e datasets
Integração com modelos PyTorch e gerenciamento de dados
"""
import os
import pandas as pd
import sqlite3
import torch
import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
import time
from Tools.selene_integration import selene_manager


class AIModelManager:
    """Gerenciador de modelos de IA personalizados"""
    
    def __init__(self, base_path: str = "/root/SyraApi/UserData"):
        self.base_path = Path(base_path)
        self.models_dir = self.base_path / "ai_models"
        self.datasets_dir = self.base_path / "datasets"
        self.models_dir.mkdir(parents=True, exist_ok=True)
        self.datasets_dir.mkdir(parents=True, exist_ok=True)
    
    def get_user_model_dir(self, user_id: int, model_id: int) -> Path:
        """Retorna diretório do modelo do usuário"""
        model_dir = self.models_dir / f"user_{user_id}" / f"model_{model_id}"
        model_dir.mkdir(parents=True, exist_ok=True)
        return model_dir
    
    def get_user_dataset_dir(self, user_id: int) -> Path:
        """Retorna diretório de datasets do usuário"""
        dataset_dir = self.datasets_dir / f"user_{user_id}"
        dataset_dir.mkdir(parents=True, exist_ok=True)
        return dataset_dir
    
    def get_knowledge_db_path(self, user_id: int, model_id: int) -> Path:
        """Retorna caminho do banco de conhecimento do modelo"""
        model_dir = self.get_user_model_dir(user_id, model_id)
        return model_dir / "knowledge.db"
    
    def get_commands_db_path(self, user_id: int, model_id: int) -> Path:
        """Retorna caminho do banco de comandos do modelo"""
        model_dir = self.get_user_model_dir(user_id, model_id)
        return model_dir / "commands.db"
    
    def csv_to_sqlite(self, csv_path: str, db_path: str, table_name: str = "data") -> Dict[str, Any]:
        """
        Converte CSV para SQLite
        Retorna estatísticas da conversão
        """
        try:
            # Ler CSV
            df = pd.read_csv(csv_path)
            
            # Criar conexão SQLite
            conn = sqlite3.connect(db_path)
            
            # Salvar no banco
            df.to_sql(table_name, conn, if_exists='replace', index=False)
            
            # Estatísticas
            stats = {
                "success": True,
                "total_rows": len(df),
                "columns": df.columns.tolist(),
                "table_name": table_name,
                "db_path": db_path
            }
            
            conn.close()
            return stats
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e)
            }
    
    def load_selene_model(self, model_path: str) -> Optional[torch.nn.Module]:
        """
        Carrega modelo Selene do PyTorch
        """
        try:
            if not os.path.exists(model_path):
                return None
            
            model = torch.load(model_path, map_location=torch.device('cpu'))
            model.eval()  # Modo de avaliação
            return model
        except Exception as e:
            print(f"Erro ao carregar modelo: {e}")
            return None
    
    def create_knowledge_db(self, db_path: str):
        """Cria estrutura do banco de conhecimento"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                category TEXT,
                question TEXT,
                answer TEXT NOT NULL,
                context TEXT,
                source TEXT,
                confidence REAL DEFAULT 1.0,
                is_active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_category ON knowledge(category)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_is_active ON knowledge(is_active)
        """)
        
        conn.commit()
        conn.close()
    
    def create_commands_db(self, db_path: str):
        """Cria estrutura do banco de comandos"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                trigger TEXT NOT NULL,
                command_type TEXT NOT NULL,
                target_route TEXT,
                target_function TEXT,
                target_file TEXT,
                parameters TEXT,
                description TEXT,
                response_template TEXT,
                is_active INTEGER DEFAULT 1,
                execution_count INTEGER DEFAULT 0,
                last_executed_at TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_trigger ON commands(trigger)
        """)
        
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_is_active ON commands(is_active)
        """)
        
        conn.commit()
        conn.close()
    
    def add_knowledge(self, db_path: str, knowledge_items: List[Dict[str, Any]]) -> int:
        """Adiciona conhecimento ao banco"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        added_count = 0
        for item in knowledge_items:
            cursor.execute("""
                INSERT INTO knowledge (category, question, answer, context, source, confidence)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                item.get('category'),
                item.get('question'),
                item['answer'],
                item.get('context'),
                item.get('source', 'manual'),
                item.get('confidence', 1.0)
            ))
            added_count += 1
        
        conn.commit()
        conn.close()
        
        return added_count
    
    def search_knowledge(self, db_path: str, query: str, limit: int = 5) -> List[Dict[str, Any]]:
        """Busca conhecimento relevante"""
        import re
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Normalizar query: remover pontuação e converter para minúsculas
        normalized_query = re.sub(r'[^\w\s]', '', query.lower()).strip()
        
        # Busca simples por palavras-chave
        search_pattern = f"%{normalized_query}%"
        
        cursor.execute("""
            SELECT id, category, question, answer, context, confidence
            FROM knowledge
            WHERE is_active = 1 AND (
                question LIKE ? OR answer LIKE ? OR context LIKE ?
            )
            ORDER BY confidence DESC
            LIMIT ?
        """, (search_pattern, search_pattern, search_pattern, limit))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "id": row[0],
                "category": row[1],
                "question": row[2],
                "answer": row[3],
                "context": row[4],
                "confidence": row[5]
            })
        
        conn.close()
        return results
    
    def find_command(self, db_path: str, message: str) -> Optional[Dict[str, Any]]:
        """Busca comando que corresponda à mensagem"""
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT id, trigger, command_type, target_route, target_function, 
                   target_file, parameters, response_template
            FROM commands
            WHERE is_active = 1
        """)
        
        message_lower = message.lower()
        
        for row in cursor.fetchall():
            trigger = row[1].lower()
            # Verificação simples: se trigger está na mensagem
            if trigger in message_lower:
                command = {
                    "id": row[0],
                    "trigger": row[1],
                    "command_type": row[2],
                    "target_route": row[3],
                    "target_function": row[4],
                    "target_file": row[5],
                    "parameters": json.loads(row[6]) if row[6] else None,
                    "response_template": row[7]
                }
                
                # Atualizar contador de execução
                cursor.execute("""
                    UPDATE commands
                    SET execution_count = execution_count + 1,
                        last_executed_at = ?
                    WHERE id = ?
                """, (datetime.utcnow().isoformat(), row[0]))
                
                conn.commit()
                conn.close()
                return command
        
        conn.close()
        return None
    
    def generate_response(self, message: str, knowledge_results: List[Dict[str, Any]], 
                         model_name: Optional[str] = None, 
                         use_selene: bool = False,
                         contexto: str = "",
                         user_id: int = None,
                         model_id: int = None) -> str:
        """
        Gera resposta baseada em conhecimento e modelo
        
        Ordem de prioridade:
        1. Base de conhecimento personalizada
        2. Modelo treinado do usuário (se disponível)
        3. Modelo Selene (se configurado)
        4. Resposta padrão
        """
        # 1. Se encontrou conhecimento relevante na base personalizada
        if knowledge_results:
            best_match = knowledge_results[0]
            return best_match['answer']
        
        # 2. Tentar usar modelo treinado do usuário
        if user_id and model_id:
            user_model_response = self.predict_with_user_model(user_id, model_id, message, contexto)
            if user_model_response:
                return user_model_response
        
        # 3. Se deve usar Selene e modelo está especificado
        if use_selene and model_name:
            try:
                response = selene_manager.predict_with_model(model_name, message, contexto)
                if response and not response.startswith("Erro:"):
                    return response
            except Exception as e:
                print(f"Erro ao usar Selene: {e}")
        
        # 4. Resposta padrão
        return "Desculpe, não encontrei informações sobre isso. Você pode adicionar este conhecimento ao meu banco de dados!"
    
    def get_selene_models(self) -> List[Dict[str, Any]]:
        """
        Lista modelos Selene disponíveis
        """
        return selene_manager.list_available_models()
    
    def load_selene_model_info(self, model_name: str) -> Dict[str, Any]:
        """
        Carrega um modelo Selene específico e retorna informações
        """
        model = selene_manager.load_model(model_name)
        if model:
            return model.get_model_info()
        return {"error": "Falha ao carregar modelo"}
    
    def load_dataset(self, dataset_db_path: str) -> list:
        """
        Carrega dados de um dataset SQLite
        """
        try:
            conn = sqlite3.connect(dataset_db_path)
            cursor = conn.cursor()
            
            # Pegar todas as linhas
            cursor.execute("SELECT * FROM dataset LIMIT 10000")
            rows = cursor.fetchall()
            
            # Pegar nomes das colunas
            columns = [description[0] for description in cursor.description]
            
            # Converter para lista de dicts
            data = [dict(zip(columns, row)) for row in rows]
            
            conn.close()
            return data
            
        except Exception as e:
            print(f"Erro ao carregar dataset: {e}")
            return []
    
    def get_dataset_db_path(self, user_id: int, model_id: int, dataset_id: int) -> Path:
        """
        Retorna caminho para banco de dados do dataset
        """
        dataset_dir = self.base_path / "datasets" / f"user_{user_id}" / f"model_{model_id}"
        dataset_dir.mkdir(parents=True, exist_ok=True)
        return dataset_dir / f"dataset_{dataset_id}.db"
    
    def get_model_path(self, user_id: int, model_id: int) -> Path:
        """
        Retorna caminho para o modelo treinado
        """
        model_dir = self.get_user_model_dir(user_id, model_id)
        return model_dir / "model.pt"
    
    def load_user_trained_model(self, user_id: int, model_id: int):
        """
        Carrega modelo treinado do usuário para fazer predições
        
        Returns:
            Tupla (model, vectorizer, idx2resposta) ou None se não treinado
        """
        import pickle
        import torch.nn as nn
        
        model_path = self.get_model_path(user_id, model_id)
        vectorizer_path = model_path.parent / "vectorizer.pkl"
        
        if not model_path.exists() or not vectorizer_path.exists():
            return None
        
        try:
            # Carregar vetorizador e mapeamentos
            with open(vectorizer_path, "rb") as f:
                vectorizer, resposta2idx, idx2resposta = pickle.load(f)
            
            # Modelo simples (mesmo do treinamento)
            class SimpleModel(nn.Module):
                def __init__(self, input_dim, output_dim):
                    super().__init__()
                    self.linear = nn.Linear(input_dim, output_dim)
                def forward(self, x):
                    return self.linear(x)
            
            # Criar e carregar modelo
            model = SimpleModel(len(vectorizer.get_feature_names_out()), len(resposta2idx))
            model.load_state_dict(torch.load(model_path, map_location='cpu'))
            model.eval()
            
            return (model, vectorizer, idx2resposta)
            
        except Exception as e:
            print(f"Erro ao carregar modelo do usuário: {e}")
            return None
    
    def predict_with_user_model(self, user_id: int, model_id: int, message: str, contexto: str = "") -> Optional[str]:
        """
        Faz predição usando modelo treinado do usuário
        """
        loaded = self.load_user_trained_model(user_id, model_id)
        
        if not loaded:
            return None
        
        model, vectorizer, idx2resposta = loaded
        
        try:
            # Combinar mensagem com contexto
            query = f"{message} {contexto}".strip()
            
            # Vetorizar
            X_query = vectorizer.transform([query])
            X_tensor = torch.tensor(X_query.toarray(), dtype=torch.float32)
            
            # Predição
            with torch.no_grad():
                output = model(X_tensor)
            
            idx = torch.argmax(output, dim=1).item()
            return idx2resposta[idx]
            
        except Exception as e:
            print(f"Erro na predição: {e}")
            return None


# Instância global
ai_manager = AIModelManager()
