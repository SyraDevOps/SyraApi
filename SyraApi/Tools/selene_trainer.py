"""
Sistema de criação e treinamento de modelos Selene via API
Permite criar, treinar e gerenciar modelos customizados
"""
import os
import csv
import pickle
import torch
import torch.nn as nn
import torch.optim as optim
from sklearn.feature_extraction.text import TfidfVectorizer
from torch.utils.data import Dataset, DataLoader
import sqlite3
from pathlib import Path
from typing import Dict, Any, List, Optional
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class TextDataset(Dataset):
    """Dataset customizado para PyTorch compatível com matrizes esparsas TF-IDF."""
    def __init__(self, X, y):
        self.X = X.tocsr()  # Converte para CSR para fatiamento eficiente
        self.y = y

    def __len__(self):
        return self.X.shape[0]

    def __getitem__(self, idx):
        # Converte a linha esparsa para um tensor denso para o modelo
        x_sample = torch.tensor(self.X[idx].toarray().squeeze(), dtype=torch.float32)
        y_sample = self.y[idx]
        return x_sample, y_sample


class SimpleModel(nn.Module):
    """Modelo neural simples usado pelo Selene"""
    def __init__(self, input_dim, output_dim):
        super(SimpleModel, self).__init__()
        self.linear = nn.Linear(input_dim, output_dim)

    def forward(self, x):
        return self.linear(x)


class SeleneTrainer:
    """
    Classe para criar e treinar novos modelos Selene
    """
    
    def __init__(self, base_path: str = "/root/SyraApi/Modelos/Selene/models"):
        self.base_path = Path(base_path)
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def create_model(self, model_name: str) -> Dict[str, Any]:
        """
        Cria um novo modelo Selene
        
        Args:
            model_name: Nome do modelo a criar
            
        Returns:
            Dicionário com informações do modelo criado
        """
        model_path = self.base_path / model_name
        
        if model_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' já existe"
            }
        
        try:
            # Criar diretório
            model_path.mkdir(parents=True, exist_ok=True)
            
            # Criar banco de dados
            db_path = model_path / "data.db"
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS dataset (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pergunta TEXT,
                    resposta TEXT,
                    contexto TEXT,
                    UNIQUE(pergunta, contexto)
                )
            """)
            conn.commit()
            conn.close()
            
            logger.info(f"Modelo '{model_name}' criado em {model_path}")
            
            return {
                "success": True,
                "model_name": model_name,
                "path": str(model_path),
                "message": f"Modelo '{model_name}' criado com sucesso"
            }
            
        except Exception as e:
            logger.error(f"Erro ao criar modelo: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def add_training_data(self, model_name: str, data: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Adiciona dados de treinamento ao modelo
        
        Args:
            model_name: Nome do modelo
            data: Lista de dicts com 'pergunta', 'resposta', 'contexto'
            
        Returns:
            Estatísticas da adição
        """
        model_path = self.base_path / model_name
        
        if not model_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            db_path = model_path / "data.db"
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            
            added_count = 0
            for item in data:
                cursor.execute(
                    "INSERT OR IGNORE INTO dataset (pergunta, resposta, contexto) VALUES (?, ?, ?)",
                    (item['pergunta'], item['resposta'], item.get('contexto', ''))
                )
                added_count += cursor.rowcount
            
            conn.commit()
            conn.close()
            
            logger.info(f"Adicionados {added_count} itens ao modelo '{model_name}'")
            
            return {
                "success": True,
                "added_count": added_count,
                "message": f"{added_count} itens adicionados"
            }
            
        except Exception as e:
            logger.error(f"Erro ao adicionar dados: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def load_training_data(self, model_name: str) -> tuple:
        """
        Carrega dados de treinamento do banco
        
        Returns:
            (perguntas, respostas)
        """
        model_path = self.base_path / model_name
        db_path = model_path / "data.db"
        
        perguntas, respostas = [], []
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute("SELECT pergunta, resposta, contexto FROM dataset")
        
        for row in cursor.fetchall():
            # Combinar pergunta com contexto
            perguntas.append(row[0] + " " + row[2])
            respostas.append(row[1])
        
        conn.close()
        return perguntas, respostas
    
    def train_model(
        self,
        model_name: str,
        epochs: int = 10,
        batch_size: int = 16,
        learning_rate: float = 0.01,
        continue_training: bool = False
    ) -> Dict[str, Any]:
        """
        Treina um modelo Selene
        
        Args:
            model_name: Nome do modelo
            epochs: Número de épocas
            batch_size: Tamanho do batch
            learning_rate: Taxa de aprendizado
            continue_training: Se True, continua treinamento existente
            
        Returns:
            Resultados do treinamento
        """
        model_path = self.base_path / model_name
        
        if not model_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            # Carregar dados
            perguntas, respostas = self.load_training_data(model_name)
            
            if not perguntas:
                return {
                    "success": False,
                    "error": "Nenhum dado de treinamento encontrado"
                }
            
            logger.info(f"Iniciando treinamento de '{model_name}' com {len(perguntas)} amostras")
            
            # Vetorização TF-IDF
            vectorizer = TfidfVectorizer()
            X = vectorizer.fit_transform(perguntas)
            
            # Preparar labels
            respostas_set = sorted(list(set(respostas)))
            resposta2idx = {resp: idx for idx, resp in enumerate(respostas_set)}
            idx2resposta = {idx: resp for resp, idx in resposta2idx.items()}
            y = torch.tensor([resposta2idx[r] for r in respostas], dtype=torch.long)
            
            # Dataset e DataLoader
            dataset = TextDataset(X, y)
            data_loader = DataLoader(dataset, batch_size=batch_size, shuffle=True)
            
            # Criar modelo
            model = SimpleModel(X.shape[1], len(respostas_set))
            
            model_file = model_path / "torch_model.pt"
            
            # Carregar pesos existentes se for continuar treinamento
            if continue_training and model_file.exists():
                try:
                    model.load_state_dict(torch.load(model_file))
                    logger.info(f"Continuando treinamento de '{model_name}'")
                except Exception as e:
                    logger.warning(f"Não foi possível carregar modelo existente: {e}")
            
            # Configurar treinamento
            criterion = nn.CrossEntropyLoss()
            optimizer = optim.Adam(model.parameters(), lr=learning_rate)
            
            # Loop de treinamento
            model.train()
            training_history = []
            
            for epoch in range(epochs):
                total_loss = 0
                batch_count = 0
                
                for batch_X, batch_y in data_loader:
                    optimizer.zero_grad()
                    outputs = model(batch_X)
                    loss = criterion(outputs, batch_y)
                    loss.backward()
                    optimizer.step()
                    total_loss += loss.item()
                    batch_count += 1
                
                avg_loss = total_loss / batch_count
                training_history.append({
                    "epoch": epoch + 1,
                    "loss": avg_loss
                })
                
                logger.info(f"Época {epoch+1}/{epochs} - Perda: {avg_loss:.4f}")
            
            # Salvar modelo e vetorizador
            torch.save(model.state_dict(), str(model_file))
            
            vectorizer_file = model_path / "vectorizer.pkl"
            with open(vectorizer_file, "wb") as f:
                pickle.dump((vectorizer, resposta2idx, idx2resposta), f)
            
            # Salvar checkpoint do treinamento
            checkpoint_data = {
                "epochs": epochs,
                "batch_size": batch_size,
                "learning_rate": learning_rate,
                "training_samples": len(perguntas),
                "unique_responses": len(respostas_set),
                "final_loss": training_history[-1]["loss"],
                "training_history": training_history,
                "continue_training": continue_training
            }
            self.save_training_checkpoint(model_name, checkpoint_data)
            
            logger.info(f"Modelo '{model_name}' treinado e salvo com sucesso")
            
            return {
                "success": True,
                "model_name": model_name,
                "training_samples": len(perguntas),
                "unique_responses": len(respostas_set),
                "epochs": epochs,
                "final_loss": training_history[-1]["loss"],
                "training_history": training_history,
                "model_path": str(model_file),
                "vectorizer_path": str(vectorizer_file)
            }
            
        except Exception as e:
            logger.error(f"Erro durante treinamento: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_model_stats(self, model_name: str) -> Dict[str, Any]:
        """
        Obtém estatísticas do modelo
        
        Returns:
            Estatísticas do modelo
        """
        model_path = self.base_path / model_name
        
        if not model_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            # Contar dados de treinamento
            db_path = model_path / "data.db"
            conn = sqlite3.connect(str(db_path))
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM dataset")
            total_samples = cursor.fetchone()[0]
            
            cursor.execute("SELECT COUNT(DISTINCT resposta) FROM dataset")
            unique_responses = cursor.fetchone()[0]
            
            conn.close()
            
            # Verificar se modelo está treinado
            model_file = model_path / "torch_model.pt"
            vectorizer_file = model_path / "vectorizer.pkl"
            
            is_trained = model_file.exists() and vectorizer_file.exists()
            
            stats = {
                "success": True,
                "model_name": model_name,
                "total_samples": total_samples,
                "unique_responses": unique_responses,
                "is_trained": is_trained,
                "path": str(model_path)
            }
            
            if is_trained:
                stats["model_size"] = model_file.stat().st_size
                stats["vectorizer_size"] = vectorizer_file.stat().st_size
            
            return stats
            
        except Exception as e:
            logger.error(f"Erro ao obter estatísticas: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def remove_training_data(self, model_name: str, condition: str = None, ids: List[int] = None) -> Dict[str, Any]:
        """
        Remove dados específicos de treinamento
        
        Args:
            model_name: Nome do modelo
            condition: Condição SQL (ex: "pergunta LIKE '%teste%'")
            ids: Lista de IDs específicos para remover
        """
        db_path = self.base_path / model_name / "data.db"
        
        if not db_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            if ids:
                # Remove IDs específicos
                placeholders = ','.join(['?'] * len(ids))
                cursor.execute(f"DELETE FROM dataset WHERE id IN ({placeholders})", ids)
                removed = cursor.rowcount
            elif condition:
                # Remove por condição
                cursor.execute(f"DELETE FROM dataset WHERE {condition}")
                removed = cursor.rowcount
            else:
                # Remove todos os dados
                cursor.execute("DELETE FROM dataset")
                removed = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "removed_count": removed,
                "message": f"{removed} registro(s) removido(s)"
            }
            
        except Exception as e:
            logger.error(f"Erro ao remover dados: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_training_data(self, model_name: str, limit: int = 100, offset: int = 0) -> Dict[str, Any]:
        """
        Obtém dados de treinamento paginados
        """
        db_path = self.base_path / model_name / "data.db"
        
        if not db_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Total de registros
            cursor.execute("SELECT COUNT(*) FROM dataset")
            total = cursor.fetchone()[0]
            
            # Dados paginados
            cursor.execute(
                "SELECT id, pergunta, resposta, contexto FROM dataset LIMIT ? OFFSET ?",
                (limit, offset)
            )
            
            rows = cursor.fetchall()
            data = [
                {
                    "id": row[0],
                    "pergunta": row[1],
                    "resposta": row[2],
                    "contexto": row[3]
                }
                for row in rows
            ]
            
            conn.close()
            
            return {
                "success": True,
                "total": total,
                "limit": limit,
                "offset": offset,
                "data": data
            }
            
        except Exception as e:
            logger.error(f"Erro ao obter dados: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def export_training_data_csv(self, model_name: str, output_path: str = None) -> Dict[str, Any]:
        """
        Exporta dados de treinamento para CSV
        """
        db_path = self.base_path / model_name / "data.db"
        
        if not db_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            if not output_path:
                output_path = self.base_path / model_name / f"export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
            
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT pergunta, resposta, contexto FROM dataset")
            rows = cursor.fetchall()
            
            with open(output_path, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.writer(csvfile)
                writer.writerow(['pergunta', 'resposta', 'contexto'])
                writer.writerows(rows)
            
            conn.close()
            
            return {
                "success": True,
                "path": str(output_path),
                "rows_exported": len(rows)
            }
            
        except Exception as e:
            logger.error(f"Erro ao exportar CSV: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def save_training_checkpoint(self, model_name: str, checkpoint_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Salva checkpoint de treinamento (losses, métricas, etc)
        """
        model_path = self.base_path / model_name
        
        if not model_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            checkpoint_path = model_path / "training_history.pkl"
            
            # Carrega histórico existente se houver
            history = []
            if checkpoint_path.exists():
                with open(checkpoint_path, 'rb') as f:
                    history = pickle.load(f)
            
            # Adiciona novo checkpoint
            checkpoint_data['timestamp'] = datetime.now().isoformat()
            history.append(checkpoint_data)
            
            # Salva
            with open(checkpoint_path, 'wb') as f:
                pickle.dump(history, f)
            
            return {
                "success": True,
                "checkpoint_saved": True,
                "total_checkpoints": len(history)
            }
            
        except Exception as e:
            logger.error(f"Erro ao salvar checkpoint: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def get_training_history(self, model_name: str) -> Dict[str, Any]:
        """
        Obtém histórico completo de treinamento (todos os losses)
        """
        checkpoint_path = self.base_path / model_name / "training_history.pkl"
        
        if not checkpoint_path.exists():
            return {
                "success": True,
                "history": [],
                "message": "Nenhum histórico de treinamento encontrado"
            }
        
        try:
            with open(checkpoint_path, 'rb') as f:
                history = pickle.load(f)
            
            return {
                "success": True,
                "total_trainings": len(history),
                "history": history
            }
            
        except Exception as e:
            logger.error(f"Erro ao carregar histórico: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def delete_model(self, model_name: str) -> Dict[str, Any]:
        """
        Deleta um modelo completamente
        """
        model_path = self.base_path / model_name
        
        if not model_path.exists():
            return {
                "success": False,
                "error": f"Modelo '{model_name}' não encontrado"
            }
        
        try:
            import shutil
            shutil.rmtree(model_path)
            
            logger.info(f"Modelo '{model_name}' deletado")
            
            return {
                "success": True,
                "message": f"Modelo '{model_name}' deletado com sucesso"
            }
            
        except Exception as e:
            logger.error(f"Erro ao deletar modelo: {e}")
            return {
                "success": False,
                "error": str(e)
            }


# Instância global do trainer
selene_trainer = SeleneTrainer()
