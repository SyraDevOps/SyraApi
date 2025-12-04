"""
Integração do modelo Selene com o sistema de IA da API
Wrapper para usar modelos treinados do Selene (Luna, MML)
"""
import os
import pickle
import torch
import torch.nn as nn
from pathlib import Path
from typing import Optional, Dict, Any, List
import logging

# Configurar logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class SimpleModel(nn.Module):
    """Modelo neural simples usado pelo Selene (compatível)"""
    def __init__(self, input_dim, output_dim):
        super(SimpleModel, self).__init__()
        self.linear = nn.Linear(input_dim, output_dim)

    def forward(self, x):
        return self.linear(x)


class SeleneModel:
    """
    Wrapper para carregar e usar modelos treinados do Selene
    Compatível com Luna e outros modelos treinados
    """
    
    def __init__(self, model_path: str):
        """
        Inicializa o modelo Selene
        
        Args:
            model_path: Caminho para a pasta do modelo (ex: models/Luna)
        """
        self.model_path = Path(model_path)
        self.model = None
        self.vectorizer = None
        self.resposta2idx = None
        self.idx2resposta = None
        self.is_loaded = False
        
    def load(self) -> bool:
        """
        Carrega modelo treinado, vectorizer e mapeamentos
        
        Returns:
            True se carregamento foi bem-sucedido
        """
        try:
            model_file = self.model_path / "torch_model.pt"
            vectorizer_file = self.model_path / "vectorizer.pkl"
            
            if not model_file.exists():
                logger.error(f"Arquivo do modelo não encontrado: {model_file}")
                return False
                
            if not vectorizer_file.exists():
                logger.error(f"Arquivo do vectorizer não encontrado: {vectorizer_file}")
                return False
            
            # Carregar vectorizer e mapeamentos
            with open(vectorizer_file, "rb") as f:
                self.vectorizer, self.resposta2idx, self.idx2resposta = pickle.load(f)
            
            # Criar e carregar modelo PyTorch
            input_dim = len(self.vectorizer.get_feature_names_out())
            output_dim = len(self.resposta2idx)
            
            self.model = SimpleModel(input_dim, output_dim)
            self.model.load_state_dict(torch.load(model_file, map_location='cpu'))
            self.model.eval()
            
            self.is_loaded = True
            logger.info(f"Modelo Selene carregado: {self.model_path.name}")
            logger.info(f"  - Dimensões: {input_dim} → {output_dim}")
            logger.info(f"  - Respostas únicas: {output_dim}")
            
            return True
            
        except Exception as e:
            logger.error(f"Erro ao carregar modelo Selene: {e}")
            return False
    
    def predict(self, pergunta: str, contexto: str = "") -> str:
        """
        Faz predição usando o modelo
        
        Args:
            pergunta: Pergunta do usuário
            contexto: Contexto opcional da conversa
            
        Returns:
            Resposta gerada pelo modelo
        """
        if not self.is_loaded:
            return "Erro: Modelo não está carregado"
        
        try:
            # Combinar pergunta com contexto (mesmo método do Selene)
            query = pergunta
            if contexto:
                query = f"{pergunta} {contexto}"
            
            # Vetorizar
            X_query = self.vectorizer.transform([query])
            X_tensor = torch.tensor(X_query.toarray(), dtype=torch.float32)
            
            # Predição
            with torch.no_grad():
                output = self.model(X_tensor)
            
            # Obter índice da resposta
            idx = torch.argmax(output, dim=1).item()
            resposta = self.idx2resposta[idx]
            
            return resposta
            
        except Exception as e:
            logger.error(f"Erro na predição: {e}")
            return "Desculpe, houve um erro ao processar sua mensagem."
    
    def get_model_info(self) -> Dict[str, Any]:
        """
        Retorna informações sobre o modelo carregado
        
        Returns:
            Dicionário com informações do modelo
        """
        if not self.is_loaded:
            return {"loaded": False, "error": "Modelo não carregado"}
        
        return {
            "loaded": True,
            "name": self.model_path.name,
            "path": str(self.model_path),
            "input_dim": len(self.vectorizer.get_feature_names_out()),
            "output_dim": len(self.resposta2idx),
            "vocabulary_size": len(self.vectorizer.vocabulary_),
            "unique_responses": len(self.idx2resposta)
        }


class SeleneManager:
    """
    Gerenciador de modelos Selene
    Carrega e mantém cache de modelos disponíveis
    """
    
    def __init__(self, selene_base_path: str = "/root/SyraApi/Modelos/Selene"):
        self.base_path = Path(selene_base_path)
        self.models_path = self.base_path / "models"
        self.loaded_models: Dict[str, SeleneModel] = {}
        
    def list_available_models(self) -> List[Dict[str, Any]]:
        """
        Lista todos os modelos Selene disponíveis
        
        Returns:
            Lista de dicionários com informações dos modelos
        """
        available = []
        
        if not self.models_path.exists():
            logger.warning(f"Diretório de modelos não encontrado: {self.models_path}")
            return available
        
        for model_dir in self.models_path.iterdir():
            if not model_dir.is_dir():
                continue
            
            model_file = model_dir / "torch_model.pt"
            vectorizer_file = model_dir / "vectorizer.pkl"
            
            if model_file.exists() and vectorizer_file.exists():
                available.append({
                    "name": model_dir.name,
                    "path": str(model_dir),
                    "model_size": model_file.stat().st_size,
                    "has_vectorizer": True,
                    "is_loaded": model_dir.name in self.loaded_models
                })
        
        return available
    
    def load_model(self, model_name: str) -> Optional[SeleneModel]:
        """
        Carrega um modelo Selene específico
        
        Args:
            model_name: Nome do modelo (ex: Luna, mml)
            
        Returns:
            Instância do modelo ou None se falhar
        """
        # Verificar se já está carregado
        if model_name in self.loaded_models:
            logger.info(f"Modelo '{model_name}' já está carregado (usando cache)")
            return self.loaded_models[model_name]
        
        model_path = self.models_path / model_name
        
        if not model_path.exists():
            logger.error(f"Modelo '{model_name}' não encontrado em {model_path}")
            return None
        
        # Criar e carregar modelo
        selene_model = SeleneModel(str(model_path))
        
        if selene_model.load():
            self.loaded_models[model_name] = selene_model
            logger.info(f"Modelo '{model_name}' carregado e cacheado com sucesso")
            return selene_model
        
        return None
    
    def predict_with_model(self, model_name: str, pergunta: str, contexto: str = "") -> str:
        """
        Faz predição com um modelo específico
        
        Args:
            model_name: Nome do modelo
            pergunta: Pergunta do usuário
            contexto: Contexto da conversa
            
        Returns:
            Resposta do modelo
        """
        model = self.load_model(model_name)
        
        if model is None:
            return f"Erro: Modelo '{model_name}' não pôde ser carregado"
        
        return model.predict(pergunta, contexto)
    
    def get_model_info(self, model_name: str) -> Dict[str, Any]:
        """
        Obtém informações de um modelo específico
        
        Args:
            model_name: Nome do modelo
            
        Returns:
            Dicionário com informações
        """
        model = self.load_model(model_name)
        
        if model is None:
            return {"error": f"Modelo '{model_name}' não encontrado"}
        
        return model.get_model_info()
    
    def unload_model(self, model_name: str) -> bool:
        """
        Descarrega um modelo da memória
        
        Args:
            model_name: Nome do modelo
            
        Returns:
            True se descarregado com sucesso
        """
        if model_name in self.loaded_models:
            del self.loaded_models[model_name]
            logger.info(f"Modelo '{model_name}' descarregado da memória")
            return True
        
        return False
    
    def clear_cache(self):
        """Limpa todos os modelos carregados da memória"""
        self.loaded_models.clear()
        logger.info("Cache de modelos Selene limpo")


# Instância global do gerenciador
selene_manager = SeleneManager()
