"""
Teste Completo e Compreensivo do Sistema Syra API
Verifica: Modelos IA, Upload, Treinamento, Localização, etc.
"""
import requests
import time
import json
import os
import sys

BASE_URL = "http://localhost:8080"
TESTS_PASSED = 0
TESTS_FAILED = 0
ERRORS = []

def log_test(name, passed, details=""):
    global TESTS_PASSED, TESTS_FAILED, ERRORS
    if passed:
        TESTS_PASSED += 1
        print(f"  ✓ {name}")
    else:
        TESTS_FAILED += 1
        ERRORS.append(f"{name}: {details}")
        print(f"  ✗ {name} - {details}")

def test_api_health():
    """Testa se a API está online"""
    print("\n" + "="*60)
    print("1. TESTE DE SAÚDE DA API")
    print("="*60)
    
    try:
        r = requests.get(f"{BASE_URL}/", timeout=5)
        log_test("API online", r.status_code == 200, f"Status: {r.status_code}")
        
        r = requests.get(f"{BASE_URL}/health", timeout=5)
        log_test("Endpoint /health", r.status_code == 200)
        
        r = requests.get(f"{BASE_URL}/api-info", timeout=5)
        log_test("Endpoint /api-info", r.status_code == 200)
        
    except Exception as e:
        log_test("Conexão com API", False, str(e))

def register_user():
    """Registra usuário de teste e retorna token"""
    timestamp = int(time.time())
    user_data = {
        "user": f"test_user_{timestamp}",
        "email": f"test_{timestamp}@test.com",
        "password": "TestPass123!",
        "senha_seguranca": "Seguranca123",
        "telefone": "11999999999"
    }
    
    r = requests.post(f"{BASE_URL}/auth/register", json=user_data)
    if r.status_code == 201:
        data = r.json()
        return data["access_token"], data["user"]["id"], data["user"]["user"]
    return None, None, None

def test_auth_system():
    """Testa sistema de autenticação"""
    print("\n" + "="*60)
    print("2. TESTE DE AUTENTICAÇÃO")
    print("="*60)
    
    # Registrar usuário
    token, user_id, username = register_user()
    log_test("Registro de usuário", token is not None, "Token não obtido" if not token else "")
    
    if not token:
        return None, None
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Verificar perfil
    r = requests.get(f"{BASE_URL}/auth/me", headers=headers)
    log_test("Obter perfil (/auth/me)", r.status_code == 200, f"Status: {r.status_code}")
    
    # Login com credenciais
    login_data = {"username": username, "password": "TestPass123!"}
    r = requests.post(f"{BASE_URL}/auth/login", data=login_data)
    log_test("Login com credenciais", r.status_code == 200, f"Status: {r.status_code}")
    
    return token, user_id

def test_ai_models(token, user_id):
    """Testa sistema de modelos de IA"""
    print("\n" + "="*60)
    print("3. TESTE DE MODELOS DE IA")
    print("="*60)
    
    if not token:
        log_test("Criação de modelo", False, "Token não disponível")
        return None
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Criar modelo
    model_data = {
        "model_name": f"ModeloTeste_{int(time.time())}",
        "model_type": "conversational",
        "description": "Modelo de teste automatizado",
        "config": {"use_selene": False}
    }
    
    r = requests.post(f"{BASE_URL}/ai/models", json=model_data, headers=headers)
    log_test("Criar modelo de IA", r.status_code == 201, f"Status: {r.status_code} - {r.text[:100] if r.status_code != 201 else ''}")
    
    if r.status_code != 201:
        return None
    
    model_id = r.json()["id"]
    
    # Listar modelos
    r = requests.get(f"{BASE_URL}/ai/models", headers=headers)
    log_test("Listar modelos", r.status_code == 200)
    
    # Obter modelo específico
    r = requests.get(f"{BASE_URL}/ai/models/{model_id}", headers=headers)
    log_test("Obter modelo específico", r.status_code == 200)
    
    # Atualizar modelo
    r = requests.patch(f"{BASE_URL}/ai/models/{model_id}", 
                       json={"description": "Descrição atualizada"}, 
                       headers=headers)
    log_test("Atualizar modelo", r.status_code == 200, f"Status: {r.status_code}")
    
    return model_id

def test_knowledge_base(token, model_id):
    """Testa base de conhecimento"""
    print("\n" + "="*60)
    print("4. TESTE DE BASE DE CONHECIMENTO")
    print("="*60)
    
    if not token or not model_id:
        log_test("Adicionar conhecimento", False, "Token ou model_id não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Adicionar conhecimento individual
    knowledge = {
        "category": "geral",
        "question": "O que é o Syra?",
        "answer": "Syra é um sistema completo de API com IA personalizada.",
        "confidence": 1.0,
        "source": "manual"
    }
    
    r = requests.post(f"{BASE_URL}/ai/models/{model_id}/knowledge", 
                      json=knowledge, headers=headers)
    log_test("Adicionar conhecimento único", r.status_code == 201, f"Status: {r.status_code}")
    
    # Adicionar conhecimento em bulk
    bulk_knowledge = {
        "items": [
            {"category": "faq", "question": "Como funciona?", "answer": "Funciona via API REST", "confidence": 0.9},
            {"category": "faq", "question": "Quem criou?", "answer": "Foi criado pela equipe Syra", "confidence": 0.9},
            {"category": "técnico", "question": "Qual o banco de dados?", "answer": "SQLite e SQLAlchemy", "confidence": 1.0}
        ]
    }
    
    r = requests.post(f"{BASE_URL}/ai/models/{model_id}/knowledge/bulk", 
                      json=bulk_knowledge, headers=headers)
    log_test("Adicionar conhecimento em bulk", r.status_code == 201, f"Status: {r.status_code}")
    
    # Listar conhecimentos
    r = requests.get(f"{BASE_URL}/ai/models/{model_id}/knowledge", headers=headers)
    log_test("Listar conhecimentos", r.status_code == 200)
    
    # Listar por categoria
    r = requests.get(f"{BASE_URL}/ai/models/{model_id}/knowledge?category=faq", headers=headers)
    log_test("Filtrar conhecimento por categoria", r.status_code == 200)

def test_ai_commands(token, model_id):
    """Testa comandos de automação"""
    print("\n" + "="*60)
    print("5. TESTE DE COMANDOS DE AUTOMAÇÃO")
    print("="*60)
    
    if not token or not model_id:
        log_test("Criar comando", False, "Token ou model_id não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Criar comando
    command = {
        "command_trigger": "listar arquivos",
        "command_type": "route",
        "target_route": "/drive/files",
        "description": "Lista arquivos do usuário",
        "response_template": "Aqui estão seus arquivos!"
    }
    
    r = requests.post(f"{BASE_URL}/ai/models/{model_id}/commands", 
                      json=command, headers=headers)
    log_test("Criar comando", r.status_code == 201, f"Status: {r.status_code}")
    
    # Listar comandos
    r = requests.get(f"{BASE_URL}/ai/models/{model_id}/commands", headers=headers)
    log_test("Listar comandos", r.status_code == 200)

def test_ai_chat(token, model_id):
    """Testa chat com IA"""
    print("\n" + "="*60)
    print("6. TESTE DE CHAT COM IA")
    print("="*60)
    
    if not token or not model_id:
        log_test("Chat com IA", False, "Token ou model_id não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Chat normal
    message = {"message": "O que é o Syra?", "context": {}}
    r = requests.post(f"{BASE_URL}/ai/models/{model_id}/chat", 
                      json=message, headers=headers)
    log_test("Enviar mensagem para IA", r.status_code == 200, f"Status: {r.status_code}")
    
    if r.status_code == 200:
        resp = r.json()
        log_test("Resposta da IA recebida", "response" in resp and len(resp["response"]) > 0)
        log_test("Tempo de resposta válido", "response_time" in resp)
    
    # Chat com comando
    message = {"message": "listar arquivos", "context": {}}
    r = requests.post(f"{BASE_URL}/ai/models/{model_id}/chat", 
                      json=message, headers=headers)
    log_test("Chat com trigger de comando", r.status_code == 200)
    
    # Histórico de chat
    r = requests.get(f"{BASE_URL}/ai/models/{model_id}/chat/history", headers=headers)
    log_test("Obter histórico de chat", r.status_code == 200)

def test_dataset_upload(token):
    """Testa upload de datasets"""
    print("\n" + "="*60)
    print("7. TESTE DE UPLOAD DE DATASETS")
    print("="*60)
    
    if not token:
        log_test("Upload de dataset", False, "Token não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Criar CSV de teste
    csv_content = "pergunta,resposta,categoria\n"
    csv_content += "Olá,Olá! Como posso ajudar?,saudacao\n"
    csv_content += "Tchau,Até logo!,despedida\n"
    csv_content += "Obrigado,De nada!,agradecimento\n"
    
    files = {"file": ("teste.csv", csv_content.encode(), "text/csv")}
    data = {"dataset_name": f"dataset_teste_{int(time.time())}", "description": "Dataset de teste"}
    
    r = requests.post(f"{BASE_URL}/ai/datasets/upload", 
                      files=files, data=data, headers=headers)
    log_test("Upload de CSV", r.status_code == 201, f"Status: {r.status_code} - {r.text[:100] if r.status_code != 201 else ''}")
    
    # Listar datasets
    r = requests.get(f"{BASE_URL}/ai/datasets", headers=headers)
    log_test("Listar datasets", r.status_code == 200)

def test_training(token, model_id):
    """Testa sistema de treinamento"""
    print("\n" + "="*60)
    print("8. TESTE DE TREINAMENTO")
    print("="*60)
    
    if not token or not model_id:
        log_test("Iniciar treinamento", False, "Token ou model_id não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Iniciar treinamento
    training_config = {
        "epochs": 5,
        "batch_size": 32,
        "learning_rate": 0.001,
        "validation_split": 0.2
    }
    
    r = requests.post(f"{BASE_URL}/ai/models/{model_id}/training/start", 
                      json=training_config, headers=headers)
    log_test("Iniciar treinamento", r.status_code in [200, 201, 409], f"Status: {r.status_code}")
    
    if r.status_code in [200, 201]:
        task_id = r.json().get("task_id")
        if task_id:
            # Verificar status
            r = requests.get(f"{BASE_URL}/ai/models/{model_id}/training/status/{task_id}", 
                            headers=headers)
            log_test("Verificar status de treinamento", r.status_code == 200)
    
    # Histórico de treinamento
    r = requests.get(f"{BASE_URL}/ai/models/{model_id}/training/history", headers=headers)
    log_test("Histórico de treinamento", r.status_code == 200)

def test_selene_integration(token):
    """Testa integração com Selene"""
    print("\n" + "="*60)
    print("9. TESTE DE INTEGRAÇÃO SELENE")
    print("="*60)
    
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    
    # Status do Selene
    r = requests.get(f"{BASE_URL}/ai/selene/status")
    log_test("Status do Selene", r.status_code == 200)
    
    if r.status_code == 200:
        data = r.json()
        log_test("Informações Selene disponíveis", "available" in data)

def test_location_system(token, user_id):
    """Testa sistema de localização"""
    print("\n" + "="*60)
    print("10. TESTE DE LOCALIZAÇÃO")
    print("="*60)
    
    if not token:
        log_test("Compartilhar localização", False, "Token não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Compartilhar localização
    location = {
        "latitude": -23.5505,
        "longitude": -46.6333,
        "accuracy": 10.0,
        "duration_minutes": 30,
        "visibility_radius": 1000,
        "is_public": True
    }
    
    r = requests.post(f"{BASE_URL}/location/share", json=location, headers=headers)
    log_test("Compartilhar localização", r.status_code == 201, f"Status: {r.status_code}")
    
    # Obter minha localização
    r = requests.get(f"{BASE_URL}/location/my", headers=headers)
    log_test("Obter minha localização", r.status_code == 200)
    
    # Atualizar localização
    update = {
        "latitude": -23.5510,
        "longitude": -46.6340,
        "accuracy": 8.0
    }
    
    r = requests.patch(f"{BASE_URL}/location/update", json=update, headers=headers)
    log_test("Atualizar localização", r.status_code == 200, f"Status: {r.status_code}")
    
    # Buscar usuários próximos
    r = requests.get(f"{BASE_URL}/location/nearby?radius_meters=5000", headers=headers)
    log_test("Buscar usuários próximos", r.status_code == 200)
    
    # Testar validação de coordenadas inválidas
    invalid_location = {
        "latitude": 100.0,  # Inválido: latitude deve ser -90 a 90
        "longitude": -46.6333,
        "accuracy": 10.0,
        "duration_minutes": 30
    }
    r = requests.post(f"{BASE_URL}/location/share", json=invalid_location, headers=headers)
    log_test("Rejeitar coordenadas inválidas", r.status_code in [400, 422], f"Status: {r.status_code}")
    
    # Parar compartilhamento
    r = requests.delete(f"{BASE_URL}/location/stop", headers=headers)
    log_test("Parar compartilhamento", r.status_code == 200)

def test_bonds_and_meetings(token, user_id):
    """Testa vínculos e encontros"""
    print("\n" + "="*60)
    print("11. TESTE DE VÍNCULOS E ENCONTROS")
    print("="*60)
    
    if not token:
        log_test("Vínculos", False, "Token não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Listar vínculos
    r = requests.get(f"{BASE_URL}/location/bonds", headers=headers)
    log_test("Listar vínculos", r.status_code == 200)
    
    # Listar convites recebidos
    r = requests.get(f"{BASE_URL}/meeting/invites/received", headers=headers)
    log_test("Listar convites recebidos", r.status_code == 200)
    
    # Listar convites enviados
    r = requests.get(f"{BASE_URL}/meeting/invites/sent", headers=headers)
    log_test("Listar convites enviados", r.status_code == 200)

def test_drive_system(token):
    """Testa sistema de arquivos"""
    print("\n" + "="*60)
    print("12. TESTE DE DRIVE/ARQUIVOS")
    print("="*60)
    
    if not token:
        log_test("Upload de arquivo", False, "Token não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Upload de arquivo
    file_content = b"Conteudo de teste para arquivo"
    files = {"file": ("test_file.txt", file_content, "text/plain")}
    
    r = requests.post(f"{BASE_URL}/drive/upload", files=files, headers=headers)
    log_test("Upload de arquivo", r.status_code == 201, f"Status: {r.status_code}")
    
    # Listar arquivos
    r = requests.get(f"{BASE_URL}/drive/files", headers=headers)
    log_test("Listar arquivos", r.status_code == 200)
    
    # Estatísticas do drive
    r = requests.get(f"{BASE_URL}/drive/stats", headers=headers)
    log_test("Estatísticas do drive", r.status_code == 200)

def test_notifications(token):
    """Testa sistema de notificações"""
    print("\n" + "="*60)
    print("13. TESTE DE NOTIFICAÇÕES")
    print("="*60)
    
    if not token:
        log_test("Notificações", False, "Token não disponível")
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Listar minhas notificações
    r = requests.get(f"{BASE_URL}/notifications/my", headers=headers)
    log_test("Listar minhas notificações", r.status_code == 200)
    
    # Contador de não lidas
    r = requests.get(f"{BASE_URL}/notifications/unread-count", headers=headers)
    log_test("Contador de não lidas", r.status_code == 200)

def test_cleanup(token, model_id):
    """Limpa dados de teste"""
    print("\n" + "="*60)
    print("14. LIMPEZA")
    print("="*60)
    
    if not token:
        return
    
    headers = {"Authorization": f"Bearer {token}"}
    
    # Deletar modelo de teste
    if model_id:
        r = requests.delete(f"{BASE_URL}/ai/models/{model_id}", headers=headers)
        log_test("Deletar modelo de teste", r.status_code == 200, f"Status: {r.status_code}")

def print_summary():
    """Imprime resumo dos testes"""
    print("\n" + "="*60)
    print("RESUMO DOS TESTES")
    print("="*60)
    print(f"✓ Testes passados: {TESTS_PASSED}")
    print(f"✗ Testes falhados: {TESTS_FAILED}")
    print(f"Total: {TESTS_PASSED + TESTS_FAILED}")
    
    if ERRORS:
        print("\nErros encontrados:")
        for error in ERRORS:
            print(f"  - {error}")
    
    print("\n" + "="*60)
    
    return TESTS_FAILED == 0

def main():
    print("\n" + "="*60)
    print("TESTE COMPLETO DO SISTEMA SYRA API")
    print("="*60)
    print(f"URL Base: {BASE_URL}")
    print(f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Executar testes
    test_api_health()
    token, user_id = test_auth_system()
    model_id = test_ai_models(token, user_id)
    test_knowledge_base(token, model_id)
    test_ai_commands(token, model_id)
    test_ai_chat(token, model_id)
    test_dataset_upload(token)
    test_training(token, model_id)
    test_selene_integration(token)
    test_location_system(token, user_id)
    test_bonds_and_meetings(token, user_id)
    test_drive_system(token)
    test_notifications(token)
    test_cleanup(token, model_id)
    
    success = print_summary()
    
    sys.exit(0 if success else 1)

if __name__ == "__main__":
    main()
