#!/bin/bash
# Script de comandos úteis para o Sistema Syra API

echo "🚀 Sistema Syra API - Comandos Úteis"
echo "===================================="
echo ""

# Função para exibir menu
show_menu() {
    echo "Escolha uma opção:"
    echo "1) Iniciar servidor"
    echo "2) Iniciar servidor em background"
    echo "3) Parar servidor"
    echo "4) Testar sistema de notificações"
    echo "5) Limpar banco de dados"
    echo "6) Verificar status do servidor"
    echo "7) Ver logs do servidor"
    echo "8) Instalar dependências"
    echo "9) Abrir documentação (Swagger)"
    echo "0) Sair"
    echo ""
}

# Ativa ambiente virtual
activate_env() {
    source /root/Syra/bin/activate
    cd /root/SyraApi
}

# Opções do menu
case "$1" in
    1|start)
        echo "▶️  Iniciando servidor..."
        activate_env
        python main.py
        ;;
    2|background)
        echo "▶️  Iniciando servidor em background..."
        activate_env
        nohup python main.py > server.log 2>&1 &
        echo "✅ Servidor iniciado! PID: $!"
        echo "📋 Logs em: server.log"
        ;;
    3|stop)
        echo "⏹️  Parando servidor..."
        pkill -f "python main.py"
        echo "✅ Servidor parado!"
        ;;
    4|test)
        echo "🧪 Testando sistema de notificações..."
        activate_env
        python test_notifications.py
        ;;
    5|clean)
        echo "🗑️  Limpando banco de dados..."
        activate_env
        rm -f DB/syra_users.db
        rm -rf DB/user_data/*
        echo "✅ Banco de dados limpo!"
        ;;
    6|status)
        echo "📊 Verificando status..."
        if pgrep -f "python main.py" > /dev/null; then
            echo "✅ Servidor está RODANDO"
            echo "PID: $(pgrep -f 'python main.py')"
        else
            echo "❌ Servidor NÃO está rodando"
        fi
        ;;
    7|logs)
        echo "📋 Logs do servidor:"
        tail -f server.log
        ;;
    8|install)
        echo "📦 Instalando dependências..."
        activate_env
        pip install -r requirements.txt
        echo "✅ Dependências instaladas!"
        ;;
    9|docs)
        echo "📚 Abrindo documentação..."
        echo "Acesse: http://localhost:80/docs"
        ;;
    *)
        show_menu
        read -p "Opção: " option
        bash syra_commands.sh $option
        ;;
esac
