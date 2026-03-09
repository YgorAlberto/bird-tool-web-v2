#!/bin/bash

clear

echo ""
echo "╔════════════════════════════════════════════════════╗"
echo "║                 BIRD TOOL WEB                       ║"
echo "║            Pentest Automation Suite                ║"
echo "╚════════════════════════════════════════════════════╝"
echo ""
echo "██████╗ ██╗██████╗ ██████╗ "
echo "██╔══██╗██║██╔══██╗██╔══██╗"
echo "██████╔╝██║██████╔╝██║  ██║"
echo "██╔══██╗██║██╔══██╗██║  ██║"
echo "██████╔╝██║██║  ██║██████╔╝"
echo "╚═════╝ ╚═╝╚═╝  ╚═╝╚═════╝ "
echo ""
echo "┌────────────────────────────────────────────────────┐"
echo "│  Ferramentas Integradas:                           │"
echo "│  • assetfinder • hakrawler   • gau                 │"
echo "│  • sublist3r   • urlfinder   • katana              │"
echo "│  • dnsenum    • subfinder    • waybackurls         │"
echo "│  • dnsrecon   • fierce      • bird-craftjs         │"
echo "├────────────────────────────────────────────────────┤"
echo "│  Dashboards:                                        │"
echo "│  • 📊 Dashboard (análise baseada em regras)         │"
echo "│  • 🤖 Dashboard LLM (análise com IA/Ollama)         │"
echo "└────────────────────────────────────────────────────┘"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  👨‍💻 Desenvolvedor: KidMan"
echo "  📁 GitHub: https://github.com/YgorAlberto"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ============================================
# DEPENDÊNCIAS — escolha interativa
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📦 DEPENDÊNCIAS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
read -p "Deseja instalar/atualizar dependências? [s/N]: " install_deps
if [[ "$install_deps" =~ ^[sS]$ ]]; then
    echo ""
    echo "🔧 Executando instalação de dependências..."
    ./dependencias.sh
    echo ""
    echo "✅ Dependências instaladas"
else
    echo "⏭️  Pulando instalação de dependências"
fi
echo ""

# ============================================
# DASHBOARD — escolha interativa
# ============================================
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📊 ESCOLHA O DASHBOARD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  1) 📊 Dashboard (sem LLM — análise por regras)"
echo "  2) 🤖 Dashboard LLM (requer Ollama rodando)"
echo "  3) 📊 + 🤖 Ambos"
echo ""
read -p "Escolha [1/2/3] (padrão: 1): " dashboard_choice
dashboard_choice=${dashboard_choice:-1}
echo ""

# ============================================
# FERRAMENTAS — Primeira execução (descoberta)
# ============================================

# Ferramentas de descoberta de subdomínios + DNS
discovery_scripts=(
    "./tool-assetfinder.sh"
    "./tool-sublist3r.sh"
    "./tool-subfinder.sh"
)

# Ferramentas secundárias (fierce, hakrawler, waybackurl, gau)
# Estas não buscam subdomínios — usam os já descobertos
secondary_scripts=(
    "./tool-urlfinder.sh"
    "./tool-dnsrecon.sh"
    "./tool-dnsenum.sh"
    "./tool-fierce.sh"
    "./tool-hakrawler.sh"
    "./tool-waybackurl.sh"
    "./tool-gau.sh"
)

# Função para executar uma lista de scripts em paralelo
run_scripts_parallel() {
    local scripts_to_run=("$@")
    local pids=()
    for script in "${scripts_to_run[@]}"; do
        $script &
        pids+=($!)
    done
    for pid in "${pids[@]}"; do
        wait $pid
    done
}

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🚀 INICIANDO BUSCAS COM AS FERRAMENTAS"
echo "📅 $(date '+%d/%m/%Y %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
# Primeira execução: descoberta de subdomínios + DNS + URLs
run_scripts_parallel "${discovery_scripts[@]}" "${secondary_scripts[@]}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ KATANA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-katana.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💾 SALVANDO SUBDOMÍNIOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./parsing-domains.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ VALIDANDO SUBDOMÍNIOS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./domain-validator.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 ESCANEANDO SUBDOMÍNIOS ENCONTRADOS"
echo "   (fierce, hakrawler, waybackurl, gau)"
echo "📅 $(date '+%d/%m/%Y %H:%M:%S')"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
# Segunda execução: apenas ferramentas secundárias nos subs descobertos
run_scripts_parallel "${secondary_scripts[@]}"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ KATANA"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-katana.sh

echo " "
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔍 ANALISANDO ARQUIVOS EM BUSCA DE TERMOS INTERESSANTES"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
./tool-bird-craftjs.sh

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ FERRAMENTAS FINALIZADAS"
echo "📊 GERANDO DASHBOARD HTML"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Gerar dashboard(s) conforme escolha
case "$dashboard_choice" in
    1)
        echo "📊 Gerando Dashboard (sem LLM)..."
        ./tool-web-dashboard.sh
        ;;
    2)
        echo "🤖 Gerando Dashboard LLM..."
        ./tool-web-dashboard-llm.sh
        ;;
    3)
        echo "📊 Gerando Dashboard (sem LLM)..."
        ./tool-web-dashboard.sh
        echo ""
        echo "🤖 Gerando Dashboard LLM..."
        ./tool-web-dashboard-llm.sh
        ;;
    *)
        echo "📊 Gerando Dashboard (sem LLM)..."
        ./tool-web-dashboard.sh
        ;;
esac

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "                    BIRD TOOL WEB - FINALIZADO"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📅 Data/Hora: $(date '+%d/%m/%Y %H:%M:%S')"
echo "📁 Resultados salvos em: OUT-WEB-BIRD/"
case "$dashboard_choice" in
    1) echo "📁 Dashboard salvo em: dashboard/" ;;
    2) echo "📁 Dashboard LLM salvo em: dashboard-llm/" ;;
    3) echo "📁 Dashboard salvo em: dashboard/ + dashboard-llm/" ;;
esac

echo ""
echo "🌐 Abrindo dashboard no navegador..."
case "$dashboard_choice" in
    1) xdg-open "dashboard/index.html" 2>/dev/null & ;;
    2) xdg-open "dashboard-llm/index.html" 2>/dev/null & ;;
    3) xdg-open "dashboard/index.html" 2>/dev/null &
       xdg-open "dashboard-llm/index.html" 2>/dev/null & ;;
    *) xdg-open "dashboard/index.html" 2>/dev/null & ;;
esac
