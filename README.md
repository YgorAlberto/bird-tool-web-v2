# 🐦 BIRD TOOL WEB v4

<p align="center">
  <b>Automated Web Reconnaissance & Security Analysis Suite</b><br>
  <i>Subdomain discovery → Validation → Deep crawling → Dashboard generation</i>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Shell-Bash-4EAA25?logo=gnu-bash&logoColor=white" />
  <img src="https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/Platform-Linux-FCC624?logo=linux&logoColor=black" />
  <img src="https://img.shields.io/badge/License-MIT-blue" />
</p>

---

## 📌 O que é

**Bird Tool Web** é uma suíte de automação para reconhecimento web e análise de segurança. Executa mais de 12 ferramentas em paralelo, valida subdomínios, consulta o Shodan, e gera **dashboards HTML interativos** com análise de risco, exploração de portas, fuzzing e visualização em árvore de URLs.

### Dois modos de dashboard:
| Dashboard | Descrição |
|-----------|-----------|
| 📊 **Dashboard Auto** | Análise baseada em regras (sem dependência externa) |
| 🤖 **Dashboard LLM** | Análise com IA via Ollama (deepseek-r1:14b) |

---

## 🚀 Como Funciona

```
┌─────────────────────────────────────────────────────────────────┐
│  1. DESCOBERTA          Busca subdomínios com 6 ferramentas     │
│     assetfinder, sublist3r, subfinder, dnsenum, dnsrecon        │
├─────────────────────────────────────────────────────────────────┤
│  2. VALIDAÇÃO           Filtra apenas subdomínios ativos (DNS)  │
│     domain-validator.sh, parsing-domains.sh                     │
├─────────────────────────────────────────────────────────────────┤
│  3. ESCANEAMENTO        Executa exploração nos subs encontrados │
│     fierce, hakrawler, waybackurls, gau, urlfinder, katana      │
├─────────────────────────────────────────────────────────────────┤
│  4. ANÁLISE             Busca dados sensíveis em JS             │
│     bird-craftjs (API keys, tokens, senhas, rotas)              │
├─────────────────────────────────────────────────────────────────┤
│  5. DASHBOARD           Gera relatório HTML interativo          │
│     Shodan API + análise de risco + exploração de portas        │
└─────────────────────────────────────────────────────────────────┘
```

---

## ⚙️ Instalação

```bash
git clone https://github.com/YgorAlberto/bird-tool-web.git
cd bird-tool-web
chmod +x *.sh
```

### Instalar dependências
```bash
./dependencias.sh
```
> Instala: assetfinder, dnsenum, dnsrecon, fierce, hakrawler, subfinder, sublist3r, waybackurls, urlfinder, gau, katana, python3, jq, Ollama + deepseek-r1:14b

---

## 📋 Uso

### 1. Defina o alvo
```bash
echo "seu.alvo.com.br" > target.txt
```

### 2. Execute
```bash
./BIRD-TOOL-WEB-v4.sh
```

### 3. Menu interativo
O script pergunta:
```
📦 Deseja instalar/atualizar dependências? [s/N]

📊 Qual dashboard gerar?
  1) 📊 Dashboard (sem LLM)
  2) 🤖 Dashboard LLM (requer Ollama)
  3) 📊 + 🤖 Ambos
```

### 4. Resultados
```
OUT-WEB-BIRD/           ← Dados brutos de todas as ferramentas
dashboard/              ← Dashboard HTML (análise por regras)
dashboard-llm/          ← Dashboard HTML (análise com IA)
```

---

## 🔧 Ferramentas Integradas

### Descoberta de Subdomínios
| Ferramenta | Descrição |
|------------|-----------|
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Descoberta rápida de subdomínios |
| [subfinder](https://github.com/projectdiscovery/subfinder) | Enumeração passiva de subdomínios |
| [sublist3r](https://github.com/aboul3la/Sublist3r) | Enumeração via múltiplas fontes |
| [dnsenum](https://github.com/fwaeytens/dnsenum) | Enumeração DNS completa |
| [dnsrecon](https://github.com/darkoperator/dnsrecon) | Reconhecimento de registros DNS |

### Exploração & Crawling
| Ferramenta | Descrição |
|------------|-----------|
| [fierce](https://github.com/mschwager/fierce) | Mapeamento DNS e brute-force |
| [hakrawler](https://github.com/hakluke/hakrawler) | Rastreio de URLs em aplicações web |
| [waybackurls](https://github.com/tomnomnom/waybackurls) | URLs históricas via Wayback Machine |
| [gau](https://github.com/lc/gau) | URLs de múltiplas fontes públicas |
| [urlfinder](https://github.com/projectdiscovery/urlfinder) | Busca de URLs expostas |
| [katana](https://github.com/projectdiscovery/katana) | Crawler com JS rendering (Chromium) |

### Análise
| Ferramenta | Descrição |
|------------|-----------|
| **BRID-CRAFTJS** | Scanner de código JS (API keys, tokens, senhas, emails, rotas) |
| [Shodan API](https://www.shodan.io/) | Portas abertas, CVEs, serviços expostos |
| [Ollama](https://ollama.ai/) | Análise de risco com IA (opcional) |

---

## 📊 Dashboard — Funcionalidades

### Páginas Geradas
| Página | Conteúdo |
|--------|----------|
| **index.html** | Resumo executivo, análise de risco, achados, vulnerabilidades, recomendações, comandos de exploração |
| **subdomains.html** | Tabela com status, IPs, portas/serviços, botões de ação (IP, Dom, GIT, Fuzz, Explore) |
| **brid-craftjs.html** | Dados sensíveis encontrados em JS (deduplicados e ordenados) |
| **urls.html** | Todas as URLs descobertas (deduplicadas e ordenadas) |
| **tree.html** | Visualização em árvore de diretórios/arquivos clicáveis |

### Botões de Ação por Subdomínio
| Botão | Funcionalidade |
|-------|----------------|
| ⚙️ **IP** | Shodan, Censys, FOFA + dorks de IP |
| 🌐 **Dom** | Busca por domínio + Google dorks (docs, login, APIs, leaks) |
| 💻 **GIT** | GitHub/GitLab code search + dorks de secrets |
| 🔍 **Fuzz** | Comandos copy-paste: gobuster, feroxbuster, dirsearch, ffuf, dirb |
| 🔓 **Explore** | Links e comandos por porta aberta (HTTP, FTP, SSH, SMB, RDP, DB...) |

### 🔥 Fuzz Geral
Card na página de subdomínios com comando `for` que executa fuzzing em **todos** os subdomínios ativos de uma vez, com saída salva em arquivo.

### 🚀 Próximos Passos
Seção no dashboard com comandos customizados baseados na superfície de ataque:
- Nmap Deep Scan / Vuln Scripts
- Nuclei Scan em todos os subs
- SSL Check / HTTP Headers
- FTP Anonymous Check
- SSH Banner Grab
- Database Service Scan

---

## 📁 Estrutura de Arquivos

```
bird-tool-web/
├── BIRD-TOOL-WEB-v4.sh          # Script principal (menu interativo)
├── dependencias.sh               # Instalador de dependências + Ollama
├── target.txt                    # Arquivo de alvos (um domínio por linha)
├── parsing-domains.sh            # Consolida subdomínios encontrados
├── domain-validator.sh           # Valida subdomínios via DNS
├── tool-assetfinder.sh           # Wrapper assetfinder
├── tool-subfinder.sh             # Wrapper subfinder
├── tool-sublist3r.sh             # Wrapper sublist3r
├── tool-dnsenum.sh               # Wrapper dnsenum
├── tool-dnsrecon.sh              # Wrapper dnsrecon
├── tool-fierce.sh                # Wrapper fierce
├── tool-hakrawler.sh             # Wrapper hakrawler
├── tool-waybackurl.sh            # Wrapper waybackurls
├── tool-gau.sh                   # Wrapper gau
├── tool-urlfinder.sh             # Wrapper urlfinder
├── tool-katana.sh                # Wrapper katana (JS crawl)
├── tool-bird-craftjs.sh          # Scanner JS (busca dados sensíveis)
├── tool-bird-craftjs-v2.py       # Motor Python do BRID-CRAFTJS
├── tool-web-dashboard.sh         # Gerador do dashboard (sem LLM)
├── tool-web-dashboard-llm.sh     # Gerador do dashboard (com LLM)
├── OUT-WEB-BIRD/                 # Saídas das ferramentas
├── dashboard/                    # Dashboard HTML gerado (sem LLM)
└── dashboard-llm/                # Dashboard HTML gerado (com LLM)
```

---

## 📦 Pré-requisitos

- **OS:** Linux (recomendado: Kali Linux / Parrot OS)
- **Runtime:** bash, python3, Go (para instalar ferramentas via `go install`)
- **API Key (opcional):** `SHODAN_API_KEY` para consulta de portas/serviços via API paga
- **LLM (opcional):** Ollama com modelo deepseek-r1:14b para Dashboard LLM

### Variáveis de Ambiente
```bash
export SHODAN_API_KEY="sua_chave_aqui"    # Opcional: habilita Shodan API paga
```

---

## 👨‍💻 Autor

**KidMan** — [@YgorAlberto](https://github.com/YgorAlberto)

---

## ⚠️ Aviso Legal

Esta ferramenta foi desenvolvida para fins educacionais e de segurança ofensiva autorizada. Use apenas em domínios e redes para os quais você possui autorização explícita. O autor não se responsabiliza pelo uso indevido.
