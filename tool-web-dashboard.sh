#!/bin/bash

# Bird Tool Web Analyzer - Dashboard Generator v3 (sem LLM)
# Página unificada de subdomínios com status, IPs, portas/serviços, e busca em repos
# Uso: ./tool-web-dashboard.sh
# Usa Shodan InternetDB (gratuito) + Shodan API (pago, fallback)
# Análise baseada em regras — não requer Ollama/LLM

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT_DIR="${SCRIPT_DIR}/OUT-WEB-BIRD"
DASHBOARD_DIR="${SCRIPT_DIR}/dashboard"
ASSETS_DIR="${DASHBOARD_DIR}/assets"
SHODAN_API_KEY="${SHODAN_API_KEY:-}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Try to get Shodan API Key from file if not in environment
if [[ -z "$SHODAN_API_KEY" && -f "$HOME/.shodan-api" ]]; then
    SHODAN_API_KEY=$(cat "$HOME/.shodan-api" | head -n 1 | tr -d '[:space:]')
    [[ -n "$SHODAN_API_KEY" ]] && log_info "Utilizando Shodan API key extraída de ~/.shodan-api"
fi

TEMP_DIR=$(mktemp -d)
trap "rm -rf ${TEMP_DIR}" EXIT

# ============================================
# SCOPE DETECTION
# ============================================
SCOPE_DOMAINS_FILE="${TEMP_DIR}/scope_domains.txt"
TWO_LEVEL_TLDS="com.br org.br net.br edu.br gov.br mil.br co.uk org.uk net.uk co.nz org.nz net.nz com.au org.au net.au"

extract_base_domain() {
    local target="$1"
    local tld2=$(echo "$target" | awk -F'.' '{print $(NF-1)"."$NF}')
    if echo "$TWO_LEVEL_TLDS" | grep -qw "$tld2"; then
        echo "$target" | awk -F'.' '{if(NF>=3) print $(NF-2)"."$(NF-1)"."$NF; else print $0}'
    else
        echo "$target" | awk -F'.' '{if(NF>=2) print $(NF-1)"."$NF; else print $0}'
    fi
}

build_scope() {
    > "$SCOPE_DOMAINS_FILE"
    for target_dir in "$OUT_DIR"/*/; do
        [[ ! -d "$target_dir" ]] && continue
        local target=$(basename "$target_dir")
        [[ "$target" == "Host" || "$target" == "host" || ! "$target" =~ \. ]] && continue
        extract_base_domain "$target" >> "$SCOPE_DOMAINS_FILE"
    done
    sort -u "$SCOPE_DOMAINS_FILE" -o "$SCOPE_DOMAINS_FILE"
    log_info "Escopo: $(cat "$SCOPE_DOMAINS_FILE" | tr '\n' ', ' | sed 's/,$//')"
}

is_in_scope() {
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        echo "$1" | grep -qi "$domain" && return 0
    done < "$SCOPE_DOMAINS_FILE"
    return 1
}

strip_ansi() {
    python3 -c "
import re,sys
d=open(sys.argv[1]).read()
d=re.sub(chr(27)+r'\[[0-9;]*[mKHJABCDs]?','',d)
d=re.sub(r'\[?[0-9;]*[mKHJ]','',d)
d=re.sub(r'^0m','',d,flags=re.MULTILINE)
print(d,end='')
" "$1" 2>/dev/null || cat "$1"
}

# ============================================
# DATA PROCESSING
# ============================================

# Files for correlating data
SUBS_FILE="${TEMP_DIR}/all_subs.txt"
IP_MAP_FILE="${TEMP_DIR}/ip_map.txt"       # format: subdomain|ip
URLS_FILE="${TEMP_DIR}/urls_clean.txt"
CRAFTJS_FILE="${TEMP_DIR}/craftjs_parsed.json"
SHODAN_CACHE="${TEMP_DIR}/shodan_cache"

process_all_data() {
    log_info "Processando TODO o conteúdo de OUT-WEB-BIRD..."

    local subs_raw="${TEMP_DIR}/subs_raw.txt"
    local urls_raw="${TEMP_DIR}/urls_raw.txt"
    > "$subs_raw" && > "$urls_raw"
    > "$IP_MAP_FILE" && > "$CRAFTJS_FILE"
    > "${TEMP_DIR}/targets.txt"
    mkdir -p "$SHODAN_CACHE"

    local total_files=0

    for target_dir in "$OUT_DIR"/*/; do
        [[ ! -d "$target_dir" ]] && continue
        local target=$(basename "$target_dir")
        echo "$target" >> "${TEMP_DIR}/targets.txt"

        for file in "$target_dir"/*; do
            [[ ! -f "$file" || ! -s "$file" ]] && continue
            local fname=$(basename "$file")
            total_files=$((total_files + 1))

            case "$fname" in
                *-assetfinder|*-subfinder|*-sublist3r)
                    cat "$file" >> "$subs_raw" ;;

                *-fierce)
                    # Extract Found: entries → domain→IP mapping
                    grep "^Found:" "$file" 2>/dev/null | while IFS= read -r line; do
                        if [[ "$line" =~ Found:\ ([a-zA-Z0-9._-]+)\.\ \(([0-9.]+)\) ]]; then
                            local fdomain="${BASH_REMATCH[1]}"
                            local fip="${BASH_REMATCH[2]}"
                            echo "$fdomain" >> "$subs_raw"
                            echo "${fdomain}|${fip}" >> "$IP_MAP_FILE"
                        fi
                    done ;;

                *-dnsenum|*-dnsrecon)
                    # Strip ANSI before parsing
                    local clean=$(strip_ansi "$file")
                    local bd=$(extract_base_domain "$target")
                    # Extract subdomains
                    echo "$clean" | grep -oE "[a-zA-Z0-9][-a-zA-Z0-9]*\.$bd" 2>/dev/null >> "$subs_raw"
                    # Extract A record mappings (subdomain → IP)
                    echo "$clean" | grep -E "IN\s+A\s+" 2>/dev/null | while IFS= read -r line; do
                        local sub=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
                        local ip=$(echo "$line" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -1)
                        if [[ -n "$sub" && -n "$ip" ]] && is_in_scope "$sub"; then
                            echo "${sub}|${ip}" >> "$IP_MAP_FILE"
                        fi
                    done
                    # Extract CNAME mappings
                    echo "$clean" | grep -E "IN\s+CNAME" 2>/dev/null | while IFS= read -r line; do
                        local sub=$(echo "$line" | awk '{print $1}' | sed 's/\.$//')
                        if [[ -n "$sub" ]] && is_in_scope "$sub"; then
                            echo "$sub" >> "$subs_raw"
                        fi
                    done ;;

                *-hakrawler|*-s-hakrawler|*-URL-*|*-FULL-URLs)
                    grep -E '^https?://' "$file" 2>/dev/null >> "$urls_raw" ;;

                *-bird-craftjs|*-bird-crafjs)
                    # Parse CRAFTJS findings
                    local titulo="" dado="" url=""
                    while IFS= read -r line; do
                        if [[ "$line" =~ ^TITULO:\ (.+)$ ]]; then titulo="${BASH_REMATCH[1]}"
                        elif [[ "$line" =~ ^DADO:\ (.+)$ ]]; then dado="${BASH_REMATCH[1]}"
                        elif [[ "$line" =~ ^URL:\ (.+)$ ]]; then
                            url="${BASH_REMATCH[1]}"
                            if [[ -n "$titulo" && -n "$dado" ]]; then
                                echo "{\"titulo\":\"$(echo "$titulo" | sed 's/"/\\"/g')\",\"dado\":\"$(echo "$dado" | sed 's/"/\\"/g')\",\"url\":\"$(echo "$url" | sed 's/"/\\"/g')\"}" >> "$CRAFTJS_FILE"
                                titulo="" dado="" url=""
                            fi
                        fi
                    done < "$file" 2>/dev/null ;;

                *katana.json)
                    if command -v jq &>/dev/null; then
                        jq -r '.request.endpoint // empty' "$file" 2>/dev/null >> "$urls_raw"
                    fi ;;
            esac
        done
    done

    # Build scope pattern
    local pattern=""
    while IFS= read -r domain; do
        [[ -z "$domain" ]] && continue
        pattern="${pattern:+$pattern\|}$domain"
    done < "$SCOPE_DOMAINS_FILE"

    # Clean + dedupe + scope filter subdomains
    sed -i 's/ (FQDN)//g; s/(FQDN)//g; s/ (IPAddress)//g; s/(IPAddress)//g' "$subs_raw" 2>/dev/null
    sort -u "$subs_raw" | grep -v '^$' | grep '\.' | grep -v 'virustotal' | \
        grep -i "$pattern" > "$SUBS_FILE" 2>/dev/null || true

    # Clean + scope filter URLs
    sort -u "$urls_raw" | grep -E '^https?://' | \
        grep -i "$pattern" > "$URLS_FILE" 2>/dev/null || true

    # Clean IP map (dedupe)
    sort -u "$IP_MAP_FILE" -o "$IP_MAP_FILE" 2>/dev/null

    local nsubs=$(wc -l < "$SUBS_FILE" | tr -d ' ')
    local nurls=$(wc -l < "$URLS_FILE" | tr -d ' ')
    local nmaps=$(wc -l < "$IP_MAP_FILE" | tr -d ' ')
    log_success "Processados: $total_files arquivos"
    log_success "  → $nsubs subs, $nurls URLs, $nmaps mapeamentos IP"
}

# ============================================
# DNS VALIDATION + IP CORRELATION
# ============================================

validate_subdomains() {
    log_info "Validando subdomínios (DNS resolve + correlação IP)..."
    local validated="${TEMP_DIR}/validated_subs.txt"
    # Format: subdomain|status|ip
    > "$validated"

    local total=$(wc -l < "$SUBS_FILE" | tr -d ' ')
    local count=0

    while IFS= read -r sub; do
        [[ -z "$sub" ]] && continue
        count=$((count + 1))
        if (( count % 20 == 0 )); then
            log_info "  Validando: $count/$total..."
        fi

        local ip=""
        local status="inactive"

        # Try DNS lookup first
        local dns_result
        dns_result=$(host -W 2 "$sub" 2>/dev/null)
        if echo "$dns_result" | grep -q "has address"; then
            ip=$(echo "$dns_result" | grep "has address" | head -1 | awk '{print $NF}')
            status="active"
        fi

        # If no IP from DNS, check fierce/dnsenum mappings
        if [[ -z "$ip" ]]; then
            ip=$(grep -i "^${sub}|" "$IP_MAP_FILE" 2>/dev/null | head -1 | cut -d'|' -f2)
            # Also search without trailing dot variants
            if [[ -z "$ip" ]]; then
                ip=$(grep -i "^${sub}\.|" "$IP_MAP_FILE" 2>/dev/null | head -1 | cut -d'|' -f2)
            fi
        fi

        # Collect all IPs for this subdomain
        local all_ips="$ip"
        local extra_ips=$(grep -i "^${sub}|" "$IP_MAP_FILE" 2>/dev/null | cut -d'|' -f2 | sort -u | tr '\n' ',' | sed 's/,$//')
        if [[ -n "$extra_ips" && "$extra_ips" != "$ip" ]]; then
            if [[ -n "$all_ips" ]]; then
                all_ips=$(echo -e "${all_ips}\n${extra_ips}" | tr ',' '\n' | sort -u | tr '\n' ',' | sed 's/,$//')
            else
                all_ips="$extra_ips"
            fi
        fi

        echo "${sub}|${status}|${all_ips}" >> "$validated"
    done < "$SUBS_FILE"

    local active=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | wc -l | tr -d ' ')
    local inactive=$(grep '|inactive|' "${TEMP_DIR}/validated_subs.txt" | wc -l | tr -d ' ')
    log_success "Validação: $active ativos, $inactive inativos (total: $total)"
}

# ============================================
# SHODAN: InternetDB (free) + Paid API (fallback)
# ============================================

query_shodan_ip() {
    local ip="$1"
    [[ -z "$ip" ]] && return 1

    local cache_file="${SHODAN_CACHE}/${ip}.json"
    if [[ -f "$cache_file" ]]; then
        cat "$cache_file"
        return 0
    fi

    # 1) Try paid Shodan API first if key is set (Prioritize as requested)
    if [[ -n "$SHODAN_API_KEY" ]]; then
        local result
        result=$(timeout 15 curl -sf "https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_API_KEY}&minify=true" 2>/dev/null)
        if [[ $? -eq 0 && -n "$result" ]]; then
            # Convert paid API format to InternetDB-compatible format (with CVES)
            local converted
            converted=$(python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    out={'ip':d.get('ip_str',''),'ports':d.get('ports',[]),'cpes':d.get('cpe',[]),'vulns':d.get('vulns',[]),'hostnames':d.get('hostnames',[])}
    for item in d.get('data',[]):
        prod=item.get('product','')
        if prod:
            cpe=f'cpe:/a:vendor:{prod.lower().replace(\" \",\"_\")}'
            if cpe not in out['cpes']: out['cpes'].append(cpe)
    print(json.dumps(out))
except: pass
" <<< "$result" 2>/dev/null)
            if [[ -n "$converted" ]]; then
                echo "$converted" > "$cache_file"
                echo "$converted"
                return 0
            fi
        fi
    fi

    # 2) Fallback to free InternetDB
    local result
    result=$(timeout 10 curl -sf "https://internetdb.shodan.io/${ip}" 2>/dev/null)
    if [[ $? -eq 0 && -n "$result" && "$result" != *"No information"* ]]; then
        echo "$result" > "$cache_file"
        echo "$result"
        return 0
    fi
    return 1
}

get_ports_services() {
    local ip="$1"
    [[ -z "$ip" ]] && echo "" && return

    local idb_data
    idb_data=$(query_shodan_ip "$ip" 2>/dev/null)
    if [[ -n "$idb_data" ]]; then
        python3 -c "
import json,sys
try:
    d=json.loads(sys.stdin.read())
    ports=d.get('ports',[])
    cpes=d.get('cpes',[])
    vulns=d.get('vulns',[])
    # Well-known port→service mapping
    svc={20:'ftp-data',21:'ftp',22:'ssh',23:'telnet',25:'smtp',53:'dns',67:'dhcp',
         69:'tftp',80:'http',110:'pop3',111:'rpc',119:'nntp',123:'ntp',135:'msrpc',
         137:'netbios',139:'netbios',143:'imap',161:'snmp',162:'snmp-trap',179:'bgp',
         389:'ldap',443:'https',445:'smb',465:'smtps',514:'syslog',515:'printer',
         587:'submission',631:'ipp',636:'ldaps',873:'rsync',993:'imaps',995:'pop3s',
         1080:'socks',1433:'mssql',1434:'mssql',1521:'oracle',1883:'mqtt',
         2049:'nfs',2375:'docker',2376:'docker-tls',3000:'grafana',3306:'mysql',
         3389:'rdp',5432:'postgres',5672:'amqp',5900:'vnc',6379:'redis',
         6443:'k8s-api',7001:'weblogic',8000:'http-alt',8080:'http-proxy',
         8443:'https-alt',8888:'http-alt',9090:'prometheus',9200:'elasticsearch',
         9300:'elasticsearch',9922:'ssh-alt',11211:'memcached',15672:'rabbitmq-mgmt',
         27017:'mongodb',27018:'mongodb'}
    # Map CPEs to product names
    products={}
    for c in cpes:
        parts=c.split(':')
        if len(parts)>=5 and parts[4]:
            products[parts[4]]=True
    prods=list(products.keys())
    # Build port display with service names
    parts=[]
    for p in sorted(ports):
        name=svc.get(p,'')
        if name:
            parts.append(f'{p}/{name}')
        else:
            parts.append(str(p))
    result=', '.join(parts)
    if prods:
        result += ' | ' + ', '.join(prods[:3])
    if vulns:
        result += ' | ⚠ ' + str(len(vulns)) + ' CVEs'
    print(result)
except:
    print('')
" <<< "$idb_data"
    fi
}

enrich_with_shodan() {
    if [[ -n "$SHODAN_API_KEY" ]]; then
        log_info "Consultando Shodan (InternetDB + API paga como fallback)..."
    else
        log_info "Consultando Shodan InternetDB (sem API key — use SHODAN_API_KEY para fallback)..."
    fi
    local unique_ips="${TEMP_DIR}/unique_ips.txt"
    cut -d'|' -f3 "${TEMP_DIR}/validated_subs.txt" | tr ',' '\n' | sort -u | grep -v '^$' > "$unique_ips"

    local total=$(wc -l < "$unique_ips" | tr -d ' ')
    local count=0 found=0
    while IFS= read -r ip; do
        [[ -z "$ip" ]] && continue
        count=$((count + 1))
        if (( count % 5 == 0 )); then
            log_info "  Shodan: $count/$total IPs..."
        fi
        if query_shodan_ip "$ip" > /dev/null 2>&1; then
            found=$((found + 1))
        fi
        sleep 0.3
    done < "$unique_ips"
    log_success "Shodan: $found/$total IPs com dados de portas/serviços"
}

# ============================================
# RULE-BASED ANALYSIS (no LLM required)
# ============================================

generate_analysis() {
    local active=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | wc -l | tr -d '[:space:]')
    local inactive=$(grep '|inactive|' "${TEMP_DIR}/validated_subs.txt" | wc -l | tr -d '[:space:]')
    local total_urls=$(wc -l < "$URLS_FILE" | tr -d '[:space:]')
    local total_brid=$(wc -l < "$CRAFTJS_FILE" 2>/dev/null | tr -d '[:space:]')
    local scope=$(cat "$SCOPE_DOMAINS_FILE" | tr '\n' ', ' | sed 's/,$//')
    local total_subs=$(( ${active:-0} + ${inactive:-0} ))
    local unique_ips=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | cut -d'|' -f3 | tr ',' '\n' | sort -u | grep -v '^$' | wc -l | tr -d ' ')

    # Analyze Shodan data for all IPs
    local total_ports=0 total_vulns=0 exposed_services="" vuln_list=""
    local has_ftp=false has_ssh=false has_rdp=false has_db=false has_http=false has_admin=false
    for cache_file in "${SHODAN_CACHE}"/*.json; do
        [[ -f "$cache_file" ]] || continue
        local ip_name=$(basename "$cache_file" .json)
        local ip_data=$(python3 -c "
import json,sys
try:
    d=json.load(sys.stdin)
    ports=d.get('ports',[])
    vulns=d.get('vulns',[])
    print(f'{len(ports)}|{len(vulns)}|{\";\".join(str(p) for p in ports)}|{\";\".join(vulns[:5])}')
except: print('0|0||')
" < "$cache_file" 2>/dev/null)
        local np=$(echo "$ip_data" | cut -d'|' -f1)
        local nv=$(echo "$ip_data" | cut -d'|' -f2)
        local ports_str=$(echo "$ip_data" | cut -d'|' -f3)
        local vulns_str=$(echo "$ip_data" | cut -d'|' -f4)
        np=${np:-0}; nv=${nv:-0}
        total_ports=$((total_ports + $np))
        total_vulns=$((total_vulns + $nv))
        [[ "$ports_str" == *21* ]] && has_ftp=true
        [[ "$ports_str" == *22* ]] && has_ssh=true
        [[ "$ports_str" == *3389* ]] && has_rdp=true
        [[ "$ports_str" == *3306* || "$ports_str" == *5432* || "$ports_str" == *27017* || "$ports_str" == *6379* ]] && has_db=true
        [[ "$ports_str" == *80* || "$ports_str" == *443* || "$ports_str" == *8080* || "$ports_str" == *8443* ]] && has_http=true
        [[ "$ports_str" == *9090* || "$ports_str" == *3000* || "$ports_str" == *8888* ]] && has_admin=true
        [[ -n "$vulns_str" ]] && vuln_list="${vuln_list}${vuln_list:+; }${ip_name}: ${vulns_str}"
    done

    # Analyze sensitive data types from BRID-CRAFTJS
    local api_keys=0 tokens=0 routes=0 emails=0 passwords=0
    if [[ -f "$CRAFTJS_FILE" && -s "$CRAFTJS_FILE" ]]; then
        api_keys=$(grep -ci '\(api.key\|apikey\|api_key\|secret\)' "$CRAFTJS_FILE" 2>/dev/null || echo 0)
        tokens=$(grep -ci '\(token\|bearer\|jwt\|auth\)' "$CRAFTJS_FILE" 2>/dev/null || echo 0)
        routes=$(grep -ci '\(route\|endpoint\|api.route\|path\)' "$CRAFTJS_FILE" 2>/dev/null || echo 0)
        emails=$(grep -ci '\(email\|mail\|@\)' "$CRAFTJS_FILE" 2>/dev/null || echo 0)
        passwords=$(grep -ci '\(password\|passwd\|pwd\|senha\)' "$CRAFTJS_FILE" 2>/dev/null || echo 0)
    fi

    # Determine risk level
    local risk_level="BAIXO"
    if [[ $total_vulns -gt 0 ]] || [[ $passwords -gt 0 ]] || $has_rdp || $has_db; then
        risk_level="ALTO"
    elif [[ $total_brid -gt 100 ]] || $has_ftp || [[ $active -gt 20 ]]; then
        risk_level="MEDIO"
    fi
    [[ $total_vulns -gt 5 ]] && risk_level="CRITICO"

    # Build executive summary
    local summary="Reconhecimento do escopo ${scope} identificou ${active} subdomínios ativos e ${inactive} inativos, mapeados para ${unique_ips} IPs únicos. Foram coletadas ${total_urls} URLs e ${total_brid} dados sensíveis em JavaScript. A análise de portas identificou ${total_ports} serviços expostos com ${total_vulns} vulnerabilidades conhecidas (CVEs)."

    # Build attack surface description
    local attack_surface="${unique_ips} IPs com ${total_ports} portas abertas."
    $has_http && attack_surface="${attack_surface} Servidores web detectados."
    $has_ftp && attack_surface="${attack_surface} FTP exposto."
    $has_ssh && attack_surface="${attack_surface} SSH acessível."
    $has_rdp && attack_surface="${attack_surface} RDP exposto."
    $has_db && attack_surface="${attack_surface} Banco de dados acessível externamente."
    $has_admin && attack_surface="${attack_surface} Painéis administrativos detectados."

    # Convert shell booleans to Python booleans
    local py_ftp="False"; $has_ftp && py_ftp="True"
    local py_ssh="False"; $has_ssh && py_ssh="True"
    local py_rdp="False"; $has_rdp && py_rdp="True"
    local py_db="False"; $has_db && py_db="True"
    local py_http="False"; $has_http && py_http="True"
    local py_admin="False"; $has_admin && py_admin="True"

    # Build findings
    local findings="[]"
    findings=$(python3 -c "
import json
f=[]
f.append('${active} subdominios ativos mapeados para ${unique_ips} IPs unicos no escopo ${scope}')
f.append('${total_urls} URLs coletadas - superficie web mapeada')
if int('${total_brid}') > 0: f.append('${total_brid} dados sensiveis encontrados em JavaScript')
if int('${total_ports}') > 0: f.append('${total_ports} portas/servicos expostos via Shodan')
if int('${total_vulns}') > 0: f.append('${total_vulns} CVEs conhecidas associadas aos IPs')
if ${py_ftp}: f.append('FTP (porta 21) exposto - possivel vetor de acesso')
if ${py_rdp}: f.append('RDP (porta 3389) acessivel externamente')
if ${py_db}: f.append('Bancos de dados com acesso externo detectados')
if ${py_admin}: f.append('Paineis administrativos (Grafana/Prometheus) detectados')
print(json.dumps(f[:6], ensure_ascii=False))
" 2>/dev/null)

    # Build vulnerabilities
    local vulnerabilities="[]"
    vulnerabilities=$(python3 -c "
import json
v=[]
if int('${total_vulns}') > 0: v.append('${total_vulns} CVEs conhecidas nos IPs do escopo')
if ${py_ftp}: v.append('FTP exposto na porta 21 - verificar acesso anonimo')
if ${py_rdp}: v.append('RDP exposto - risco de brute-force e exploits (BlueKeep)')
if ${py_db}: v.append('Banco de dados acessivel externamente - risco de exfiltracao')
if int('${passwords}') > 0: v.append('Credenciais encontradas em JavaScript')
if int('${api_keys}') > 0: v.append('API keys/secrets expostos em JavaScript')
if int('${inactive}') > int('${active}'): v.append('Mais subdominios inativos que ativos - possivel subdomain takeover')
if not v: v.append('Nenhuma vulnerabilidade critica identificada automaticamente')
print(json.dumps(v[:5], ensure_ascii=False))
" 2>/dev/null)

    # Build sensitive data findings
    local sensitive_data="[]"
    sensitive_data=$(python3 -c "
import json
s=[]
if int('${api_keys}') > 0: s.append('${api_keys} referencias a API keys/secrets em JavaScript')
if int('${tokens}') > 0: s.append('${tokens} referencias a tokens/JWT/auth em JavaScript')
if int('${routes}') > 0: s.append('${routes} rotas/endpoints de API expostos em JavaScript')
if int('${emails}') > 0: s.append('${emails} referencias a e-mails em JavaScript')
if int('${passwords}') > 0: s.append('${passwords} referencias a senhas em JavaScript')
if not s and int('${total_brid}') > 0: s.append('${total_brid} dados sensiveis diversos em JavaScript')
if not s: s.append('Nenhum dado sensivel identificado')
print(json.dumps(s[:5], ensure_ascii=False))
" 2>/dev/null)

    # Build recommendations
    local recommendations="[]"
    recommendations=$(python3 -c "
import json
r=[]
if int('${total_vulns}') > 0: r.append('Priorizar correcao das ${total_vulns} CVEs identificadas')
if int('${api_keys}') > 0 or int('${passwords}') > 0: r.append('Remover credenciais e API keys dos arquivos JavaScript')
if ${py_ftp}: r.append('Desabilitar FTP ou migrar para SFTP com autenticacao forte')
if ${py_rdp}: r.append('Restringir acesso RDP via VPN e implementar MFA')
if ${py_db}: r.append('Restringir acesso a bancos de dados - apenas IPs internos/VPN')
if int('${inactive}') > 5: r.append('Investigar ${inactive} subdominios inativos para subdomain takeover')
r.append('Implementar WAF e monitoramento continuo de exposicao')
r.append('Revisar configuracoes de CORS e headers de seguranca')
print(json.dumps(r[:6], ensure_ascii=False))
" 2>/dev/null)

    # Output JSON — pipe through stdin to avoid quoting issues
    echo "${summary}|DELIM|${risk_level}|DELIM|${attack_surface}" | python3 -c "
import json,sys
parts = sys.stdin.read().strip().split('|DELIM|')
summary = parts[0] if len(parts) > 0 else ''
risk = parts[1] if len(parts) > 1 else 'MEDIO'
surface = parts[2] if len(parts) > 2 else ''
result = {
    'executive_summary': summary,
    'risk_level': risk,
    'attack_surface': surface,
    'key_findings': ${findings:-[]},
    'vulnerabilities': ${vulnerabilities:-[]},
    'sensitive_data': ${sensitive_data:-[]},
    'recommendations': ${recommendations:-[]}
}
print(json.dumps(result, ensure_ascii=False))
" 2>/dev/null || echo '{"executive_summary":"Análise automática realizada.","risk_level":"MEDIO","attack_surface":"Serviços web identificados.","key_findings":["Subdomínios mapeados","URLs coletadas"],"vulnerabilities":["Verificar serviços expostos"],"sensitive_data":["Dados em JavaScript"],"recommendations":["Revisar exposição"]}'
}

# ============================================
# CSS + JS (same premium design)
# ============================================

generate_css() {
    cat > "${ASSETS_DIR}/style.css" << 'EOFCSS'
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
*{margin:0;padding:0;box-sizing:border-box}
:root{--primary:#6366f1;--primary-light:#818cf8;--secondary:#8b5cf6;--success:#10b981;--warning:#f59e0b;--danger:#ef4444;--info:#3b82f6;--dark:#1e293b;--darker:#0f172a;--darkest:#020617;--light:#f8fafc;--gray:#64748b;--glass:rgba(15,23,42,0.6);--glass-border:rgba(99,102,241,0.15);--glow:rgba(99,102,241,0.15)}
body{font-family:'Inter',system-ui,sans-serif;background:var(--darkest);background-image:radial-gradient(ellipse at 20% 50%,rgba(99,102,241,0.08) 0%,transparent 50%),radial-gradient(ellipse at 80% 20%,rgba(139,92,246,0.06) 0%,transparent 50%),radial-gradient(ellipse at 50% 80%,rgba(16,185,129,0.04) 0%,transparent 50%);color:var(--light);min-height:100vh;line-height:1.6}
.container{max-width:1400px;margin:0 auto;padding:2rem}
nav{background:rgba(2,6,23,0.85);backdrop-filter:blur(20px) saturate(180%);border-bottom:1px solid var(--glass-border);padding:0.75rem 0;position:sticky;top:0;z-index:1000;box-shadow:0 4px 30px rgba(0,0,0,0.3)}
nav .container{display:flex;justify-content:space-between;align-items:center;padding:0 2rem}
nav h1{font-size:1.3rem;font-weight:700;background:linear-gradient(135deg,#818cf8,#c084fc,#22d3ee);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}
nav .nav-links{display:flex;gap:0.3rem;flex-wrap:wrap}
nav .nav-links a{color:#94a3b8;text-decoration:none;padding:0.4rem 0.75rem;border-radius:0.5rem;transition:all 0.3s;font-size:0.82rem;font-weight:500;border:1px solid transparent}
nav .nav-links a:hover,nav .nav-links a.active{color:white;background:rgba(99,102,241,0.15);border-color:var(--glass-border);transform:translateY(-1px)}
.card{background:var(--glass);backdrop-filter:blur(20px) saturate(180%);border:1px solid var(--glass-border);border-radius:1rem;padding:1.5rem;margin-bottom:1.5rem;transition:all 0.4s;position:relative;overflow:hidden}
.card::before{content:'';position:absolute;top:0;left:0;width:100%;height:1px;background:linear-gradient(90deg,transparent,rgba(99,102,241,0.3),transparent)}
.card:hover{border-color:rgba(99,102,241,0.3);box-shadow:0 8px 32px var(--glow)}
.hero-card{background:linear-gradient(135deg,rgba(99,102,241,0.1),rgba(139,92,246,0.05));border-left:3px solid var(--primary)}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1.25rem;margin-bottom:2rem}
.stat-card{background:var(--glass);backdrop-filter:blur(20px);border:1px solid var(--glass-border);border-radius:1rem;padding:1.5rem;text-align:center;transition:all 0.4s;position:relative;overflow:hidden}
.stat-card::after{content:'';position:absolute;bottom:0;left:0;width:100%;height:3px;background:linear-gradient(90deg,var(--primary),var(--secondary));opacity:0;transition:opacity 0.3s}
.stat-card:hover::after{opacity:1}
.stat-card:hover{transform:translateY(-4px);box-shadow:0 12px 40px var(--glow)}
.stat-icon{font-size:1.5rem;margin-bottom:0.5rem}
.stat-card .stat-number{font-size:2.5rem;font-weight:700;background:linear-gradient(135deg,#c7d2fe,#e0e7ff);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;margin-bottom:0.25rem;line-height:1.2}
.stat-card .stat-label{color:#94a3b8;font-size:0.8rem;text-transform:uppercase;letter-spacing:1.5px;font-weight:500}
.stat-card-link{text-decoration:none;color:inherit;display:block}
.table-container{overflow-x:auto;border-radius:1rem;background:var(--glass);border:1px solid var(--glass-border);backdrop-filter:blur(20px)}
table{width:100%;border-collapse:collapse}
thead{background:rgba(99,102,241,0.08);border-bottom:1px solid var(--glass-border)}
thead th{padding:0.85rem 1rem;text-align:left;font-weight:600;color:#c7d2fe;font-size:0.8rem;text-transform:uppercase;letter-spacing:0.8px;white-space:nowrap}
tbody tr{border-bottom:1px solid rgba(30,41,59,0.5);transition:all 0.2s}
tbody tr:hover{background:rgba(99,102,241,0.05)}
tbody td{padding:0.75rem 1rem;color:var(--light);font-size:0.85rem;vertical-align:middle}
.badge-active{display:inline-flex;align-items:center;gap:0.3rem;padding:0.2rem 0.6rem;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);color:#6ee7b7;border-radius:1rem;font-size:0.72rem;font-weight:600}
.badge-inactive{display:inline-flex;align-items:center;gap:0.3rem;padding:0.2rem 0.6rem;background:rgba(239,68,68,0.12);border:1px solid rgba(239,68,68,0.25);color:#fca5a5;border-radius:1rem;font-size:0.72rem;font-weight:600}
.link-btn{display:inline-block;padding:0.3rem 0.55rem;margin:0.1rem;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.25);color:#a5b4fc;text-decoration:none;border-radius:0.4rem;font-size:0.72rem;transition:all 0.3s;font-weight:500;white-space:nowrap}
.link-btn:hover{background:rgba(99,102,241,0.25);transform:translateY(-1px);color:white}
.link-btn.github{background:rgba(36,41,46,0.3);border-color:rgba(255,255,255,0.15);color:#e6edf3}
.link-btn.gitlab{background:rgba(226,67,41,0.12);border-color:rgba(226,67,41,0.25);color:#fc6d26}
.link-btn.bitbucket{background:rgba(0,82,204,0.12);border-color:rgba(0,82,204,0.25);color:#4c9aff}
.link-btn.fofa{background:rgba(245,158,11,0.12);border-color:rgba(245,158,11,0.25);color:#fcd34d}
.link-btn.censys{background:rgba(59,130,246,0.12);border-color:rgba(59,130,246,0.25);color:#93c5fd}
.link-btn.shodan{background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,0.25);color:#fca5a5}
.filter-bar{display:flex;gap:0.75rem;margin-bottom:1.25rem;flex-wrap:wrap;align-items:center}
.filter-bar input,.filter-bar select{padding:0.7rem 1rem;background:rgba(2,6,23,0.8);border:1px solid var(--glass-border);border-radius:0.5rem;color:var(--light);font-size:0.88rem;transition:all 0.3s;flex:1;min-width:200px;font-family:'Inter',system-ui,sans-serif}
.filter-bar input:focus,.filter-bar select:focus{outline:none;border-color:var(--primary-light);box-shadow:0 0 0 3px rgba(99,102,241,0.15)}
.filter-bar input::placeholder{color:#475569}
.filter-bar select option{background:#0f172a}
code{background:rgba(0,0,0,0.4);padding:0.15rem 0.45rem;border-radius:0.3rem;font-family:'JetBrains Mono','Courier New',monospace;font-size:0.78rem;color:#67e8f9;border:1px solid rgba(103,232,249,0.1)}
.export-btn{padding:0.6rem 1rem;background:rgba(16,185,129,0.15);border:1px solid rgba(16,185,129,0.3);border-radius:0.5rem;color:#6ee7b7;cursor:pointer;font-size:0.82rem;transition:all 0.3s;font-family:'Inter',system-ui,sans-serif;font-weight:500;white-space:nowrap}
.export-btn:hover{background:rgba(16,185,129,0.25);transform:translateY(-1px)}
.llm-badge{display:inline-block;padding:0.2rem 0.6rem;background:linear-gradient(135deg,#f59e0b,#d97706);color:white!important;border-radius:1rem;font-size:0.7rem;font-weight:600;margin-left:0.5rem;-webkit-text-fill-color:white!important}
.ports-cell{font-size:0.72rem;color:#94a3b8;max-width:250px;line-height:1.5}
.actions-cell{white-space:nowrap;position:relative}
.action-groups{display:flex;gap:0.3rem;flex-wrap:nowrap}
.dropdown{position:relative;display:inline-block}
.dropdown-toggle{padding:0.35rem 0.6rem;border-radius:0.4rem;font-size:0.72rem;font-weight:600;cursor:pointer;border:1px solid;transition:all 0.3s;font-family:'Inter',system-ui,sans-serif;white-space:nowrap}
.dropdown-toggle:hover{transform:translateY(-1px)}
.ip-toggle{background:rgba(239,68,68,0.12);border-color:rgba(239,68,68,0.3);color:#fca5a5}
.ip-toggle:hover{background:rgba(239,68,68,0.25)}
.domain-toggle{background:rgba(59,130,246,0.12);border-color:rgba(59,130,246,0.3);color:#93c5fd}
.domain-toggle:hover{background:rgba(59,130,246,0.25)}
.git-toggle{background:rgba(16,185,129,0.12);border-color:rgba(16,185,129,0.3);color:#6ee7b7}
.git-toggle:hover{background:rgba(16,185,129,0.25)}
.fuzz-toggle{background:rgba(251,146,60,0.12);border-color:rgba(251,146,60,0.3);color:#fdba74}
.fuzz-toggle:hover{background:rgba(251,146,60,0.25)}
.dropdown-menu{display:none;position:absolute;top:100%;right:0;min-width:220px;background:rgba(15,23,42,0.95);backdrop-filter:blur(20px) saturate(180%);border:1px solid rgba(99,102,241,0.2);border-radius:0.6rem;padding:0.4rem 0;z-index:100;box-shadow:0 8px 32px rgba(0,0,0,0.5);margin-top:0.3rem;max-height:350px;overflow-y:auto}
.dropdown.open .dropdown-menu{display:block;animation:fadeInUp 0.2s ease}
.dropdown-menu a{display:block;padding:0.4rem 0.8rem;color:#e2e8f0;text-decoration:none;font-size:0.75rem;transition:all 0.2s;border-left:2px solid transparent}
.dropdown-menu a:hover{background:rgba(99,102,241,0.12);color:white;border-left-color:var(--primary-light)}
.dropdown-label{padding:0.3rem 0.8rem;color:#64748b;font-size:0.65rem;text-transform:uppercase;letter-spacing:1px;font-weight:600;border-top:1px solid rgba(30,41,59,0.8);margin-top:0.2rem}
.dropdown-label:first-child{border-top:none;margin-top:0}
.dropdown-menu-wide{min-width:320px}
.cmd-copy{padding:0.4rem 0.8rem;color:#94a3b8;font-size:0.72rem;font-family:'JetBrains Mono',monospace;cursor:pointer;transition:all 0.2s;border-left:2px solid transparent;position:relative}
.cmd-copy:hover{background:rgba(251,146,60,0.12);color:#fdba74;border-left-color:#fb923c}
.cmd-copy.copied{background:rgba(16,185,129,0.15);color:#6ee7b7;border-left-color:#10b981}
.cmd-copy.copied::after{content:'✅ Copied!';position:absolute;left:50%;bottom:calc(100% + 4px);transform:translateX(-50%);font-size:0.65rem;color:#6ee7b7;background:#1e293b;padding:2px 8px;border-radius:4px;border:1px solid rgba(110,231,183,0.3);white-space:nowrap;z-index:10}
.ip-cell code{display:block;margin:1px 0}
@keyframes fadeInUp{from{opacity:0;transform:translateY(20px)}to{opacity:1;transform:translateY(0)}}
.card,.stat-card-link,.table-container{animation:fadeInUp 0.5s ease forwards}
@media(max-width:768px){nav .container{flex-direction:column;gap:0.75rem}.stats-grid{grid-template-columns:1fr 1fr}.container{padding:1rem}table{font-size:0.75rem}}
EOFCSS
}

generate_js() {
    cat > "${ASSETS_DIR}/script.js" << 'EOFJS'
function initFilters(){
    const s=document.getElementById('searchInput'),
          f=document.getElementById('filterStatus'),
          t=document.querySelector('table tbody');
    if(!t)return;
    const rows=Array.from(t.rows);
    function doFilter(){
        const st=s?s.value.toLowerCase():'';
        const fv=f?f.value:'';
        let vis=0;
        rows.forEach(r=>{
            const txt=r.textContent.toLowerCase();
            const isActive=r.querySelector('.badge-active')!==null;
            const statusMatch=!fv||(fv==='active'&&isActive)||(fv==='inactive'&&!isActive);
            const show=txt.includes(st)&&statusMatch;
            r.style.display=show?'':'none';
            if(show)vis++;
        });
        const c=document.getElementById('visibleCount');
        if(c)c.textContent=vis;
    }
    if(s)s.addEventListener('input',doFilter);
    if(f)f.addEventListener('change',doFilter);
}
function exportCSV(){
    const t=document.querySelector('table');if(!t)return;
    let csv=[];
    t.querySelectorAll('tr').forEach(r=>{
        if(r.style.display==='none')return;
        const cols=r.querySelectorAll('td,th');
        csv.push(Array.from(cols).map(c=>'"'+c.textContent.replace(/"/g,'""').trim()+'"').join(','));
    });
    const b=new Blob([csv.join('\n')],{type:'text/csv'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='bird-llm-export.csv';a.click();
}
function exportJSON(){
    const t=document.querySelector('table');if(!t)return;
    const h=Array.from(t.querySelectorAll('thead th')).map(h=>h.textContent.trim());
    const d=[];
    t.querySelectorAll('tbody tr').forEach(r=>{
        if(r.style.display==='none')return;
        const o={};r.querySelectorAll('td').forEach((td,i)=>{if(h[i])o[h[i]]=td.textContent.trim()});d.push(o);
    });
    const b=new Blob([JSON.stringify(d,null,2)],{type:'application/json'});
    const a=document.createElement('a');a.href=URL.createObjectURL(b);a.download='bird-llm-export.json';a.click();
}
document.addEventListener('DOMContentLoaded',function(){
    initFilters();
    // Dropdown toggle
    document.addEventListener('click',function(e){
        const toggle=e.target.closest('.dropdown-toggle');
        if(toggle){
            e.stopPropagation();
            const dd=toggle.parentElement;
            const wasOpen=dd.classList.contains('open');
            document.querySelectorAll('.dropdown.open').forEach(d=>d.classList.remove('open'));
            if(!wasOpen) dd.classList.add('open');
            return;
        }
        if(!e.target.closest('.dropdown-menu')){
            document.querySelectorAll('.dropdown.open').forEach(d=>d.classList.remove('open'));
        }
    });
    // Counter animation
    document.querySelectorAll('.stat-number[data-count]').forEach(el=>{
        const target=parseInt(el.dataset.count);if(isNaN(target)||target===0)return;
        let cur=0;const step=Math.max(1,Math.ceil(target/30));
        const timer=setInterval(()=>{cur+=step;if(cur>=target){cur=target;clearInterval(timer)}el.textContent=cur.toLocaleString()},30);
    });
});
EOFJS
}

# ============================================
# NAV
# ============================================

generate_nav() {
    local current="${1:-index}"
    cat <<EOFNAV
    <nav>
        <div class="container">
            <h1>🦅 Bird Tool Web Analyzer <span class="llm-badge">📊 Auto</span></h1>
            <div class="nav-links">
                <a href="index.html" $([ "$current" = "index" ] && echo 'class="active"')>Dashboard</a>
                <a href="subdomains.html" $([ "$current" = "subdomains" ] && echo 'class="active"')>Subdomínios</a>
                <a href="brid-craftjs.html" $([ "$current" = "brid" ] && echo 'class="active"')>BRID-CRAFTJS</a>
                <a href="urls.html" $([ "$current" = "urls" ] && echo 'class="active"')>URLs</a>
                <a href="tree.html" $([ "$current" = "tree" ] && echo 'class="active"')>Tree</a>
                <a href="dns.html" $([ "$current" = "dns" ] && echo 'class="active"')>DNS</a>
            </div>
        </div>
    </nav>
EOFNAV
}

# ============================================
# PAGE: INDEX
# ============================================

generate_index() {
    local analysis="$1"
    local active=$(grep -c '|active|' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null | tr -d '[:space:]' || echo 0)
    local inactive=$(grep -c '|inactive|' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null | tr -d '[:space:]' || echo 0)
    local total_subs=$(( ${active:-0} + ${inactive:-0} ))
#   local total_subs=$((active + inactive))
    local total_urls=$(wc -l < "$URLS_FILE" | tr -d ' ')
    local total_brid=$(wc -l < "$CRAFTJS_FILE" 2>/dev/null | tr -d ' ')
    local unique_ips=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | cut -d'|' -f3 | tr ',' '\n' | sort -u | grep -v '^$' | wc -l | tr -d ' ')

    local exec_summary risk_level findings_html recs_html attack_surface vulns_html sensitive_html
    exec_summary=$(echo "$analysis" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('executive_summary','Análise realizada.'))" 2>/dev/null)
    risk_level=$(echo "$analysis" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('risk_level','MEDIO'))" 2>/dev/null)
    attack_surface=$(echo "$analysis" | python3 -c "import sys,json;d=json.load(sys.stdin);print(d.get('attack_surface',''))" 2>/dev/null)
    findings_html=$(echo "$analysis" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for f in d.get('key_findings',[]): print(f'<li>{f}</li>')
" 2>/dev/null)
    vulns_html=$(echo "$analysis" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for v in d.get('vulnerabilities',[]): print(f'<li style=\"color:#fca5a5\">{v}</li>')
" 2>/dev/null)
    sensitive_html=$(echo "$analysis" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for s in d.get('sensitive_data',[]): print(f'<li style=\"color:#fcd34d\">{s}</li>')
" 2>/dev/null)
    recs_html=$(echo "$analysis" | python3 -c "
import sys,json
d=json.load(sys.stdin)
for r in d.get('recommendations',[]): print(f'<li>{r}</li>')
" 2>/dev/null)

    local risk_color="#fcd34d"
    [[ "$risk_level" == "CRITICO" ]] && risk_color="#ef4444"
    [[ "$risk_level" == "ALTO" ]] && risk_color="#fca5a5"
    [[ "$risk_level" == "BAIXO" ]] && risk_color="#6ee7b7"

    cat > "${DASHBOARD_DIR}/index.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Bird Tool Web - Dashboard</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "index")
<div class="container">
    <div class="card hero-card">
        <h2>📊 Dashboard de Segurança <span class="llm-badge">📊 Análise Automática</span></h2>
        <p>Reconhecimento completo com análise automática baseada em regras</p>
        <p><small style="color:#64748b">Gerado: $(date '+%Y-%m-%d %H:%M')$([ -n "$SHODAN_API_KEY" ] && echo " • Shodan: ✅")</small></p>
    </div>
    <div class="stats-grid">
        <a href="subdomains.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon">🟢</div><div class="stat-number" data-count="$active">$active</div><div class="stat-label">Subs Ativos</div></div></a>
        <a href="subdomains.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon">🔴</div><div class="stat-number" data-count="$inactive">$inactive</div><div class="stat-label">Subs Inativos</div></div></a>
        <a href="subdomains.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon">🔢</div><div class="stat-number" data-count="$unique_ips">$unique_ips</div><div class="stat-label">IPs Únicos</div></div></a>
        <a href="urls.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon">🔗</div><div class="stat-number" data-count="$total_urls">$total_urls</div><div class="stat-label">URLs</div></div></a>
        <a href="brid-craftjs.html" class="stat-card-link"><div class="stat-card"><div class="stat-icon">🔑</div><div class="stat-number" data-count="$total_brid">$total_brid</div><div class="stat-label">Dados Sensíveis</div></div></a>
    </div>
    <div class="card" style="border-left:3px solid ${risk_color};">
        <h3>📊 Análise de Risco — Nível: <strong style="color:${risk_color}">${risk_level}</strong></h3>
        <p style="margin:1rem 0;line-height:1.8;">$exec_summary</p>
        $([ -n "$attack_surface" ] && echo "<div style='margin:1rem 0;padding:0.8rem;background:rgba(99,102,241,0.08);border-radius:0.5rem;border-left:2px solid #6366f1'><h4 style='color:#a5b4fc;margin-bottom:0.3rem'>🎯 Superfície de Ataque</h4><p style='color:#cbd5e1;font-size:0.9rem'>$attack_surface</p></div>")
        <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:1.5rem;margin-top:1rem;">
            <div><h4 style="color:#a5b4fc;margin-bottom:0.5rem">🔍 Principais Achados</h4><ul style="list-style:none;padding:0">$findings_html</ul></div>
            <div><h4 style="color:#fca5a5;margin-bottom:0.5rem">⚠️ Vulnerabilidades</h4><ul style="list-style:none;padding:0">$vulns_html</ul></div>
            <div><h4 style="color:#6ee7b7;margin-bottom:0.5rem">💡 Recomendações</h4><ul style="list-style:none;padding:0">$recs_html</ul></div>
        </div>
        $([ -n "$sensitive_html" ] && echo "<div style='margin-top:1rem;padding:0.8rem;background:rgba(251,191,36,0.06);border-radius:0.5rem;border-left:2px solid #f59e0b'><h4 style='color:#fcd34d;margin-bottom:0.3rem'>🔑 Dados Sensíveis Identificados</h4><ul style='list-style:none;padding:0'>$sensitive_html</ul></div>")
    </div>
$(python3 -c "
import json, os, glob, html as h

shodan_dir = '${SHODAN_CACHE}'
subs_file = '${TEMP_DIR}/validated_subs.txt'

# Collect data
ips_ports = {}
for f in glob.glob(os.path.join(shodan_dir, '*.json')):
    ip = os.path.basename(f).replace('.json','')
    try:
        d = json.load(open(f))
        ips_ports[ip] = d.get('ports', [])
    except: pass

active_subs = []
try:
    for line in open(subs_file):
        parts = line.strip().split('|')
        if len(parts) >= 3 and parts[1] == 'active':
            active_subs.append((parts[0], parts[2]))
except: pass

# Determine what to suggest
has_http = any(p in ports for ports in ips_ports.values() for p in [80,443,8080,8443])
has_ftp = any(21 in ports for ports in ips_ports.values())
has_ssh = any(22 in ports for ports in ips_ports.values())
has_rdp = any(3389 in ports for ports in ips_ports.values())
has_db = any(p in ports for ports in ips_ports.values() for p in [3306,5432,27017,6379,1433])
all_ips = ' '.join(ips_ports.keys())
all_active = ' '.join([s[0] for s in active_subs])

print('<div class=\"card\" style=\"border-left:3px solid #818cf8;margin-top:1.5rem\">')
print('<h3>🚀 Próximos Passos — Exploração da Superfície de Ataque</h3>')
print('<p style=\"color:#94a3b8;font-size:0.85rem;margin-bottom:1rem\">Comandos prontos baseados nos dados descobertos. Clique para copiar.</p>')

# 1. Nmap deep scan
cmds = []
if all_ips:
    cmds.append(('🔍 Nmap Deep Scan (all IPs)', f'nmap -sV -sC -A -T4 -p- {all_ips} -oN nmap-deep-scan.txt'))
    cmds.append(('🔍 Nmap Vuln Scripts', f'nmap --script vuln -p- {all_ips} -oN nmap-vuln-scan.txt'))
if all_active:
    cmds.append(('🌐 Nuclei Scan (all subs)', f'for sub in {all_active}; do nuclei -u https://\$sub -severity critical,high,medium -o nuclei-\$sub.txt; done'))
    cmds.append(('🔒 SSL Check (all subs)', f'for sub in {all_active}; do echo \"[*] \$sub\"; echo | openssl s_client -connect \$sub:443 -servername \$sub 2>/dev/null | openssl x509 -noout -dates -subject -issuer; echo; done | tee ssl-check-all.txt'))
    cmds.append(('📋 HTTP Headers (all subs)', f'for sub in {all_active}; do echo \"=== \$sub ===\"; curl -sI https://\$sub/ -m 10; echo; done | tee http-headers-all.txt'))
    cmds.append(('🕷 Crawl (all subs)', f'for sub in {all_active}; do echo \"[*] Crawling \$sub\"; katana -u https://\$sub -d 3 -jc -kf all -o crawl-\$sub.txt; done'))
if has_ftp:
    ftp_ips = ' '.join([ip for ip, ports in ips_ports.items() if 21 in ports])
    cmds.append(('📂 FTP Anonymous Check', f'for ip in {ftp_ips}; do echo \"[*] FTP \$ip\"; curl -s ftp://\$ip/ --user anonymous:anonymous -m 10; echo; done | tee ftp-anon-check.txt'))
if has_ssh:
    ssh_ips = ' '.join([ip for ip, ports in ips_ports.items() if 22 in ports])
    cmds.append(('🔐 SSH Banner Grab', f'for ip in {ssh_ips}; do echo \"[*] SSH \$ip\"; timeout 5 ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 \$ip 2>&1 | head -5; echo; done | tee ssh-banners.txt'))
if has_db:
    db_info = []
    for ip, ports in ips_ports.items():
        for p in [3306,5432,27017,6379,1433]:
            if p in ports: db_info.append((ip,p))
    db_cmds = '; '.join([f'nmap -sV -p {p} --script=\\\"*{\"mysql\" if p==3306 else \"pgsql\" if p==5432 else \"mongodb\" if p==27017 else \"redis\" if p==6379 else \"ms-sql\"}*\\\" {ip}' for ip,p in db_info[:3]])
    cmds.append(('🗄 DB Service Scan', db_cmds + ' | tee db-service-scan.txt'))
if has_rdp:
    rdp_ips = ' '.join([ip for ip, ports in ips_ports.items() if 3389 in ports])
    cmds.append(('💻 RDP Check', f'nmap -p 3389 --script rdp-ntlm-info,rdp-enum-encryption {rdp_ips} -oN rdp-check.txt'))

# Advanced Techinics (Feature 1)
cmds.append(('🔥 Nuclei Advanced (Fuzzing)', f'for sub in {all_active}; do nuclei -u https://\$sub -t fuzzing,exposures,cves -severity critical,high -o nuclei-adv-\$sub.txt; done'))
cmds.append(('🔥 Feroxbuster Recursive', f'for sub in {all_active}; do feroxbuster -u https://\$sub -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -t 50 -r -o ferox-recursive-\$sub.txt; done'))
cmds.append(('🔥 Cloud Recon (S3/Azure)', f'python3 -c \"import os; [os.system(\'cloud_enum -d \' + s) for s in \'{all_active}\'.split()]\"'))
cmds.append(('🔥 MassDNS Brute-force', f'massdns -r /usr/share/massdns/lists/resolvers.txt -t A -o S ${SCOPE_DOMAINS_FILE} -w massdns-results.txt'))

print('<div style=\"display:flex;flex-direction:column;gap:0.4rem\">')
for label, cmd in cmds:
    esc = h.escape(cmd, quote=True)
    print(f'<div class=\"cmd-copy\" style=\"padding:0.5rem 0.8rem;font-size:0.75rem;position:relative\" onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add(\\x27copied\\x27);setTimeout(()=>this.classList.remove(\\x27copied\\x27),1500)\" data-cmd=\"{esc}\"><strong>{label}</strong><br><code style=\"color:#94a3b8;font-size:0.7rem\">{h.escape(cmd[:120])}{\"...\" if len(cmd)>120 else \"\"}</code></div>')
print('</div></div>')
" 2>/dev/null)
</div>
<script src="assets/script.js"></script></body></html>
EOFHTML
}

# ============================================
# PAGE: UNIFIED SUBDOMAINS
# ============================================

generate_subdomains_page() {
    local active=$(grep -c '|active|' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null | tr -d '[:space:]' || echo 0)
    local inactive=$(grep -c '|inactive|' "${TEMP_DIR}/validated_subs.txt" 2>/dev/null | tr -d '[:space:]' || echo 0)
    local total=$(( ${active:-0} + ${inactive:-0} ))

    cat > "${DASHBOARD_DIR}/subdomains.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Subdomínios - Dashboard</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "subdomains")
<div class="container">
    <div class="card">
        <h2>🌐 Subdomínios <span class="llm-badge">📊 Auto</span></h2>
        <p>Total: <strong id="visibleCount">$total</strong> subdomínios • <span style="color:#6ee7b7">$active ativos</span> • <span style="color:#fca5a5">$inactive inativos</span>$([ -n "$SHODAN_API_KEY" ] && echo " • 🔒 Shodan API ativa")</p>
    </div>
    <div class="filter-bar">
        <input type="text" id="searchInput" placeholder="🔍 Buscar subdomínio, IP, porta...">
        <select id="filterStatus">
            <option value="">Todos</option>
            <option value="active">🟢 Ativos</option>
            <option value="inactive">🔴 Inativos</option>
        </select>
        <button class="export-btn" onclick="exportCSV()">📄 CSV</button>
        <button class="export-btn" onclick="exportJSON()">📋 JSON</button>
    </div>
    <div class="table-container">
        <table>
            <thead><tr>
                <th>#</th>
                <th>Status</th>
                <th>Domínio / Subdomínio</th>
                <th>IPs Relacionados</th>
                <th>Portas + Serviços</th>
                <th>Ações</th>
            </tr></thead>
            <tbody>
EOFHTML

    local idx=1
    # Sort: active first, then alphabetical
    sort -t'|' -k2,2 -k1,1 "${TEMP_DIR}/validated_subs.txt" | while IFS='|' read -r sub status ips; do
        [[ -z "$sub" ]] && continue

        # Status badge
        local badge
        if [[ "$status" == "active" ]]; then
            badge='<span class="badge-active">🟢 Ativo</span>'
        else
            badge='<span class="badge-inactive">🔴 Inativo</span>'
        fi

        # IPs column
        local ip_html="<span style='color:#475569'>—</span>"
        if [[ -n "$ips" ]]; then
            ip_html=""
            IFS=',' read -ra ip_arr <<< "$ips"
            for ip in "${ip_arr[@]}"; do
                [[ -z "$ip" ]] && continue
                ip_html+="<code>$ip</code> "
            done
        fi

        # Ports/Services (from Shodan InternetDB — query ALL IPs, merge results)
        local ports_html="<span style='color:#475569'>—</span>"
        if [[ -n "$ips" ]]; then
            local all_ports_data=""
            IFS=',' read -ra check_ips <<< "$ips"
            for check_ip in "${check_ips[@]}"; do
                [[ -z "$check_ip" ]] && continue
                local pd=$(get_ports_services "$check_ip")
                if [[ -n "$pd" ]]; then
                    if [[ -n "$all_ports_data" ]]; then
                        all_ports_data+="<br><small style='color:#475569'>[$check_ip]</small> $pd"
                    else
                        all_ports_data="$pd"
                    fi
                fi
            done
            if [[ -n "$all_ports_data" ]]; then
                ports_html="<span class='ports-cell'>$all_ports_data</span>"
            fi
        fi

        # Encode for URLs
        local sub_enc=$(python3 -c "import urllib.parse;print(urllib.parse.quote('$sub'))" 2>/dev/null || echo "$sub")

        # Build grouped dropdown menus
        local actions="<div class='action-groups'>"

        # === IP GROUP ===
        if [[ -n "$ips" ]]; then
            local first_ip=$(echo "$ips" | cut -d',' -f1)
            local ib64=$(echo -n "ip=\"$first_ip\"" | base64 -w0 2>/dev/null)
            actions+="<div class='dropdown'>"
            actions+="<button class='dropdown-toggle ip-toggle'>⚙️ IP</button>"
            actions+="<div class='dropdown-menu'>"
            actions+="<div class='dropdown-label'>Busca por IP</div>"
            actions+="<a href=\"https://www.shodan.io/host/$first_ip\" target=\"_blank\">🔴 Shodan</a>"
            actions+="<a href=\"https://search.censys.io/hosts/$first_ip\" target=\"_blank\">🔵 Censys</a>"
            actions+="<a href=\"https://en.fofa.info/result?qbase64=$ib64\" target=\"_blank\">🟡 FOFA</a>"
            actions+="<div class='dropdown-label'>Dorks IP</div>"
            actions+="<a href=\"https://www.shodan.io/search?query=net:$first_ip/24\" target=\"_blank\">Shodan: net:$first_ip/24</a>"
            actions+="<a href=\"https://www.shodan.io/search?query=ip:$first_ip+port:22,80,443,3389\" target=\"_blank\">Shodan: common ports</a>"
            actions+="<a href=\"https://www.shodan.io/search?query=ip:$first_ip+vuln:CVE\" target=\"_blank\">Shodan: CVEs</a>"
            actions+="<a href=\"https://www.google.com/search?q=%22$first_ip%22\" target=\"_blank\">Google: \"$first_ip\"</a>"
            actions+="<a href=\"https://search.censys.io/search?resource=hosts&q=ip:$first_ip+and+services.port:%2A\" target=\"_blank\">Censys: all services</a>"
            actions+="<div class='dropdown-label'>Comandos IP</div>"
            actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"nmap -sS -p- --open -Pn $first_ip -oN nmap-ss-allp-$first_ip\">📋 Nmap Full Stealth</div>"
            actions+="</div></div>"
        fi

        # === DOMAIN GROUP ===
        local db64=$(echo -n "domain=\"$sub\"" | base64 -w0 2>/dev/null)
        actions+="<div class='dropdown'>"
        actions+="<button class='dropdown-toggle domain-toggle'>🌐 Dom</button>"
        actions+="<div class='dropdown-menu'>"
        actions+="<div class='dropdown-label'>Busca por Domínio</div>"
        actions+="<a href=\"https://www.shodan.io/search?query=hostname:$sub_enc\" target=\"_blank\">🔴 Shodan</a>"
        actions+="<a href=\"https://search.censys.io/search?resource=hosts&sort=RELEVANCE&per_page=25&virtual_hosts=EXCLUDE&q=$sub_enc\" target=\"_blank\">🔵 Censys</a>"
        actions+="<a href=\"https://en.fofa.info/result?qbase64=$db64\" target=\"_blank\">🟡 FOFA</a>"
        actions+="<div class='dropdown-label'>Dorks Domínio</div>"
        actions+="<a href=\"https://www.shodan.io/search?query=ssl.cert.subject.CN:\&quot;$sub_enc\&quot;\" target=\"_blank\">Shodan: SSL cert CN</a>"
        actions+="<a href=\"https://www.shodan.io/search?query=http.title:\&quot;$sub_enc\&quot;\" target=\"_blank\">Shodan: HTTP title</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc\" target=\"_blank\">Google: site:$sub</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc+filetype:pdf+OR+filetype:xls+OR+filetype:doc\" target=\"_blank\">Google: docs</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc+inurl:login+OR+inurl:admin+OR+inurl:painel\" target=\"_blank\">Google: login pages</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:$sub_enc+inurl:api+OR+inurl:swagger+OR+inurl:graphql\" target=\"_blank\">Google: APIs</a>"
        actions+="<a href=\"https://www.google.com/search?q=%22$sub_enc%22+password+OR+senha+OR+secret+OR+token\" target=\"_blank\">Google: leaked creds</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:pastebin.com+OR+site:ghostbin.co+%22$sub_enc%22\" target=\"_blank\">Google: pastes</a>"
        actions+="</div></div>"

        # === GIT GROUP ===
        actions+="<div class='dropdown'>"
        actions+="<button class='dropdown-toggle git-toggle'>💻 GIT</button>"
        actions+="<div class='dropdown-menu'>"
        actions+="<div class='dropdown-label'>Code Search</div>"
        actions+="<a href=\"https://github.com/search?q=${sub_enc}&type=code\" target=\"_blank\">GitHub Code</a>"
        actions+="<a href=\"https://gitlab.com/search?search=${sub_enc}&nav_source=navbar\" target=\"_blank\">GitLab</a>"
        actions+="<a href=\"https://www.google.com/search?q=site:bitbucket.org+%22${sub_enc}%22\" target=\"_blank\">Bitbucket</a>"
        actions+="<div class='dropdown-label'>Git Dorks</div>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+password+OR+secret+OR+token&type=code\" target=\"_blank\">GitHub: secrets</a>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+filename:.env+OR+filename:.yml+OR+filename:.conf&type=code\" target=\"_blank\">GitHub: configs</a>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+filename:id_rsa+OR+filename:id_dsa+OR+filename:.pem&type=code\" target=\"_blank\">GitHub: keys</a>"
        actions+="<a href=\"https://github.com/search?q=%22${sub_enc}%22+AKIA+OR+aws_secret+OR+api_key&type=code\" target=\"_blank\">GitHub: API keys</a>"
        actions+="</div></div>"

        # === FUZZ GROUP ===
        actions+="<div class='dropdown'>"
        actions+="<button class='dropdown-toggle fuzz-toggle'>🔍 Fuzz</button>"
        actions+="<div class='dropdown-menu dropdown-menu-wide'>"
        actions+="<div class='dropdown-label'>Fuzzing Commands</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"gobuster dir -u https://$sub/ -w /usr/share/dirb/wordlists/big.txt -k -t 100 -e --no-error -r -o fuzz-gobuster-$sub -a Mozilla/5.0 --exclude-length 123456 -x php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log\">gobuster</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"feroxbuster --url https://$sub/ --methods GET,POST -r -A -w /usr/share/dirb/wordlists/big.txt -o fuzz-feroxbuster-$sub -x php bkp old txt xml cgi pdf html htm asp aspx pl sql js png jpg jpeg config sh cfm zip log\">feroxbuster</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"dirsearch -u https://$sub/ --crawl --full-url -t 1 --user-agent Mozilla/5.0 -e php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log -o fuzz-dirsearch-$sub\">dirsearch</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"ffuf -u https://$sub/FUZZ -w /usr/share/dirb/wordlists/big.txt -c -t 100 -e .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.zip,.log -o fuzz-ffuf-$sub.html -of html\">ffuf</div>"
        actions+="<div class='cmd-copy' onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\" data-cmd=\"dirb https://$sub/ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -a KidMan -X .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.sh,.cfm,.zip,.log -o fuzz-dirb-$sub\">dirb</div>"
        actions+="</div></div>"

        # === EXPLORE GROUP (port-based commands/links) ===
        if [[ -n "$ips" ]]; then
            local first_ip=$(echo "$ips" | cut -d',' -f1)
            local explore_items=""
            explore_items=$(python3 -c "
import json,os,html as h
ip = '$first_ip'
sub = '$sub'
cache = os.path.join('${SHODAN_CACHE}', ip + '.json')
port_map = {
    21:  ('FTP',  'ftp://SUB:21', 'curl -s ftp://SUB:21/ --user anonymous:anonymous -m 10'),
    22:  ('SSH',  'ssh://SUB:22', 'ssh -o StrictHostKeyChecking=no SUB -p 22'),
    23:  ('Telnet', 'telnet://SUB:23', 'telnet SUB 23'),
    25:  ('SMTP', None, 'nmap -sV -p 25 --script smtp-commands,smtp-enum-users IP'),
    53:  ('DNS',  None, 'dig @IP SUB ANY'),
    80:  ('HTTP', 'http://SUB:80', 'curl -sI http://SUB:80/ -m 10'),
    110: ('POP3', None, 'nmap -sV -p 110 --script pop3-capabilities IP'),
    143: ('IMAP', None, 'nmap -sV -p 143 --script imap-capabilities IP'),
    443: ('HTTPS','https://SUB:443', 'curl -sI https://SUB:443/ -m 10 -k'),
    445: ('SMB',  None, 'smbclient -L //IP/ -N'),
    993: ('IMAPS',None, 'openssl s_client -connect IP:993'),
    995: ('POP3S',None, 'openssl s_client -connect IP:995'),
    1433:('MSSQL',None, 'nmap -sV -p 1433 --script ms-sql-info IP'),
    3306:('MySQL',None, 'mysql -h IP -u root --connect-timeout=5'),
    3389:('RDP',  None, 'nmap -p 3389 --script rdp-ntlm-info IP'),
    5432:('PgSQL',None, 'psql -h IP -U postgres -l'),
    5900:('VNC',  None, 'nmap -sV -p 5900 --script vnc-info IP'),
    6379:('Redis',None, 'redis-cli -h IP ping'),
    8080:('HTTP', 'http://SUB:8080', 'curl -sI http://SUB:8080/ -m 10'),
    8443:('HTTPS','https://SUB:8443', 'curl -sI https://SUB:8443/ -m 10 -k'),
    9200:('Elastic',None, 'curl -s http://IP:9200/ -m 10'),
    27017:('MongoDB',None,'mongosh --host IP --port 27017'),
}
try:
    with open(cache) as f:
        data = json.load(f)
    ports = data.get('ports', [])
except: ports = []
if not ports:
    print('')
else:
    items = []
    items.append(\"<div class='dropdown-label'>Portas Abertas — Links e Comandos</div>\")
    for p in sorted(ports):
        info = port_map.get(p, (f'Port {p}', None, f'nmap -sV -p {p} IP'))
        svc, url_tpl, cmd_tpl = info
        cmd = cmd_tpl.replace('SUB', sub).replace('IP', ip)
        esc_cmd = h.escape(cmd, quote=True)
        line = f\"<div style='display:flex;align-items:center;gap:0.5rem;padding:0.3rem 0.5rem'>\"
        line += f\"<span style='color:#818cf8;min-width:50px;font-size:0.7rem'>{p}/{svc}</span>\"
        if url_tpl:
            url = url_tpl.replace('SUB', sub)
            line += f\"<a href='{url}' target='_blank' style='color:#60a5fa;font-size:0.72rem'>🔗 Open</a>\"
        line += f\"<div class='cmd-copy' style='flex:1;padding:0.2rem 0.5rem;font-size:0.68rem;position:relative' onclick=\\\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add('copied');setTimeout(()=>this.classList.remove('copied'),1500)\\\" data-cmd=\\\"{esc_cmd}\\\">📋 {h.escape(cmd[:60])}</div>\"
        line += \"</div>\"
        items.append(line)
    print('\\n'.join(items))
" 2>/dev/null)
            if [[ -n "$explore_items" ]]; then
                actions+="<div class='dropdown'>"
                actions+="<button class='dropdown-toggle' style='background:rgba(129,140,248,0.12);border-color:rgba(129,140,248,0.3);color:#a5b4fc'>🔓 Explore</button>"
                actions+="<div class='dropdown-menu dropdown-menu-wide'>"
                actions+="$explore_items"
                actions+="</div></div>"
            fi
        fi

        actions+="</div>"

        echo "<tr><td>$idx</td><td>$badge</td><td><a href=\"https://$sub\" target=\"_blank\" style=\"color:#60a5fa\"><code>$sub</code></a></td><td class=\"ip-cell\">$ip_html</td><td>$ports_html</td><td class=\"actions-cell\">$actions</td></tr>" >> "${DASHBOARD_DIR}/subdomains.html"
        idx=$((idx + 1))
    done

    # Build list of active subdomains for general fuzz commands
    local active_subs_list=$(grep '|active|' "${TEMP_DIR}/validated_subs.txt" | cut -d'|' -f1 | sort -u | tr '\n' ' ')

    # Use Python to generate the fuzz card HTML (avoids all shell escaping issues)
    python3 -c "
import html
subs = '${active_subs_list}'.strip()
tools = [
    ('gobuster', 'gobuster dir -u https://\$sub/ -w /usr/share/dirb/wordlists/big.txt -k -t 100 -e --no-error -r -o fuzz-gobuster-\$sub -a Mozilla/5.0 --exclude-length 123456 -x php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log'),
    ('feroxbuster', 'feroxbuster --url https://\$sub/ --methods GET,POST -r -A -w /usr/share/dirb/wordlists/big.txt -o fuzz-feroxbuster-\$sub -x php bkp old txt xml cgi pdf html htm asp aspx pl sql js png jpg jpeg config sh cfm zip log'),
    ('dirsearch', 'dirsearch -u https://\$sub/ --crawl --full-url -t 1 --user-agent Mozilla/5.0 -e php,bkp,old,txt,xml,cgi,pdf,html,htm,asp,aspx,pl,sql,js,png,jpg,jpeg,config,sh,cfm,zip,log -o fuzz-dirsearch-\$sub'),
    ('ffuf', 'ffuf -u https://\$sub/FUZZ -w /usr/share/dirb/wordlists/big.txt -c -t 100 -e .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.zip,.log -o fuzz-ffuf-\$sub.html -of html'),
    ('dirb', 'dirb https://\$sub/ /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt -a KidMan -X .php,.bkp,.old,.txt,.xml,.cgi,.pdf,.html,.htm,.asp,.aspx,.pl,.sql,.js,.png,.jpg,.jpeg,.config,.sh,.cfm,.zip,.log -o fuzz-dirb-\$sub'),
]
print('</tbody></table></div>')
print('<div class=\"card\" style=\"border-left:3px solid #fb923c;margin-top:1.5rem\">')
print('<h3>🔥 Fuzz Geral — Executar em TODOS os subdomínios ativos</h3>')
print('<p style=\"color:#94a3b8;font-size:0.85rem;margin-bottom:1rem\">Clique para copiar o comando completo (saída salva em arquivo)</p>')
print('<div style=\"display:flex;flex-wrap:wrap;gap:0.5rem\">')
for name, tool_cmd in tools:
    cmd = f'for sub in {subs}; do echo \"[*] Fuzzing \$sub with {name}...\"; {tool_cmd}; done | tee -a fuzzing-{name}-all-subs.txt'
    escaped = html.escape(cmd, quote=True)
    print(f'<div class=\"cmd-copy fuzz-all-btn\" style=\"display:inline-block;padding:0.5rem 1rem;background:rgba(251,146,60,0.12);border:1px solid rgba(251,146,60,0.3);border-radius:0.5rem;cursor:pointer;font-size:0.8rem;color:#fdba74;position:relative\" onclick=\"navigator.clipboard.writeText(this.dataset.cmd);this.classList.add(&#39;copied&#39;);setTimeout(()=>this.classList.remove(&#39;copied&#39;),1500)\" data-cmd=\"{escaped}\">📋 {name} ALL</div>')
print('</div></div>')
" >> "${DASHBOARD_DIR}/subdomains.html"

    echo "</div><script src=\"assets/script.js\"></script></body></html>" >> "${DASHBOARD_DIR}/subdomains.html"
}

# ============================================
# PAGE: BRID-CRAFTJS
# ============================================

generate_brid_page() {
    local sorted_file="${TEMP_DIR}/craftjs_sorted.txt"
    if [[ -s "$CRAFTJS_FILE" ]]; then
        sort -u "$CRAFTJS_FILE" > "$sorted_file"
    else
        touch "$sorted_file"
    fi
    local count=$(wc -l < "$sorted_file" | tr -d ' ')

    # Use Python to group by titulo+dado, count occurrences, collect source URLs
    python3 -c "
import json, html as h, sys
from collections import defaultdict

groups = defaultdict(lambda: {'count': 0, 'urls': []})
try:
    for line in open('$sorted_file'):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            titulo = d.get('titulo', '')
            dado = d.get('dado', '')
            url = d.get('url', '')
            key = (titulo, dado)
            groups[key]['count'] += 1
            if url and url not in groups[key]['urls']:
                groups[key]['urls'].append(url)
        except: pass
except: pass

# Sort by titulo then dado
sorted_groups = sorted(groups.items(), key=lambda x: (x[0][0].lower(), x[0][1].lower()))

# Write HTML
print('<!DOCTYPE html><html lang=\"pt-BR\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1.0\">')
print('<title>BRID-CRAFTJS - Dashboard</title><link rel=\"stylesheet\" href=\"assets/style.css\">')
print('<style>')
print('.modal-overlay{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.7);z-index:1000;justify-content:center;align-items:center}')
print('.modal-overlay.active{display:flex}')
print('.modal-box{background:#1e293b;border:1px solid rgba(99,102,241,0.3);border-radius:0.75rem;padding:1.5rem;max-width:700px;width:90%;max-height:70vh;overflow-y:auto}')
print('.modal-box h3{color:#a5b4fc;margin-bottom:1rem}')
print('.modal-box a{display:block;color:#60a5fa;font-size:0.8rem;padding:0.3rem 0;word-break:break-all}')
print('.modal-box a:hover{color:#93c5fd}')
print('.modal-close{float:right;background:none;border:none;color:#94a3b8;font-size:1.2rem;cursor:pointer}')
print('.modal-close:hover{color:#fff}')
print('.count-badge{display:inline-block;min-width:24px;text-align:center;padding:0.15rem 0.4rem;border-radius:0.3rem;font-size:0.75rem;font-weight:bold}')
print('.count-1{background:rgba(99,102,241,0.15);color:#a5b4fc}')
print('.count-multi{background:rgba(251,146,60,0.2);color:#fdba74}')
print('.src-btn{padding:0.2rem 0.6rem;border-radius:0.3rem;border:1px solid rgba(96,165,250,0.3);background:rgba(96,165,250,0.08);color:#60a5fa;font-size:0.72rem;cursor:pointer}')
print('.src-btn:hover{background:rgba(96,165,250,0.2)}')
print('</style>')
print('</head><body>')
" > "${DASHBOARD_DIR}/brid-craftjs.html"

    generate_nav "brid" >> "${DASHBOARD_DIR}/brid-craftjs.html"

    python3 -c "
import json, html as h
from collections import defaultdict

groups = defaultdict(lambda: {'count': 0, 'urls': []})
try:
    for line in open('$sorted_file'):
        line = line.strip()
        if not line: continue
        try:
            d = json.loads(line)
            titulo = d.get('titulo', '')
            dado = d.get('dado', '')
            url = d.get('url', '')
            key = (titulo, dado)
            groups[key]['count'] += 1
            if url and url not in groups[key]['urls']:
                groups[key]['urls'].append(url)
        except: pass
except: pass

sorted_groups = sorted(groups.items(), key=lambda x: (x[0][0].lower(), x[0][1].lower()))
unique_count = len(sorted_groups)
total_count = sum(v['count'] for v in groups.values())

print(f'<div class=\"container\">')
print(f'<div class=\"card\"><h2>🔑 BRID-CRAFTJS <span class=\"llm-badge\">📊 Auto</span></h2>')
print(f'<p>Total: <strong>{total_count}</strong> achados • <strong>{unique_count}</strong> únicos (agrupados por conteúdo)</p></div>')
print('<div class=\"filter-bar\"><input type=\"text\" id=\"searchInput\" placeholder=\"🔍 Buscar...\"><button class=\"export-btn\" onclick=\"exportCSV()\">📄 CSV</button><button class=\"export-btn\" onclick=\"exportJSON()\">📋 JSON</button></div>')
print('<div class=\"table-container\"><table><thead><tr><th>#</th><th>Título</th><th>Dado</th><th>Qtd</th><th>Fontes</th></tr></thead><tbody>')

modals = []
for idx, ((titulo, dado), info) in enumerate(sorted_groups, 1):
    cnt = info['count']
    urls = info['urls']
    t_esc = h.escape(titulo)
    d_esc = h.escape(dado)
    cnt_class = 'count-1' if cnt == 1 else 'count-multi'
    modal_id = f'modal-{idx}'

    print(f'<tr><td>{idx}</td><td><strong>{t_esc}</strong></td><td><code style=\"color:#fca5a5\">{d_esc}</code></td>')
    print(f'<td><span class=\"count-badge {cnt_class}\">{cnt}×</span></td>')
    print(f'<td><button class=\"src-btn\" onclick=\"document.getElementById(\\'{modal_id}\\').classList.add(\\'active\\')\">')
    print(f'🔗 {len(urls)} fonte{\"s\" if len(urls)!=1 else \"\"}</button></td></tr>')

    # Collect modal HTML to render OUTSIDE the table
    urls_html = ''.join([f'<a href=\"{h.escape(u)}\" target=\"_blank\">{h.escape(u)}</a>' for u in urls])
    modals.append(f'<div id=\"{modal_id}\" class=\"modal-overlay\" onclick=\"if(event.target===this)this.classList.remove(\\'active\\')\">'
        f'<div class=\"modal-box\">'
        f'<button class=\"modal-close\" onclick=\"this.closest(\\'.modal-overlay\\').classList.remove(\\'active\\')\">&times;</button>'
        f'<h3>🔗 Fontes: {t_esc}</h3>'
        f'<code style=\"color:#fca5a5;font-size:0.85rem\">{d_esc}</code><hr style=\"border-color:#334155;margin:0.8rem 0\">'
        f'{urls_html}'
        f'</div></div>')

print('</tbody></table></div>')

# Print modals OUTSIDE the table so display:none parent doesn't block them
for m in modals:
    print(m)

print('</div>')

# Modal CSS is in head already, no extra JS needed — modals use onclick inline
print('<script src=\"assets/script.js\"></script></body></html>')
" >> "${DASHBOARD_DIR}/brid-craftjs.html"
}

# ============================================
# PAGE: URLs (deduplicated + sorted)
# ============================================

generate_urls_page() {
    # Deduplicate and sort URLs
    local sorted_urls="${TEMP_DIR}/urls_sorted.txt"
    sort -u "$URLS_FILE" > "$sorted_urls"
    local count=$(wc -l < "$sorted_urls" | tr -d ' ')
    cat > "${DASHBOARD_DIR}/urls.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>URLs - Dashboard</title><link rel="stylesheet" href="assets/style.css"></head><body>
$(generate_nav "urls")
<div class="container">
    <div class="card"><h2>🔗 URLs Coletadas <span class="llm-badge">📊 Auto</span></h2><p>Total: <strong id="visibleCount">$count</strong> URLs únicas em escopo</p></div>
    <div class="filter-bar"><input type="text" id="searchInput" placeholder="🔍 Buscar URLs..."><button class="export-btn" onclick="exportCSV()">📄 CSV</button><button class="export-btn" onclick="exportJSON()">📋 JSON</button></div>
    <div class="table-container"><table><thead><tr><th>#</th><th>URL</th></tr></thead><tbody>
EOFHTML
    local idx=1
    while IFS= read -r url; do
        local safe=$(echo "$url" | sed 's/"/\&quot;/g; s/</\&lt;/g; s/>/\&gt;/g')
        echo "<tr><td>$idx</td><td><a href=\"$url\" target=\"_blank\" style=\"color:#60a5fa;word-break:break-all\">$safe</a></td></tr>" >> "${DASHBOARD_DIR}/urls.html"
        idx=$((idx + 1))
    done < "$sorted_urls"
    echo "</tbody></table></div></div><script src=\"assets/script.js\"></script></body></html>" >> "${DASHBOARD_DIR}/urls.html"
}

# ============================================
# PAGE: Tree (folder structure from URLs)
# ============================================

generate_tree_page() {
    local sorted_urls="${TEMP_DIR}/urls_sorted.txt"
    [[ ! -f "$sorted_urls" ]] && sort -u "$URLS_FILE" > "$sorted_urls"

    # Build tree JSON from URLs using Python
    local tree_json
    tree_json=$(python3 -c "
import json,sys
from urllib.parse import urlparse

tree={}
for line in sys.stdin:
    url=line.strip()
    if not url: continue
    try:
        p=urlparse(url)
        host=p.netloc or p.path.split('/')[0]
        path=p.path.strip('/')
        parts=[host]+[x for x in path.split('/') if x]
        node=tree
        for part in parts:
            if part not in node:
                node[part]={}
            node=node[part]
        if p.query:
            q='?'+p.query
            if q not in node: node[q]={}
    except:
        pass

def sort_tree(t):
    return {k:sort_tree(v) for k,v in sorted(t.items(), key=lambda x:(0 if x[1] else 1, x[0].lower()))}

print(json.dumps(sort_tree(tree)))
" < "$sorted_urls" 2>/dev/null)
    [[ -z "$tree_json" ]] && tree_json='{}'

    local total_dirs=$(echo "$tree_json" | python3 -c "import json,sys;d=json.load(sys.stdin);c=[0];exec('def count(n):\n    for k,v in n.items():\n        if v: c[0]+=1; count(v)');count(d);print(c[0])" 2>/dev/null || echo 0)
    local total_files=$(echo "$tree_json" | python3 -c "import json,sys;d=json.load(sys.stdin);c=[0];exec('def count(n):\n    for k,v in n.items():\n        if not v: c[0]+=1\n        else: count(v)');count(d);print(c[0])" 2>/dev/null || echo 0)

    cat > "${DASHBOARD_DIR}/tree.html" <<EOFHTML
<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Tree - Dashboard</title><link rel="stylesheet" href="assets/style.css">
<style>
.tree-container{font-family:'JetBrains Mono',monospace;font-size:0.82rem;line-height:1.8}
.tree-node{padding-left:1.2rem;border-left:1px solid rgba(99,102,241,0.15)}
.tree-toggle{cursor:pointer;user-select:none;padding:0.15rem 0;display:block;color:#93c5fd;transition:color 0.2s}
.tree-toggle:hover{color:#60a5fa}
.tree-toggle::before{content:'▶ ';font-size:0.65rem;color:#6366f1;display:inline-block;transition:transform 0.2s;margin-right:0.3rem}
.tree-toggle.open::before{transform:rotate(90deg)}
.tree-file{padding:0.15rem 0;padding-left:1.2rem;color:#94a3b8;display:block}
.tree-file::before{content:'📄 ';font-size:0.7rem}
.tree-file.ext-js::before,.tree-file.ext-json::before{content:'🟡 '}
.tree-file.ext-php::before,.tree-file.ext-py::before{content:'🟣 '}
.tree-file.ext-html::before,.tree-file.ext-htm::before{content:'🟠 '}
.tree-file.ext-css::before{content:'🟢 '}
.tree-file.ext-xml::before,.tree-file.ext-config::before{content:'⚙️ '}
.tree-file.ext-pdf::before,.tree-file.ext-doc::before{content:'📝 '}
.tree-file.ext-zip::before,.tree-file.ext-gz::before{content:'📦 '}
.tree-file.ext-png::before,.tree-file.ext-jpg::before,.tree-file.ext-jpeg::before{content:'🖼️ '}
.tree-dir::before{content:'📁 '}
.tree-host{font-size:0.95rem;font-weight:600;color:#a5b4fc;padding:0.5rem 0}
.tree-host::before{content:'🌐 '}
.tree-stats{display:flex;gap:1.5rem;margin-bottom:1rem;color:#64748b;font-size:0.8rem}
.tree-actions{display:flex;gap:0.5rem;margin-bottom:1rem}
.tree-btn{padding:0.4rem 0.8rem;background:rgba(99,102,241,0.12);border:1px solid rgba(99,102,241,0.3);border-radius:0.4rem;color:#a5b4fc;cursor:pointer;font-size:0.75rem;font-family:'Inter',system-ui,sans-serif;transition:all 0.2s}
.tree-btn:hover{background:rgba(99,102,241,0.25)}
.tree-link{color:#6366f1;text-decoration:none;font-size:0.7rem;opacity:0.5;transition:all 0.2s;padding:0.1rem 0.3rem;border-radius:0.2rem}
.tree-link:hover{opacity:1;background:rgba(99,102,241,0.15);color:#818cf8}
a.tree-file{text-decoration:none;cursor:pointer}
a.tree-file:hover{color:#60a5fa;text-decoration:underline}
</style></head><body>
$(generate_nav "tree")
<div class="container">
    <div class="card"><h2>🌳 Estrutura de Diretórios <span class="llm-badge">📊 Auto</span></h2>
    <div class="tree-stats"><span>📁 $total_dirs diretórios</span><span>📄 $total_files arquivos</span></div>
    </div>
    <div class="filter-bar"><input type="text" id="treeSearch" placeholder="🔍 Buscar na árvore..."></div>
    <div class="tree-actions">
        <button class="tree-btn" onclick="expandAll()">📂 Expandir Tudo</button>
        <button class="tree-btn" onclick="collapseAll()">📁 Recolher Tudo</button>
    </div>
    <div class="card"><div class="tree-container" id="treeRoot"></div></div>
</div>
<script>
const TREE_DATA = $tree_json;

function buildTree(data, container, depth, parentPath) {
    const sorted = Object.entries(data).sort((a,b) => {
        const aDir = Object.keys(a[1]).length > 0;
        const bDir = Object.keys(b[1]).length > 0;
        if (aDir !== bDir) return aDir ? -1 : 1;
        return a[0].toLowerCase().localeCompare(b[0].toLowerCase());
    });
    sorted.forEach(([name, children]) => {
        const isDir = Object.keys(children).length > 0;
        const currentPath = parentPath ? parentPath + '/' + name : name;
        if (isDir) {
            const wrapper = document.createElement('div');
            wrapper.style.display = 'flex';
            wrapper.style.alignItems = 'center';
            wrapper.style.gap = '0.3rem';
            const toggle = document.createElement('span');
            toggle.className = depth === 0 ? 'tree-toggle tree-host' : 'tree-toggle tree-dir';
            toggle.textContent = name;
            toggle.onclick = function(e) {
                e.stopPropagation();
                this.parentElement.nextElementSibling.style.display = 
                    this.parentElement.nextElementSibling.style.display === 'none' ? 'block' : 'none';
                this.classList.toggle('open');
            };
            wrapper.appendChild(toggle);
            // Add clickable link icon for directories
            const dirLink = document.createElement('a');
            dirLink.className = 'tree-link';
            dirLink.textContent = '\u2197';
            dirLink.title = 'Abrir: ' + currentPath + '/';
            if (depth === 0) {
                dirLink.href = 'https://' + name + '/';
            } else {
                // Reconstruct URL from path: first segment is host
                const parts = currentPath.split('/');
                dirLink.href = 'https://' + parts.join('/') + '/';
            }
            dirLink.target = '_blank';
            dirLink.onclick = function(e) { e.stopPropagation(); };
            wrapper.appendChild(dirLink);
            container.appendChild(wrapper);
            const node = document.createElement('div');
            node.className = 'tree-node';
            node.style.display = depth < 1 ? 'block' : 'none';
            buildTree(children, node, depth + 1, currentPath);
            container.appendChild(node);
        } else {
            const fileLink = document.createElement('a');
            const ext = name.split('.').pop().toLowerCase();
            fileLink.className = 'tree-file ext-' + ext;
            fileLink.textContent = name;
            // Build full URL
            const parts = currentPath.split('/');
            fileLink.href = 'https://' + parts.join('/');
            fileLink.target = '_blank';
            fileLink.title = 'Abrir: https://' + parts.join('/');
            container.appendChild(fileLink);
        }
    });
}

function expandAll() {
    document.querySelectorAll('.tree-node').forEach(n => n.style.display = 'block');
    document.querySelectorAll('.tree-toggle').forEach(t => t.classList.add('open'));
}
function collapseAll() {
    document.querySelectorAll('.tree-node').forEach((n,i) => { if(i>0) n.style.display='none'; });
    document.querySelectorAll('.tree-toggle').forEach((t,i) => { if(i>0) t.classList.remove('open'); });
}

document.getElementById('treeSearch').addEventListener('input', function() {
    const q = this.value.toLowerCase();
    if (!q) { collapseAll(); document.querySelectorAll('.tree-node')[0].style.display='block'; return; }
    document.querySelectorAll('.tree-toggle,.tree-file').forEach(el => {
        const match = el.textContent.toLowerCase().includes(q);
        const parent = el.closest('div[style]') || el;
        parent.style.display = match ? '' : 'none';
        if (match) {
            let p = el.parentElement;
            while (p && p.id !== 'treeRoot') {
                if (p.classList.contains('tree-node')) p.style.display = 'block';
                const prev = p.previousElementSibling;
                if (prev) {
                    const tog = prev.querySelector ? prev.querySelector('.tree-toggle') : null;
                    if (tog) { tog.classList.add('open'); tog.parentElement.style.display = ''; }
                    else if (prev.classList && prev.classList.contains('tree-toggle')) {
                        prev.classList.add('open'); prev.style.display = '';
                    }
                }
                p = p.parentElement;
            }
        }
    });
});

buildTree(TREE_DATA, document.getElementById('treeRoot'), 0, '');
// Auto-expand first level
document.querySelectorAll('#treeRoot > div > .tree-toggle').forEach(t => t.classList.add('open'));
</script></body></html>
EOFHTML
}

# ============================================
# MAIN
# ============================================

main() {
    echo "================================================"
    echo "  Bird Tool Web - Dashboard Generator v3"
    echo "  Análise: Baseada em regras (sem LLM)"
    echo "  Shodan: $([ -n "$SHODAN_API_KEY" ] && echo "✅ InternetDB + API paga" || echo "✅ InternetDB (use SHODAN_API_KEY para fallback)")"
    echo "================================================"
    echo ""

    mkdir -p "$DASHBOARD_DIR" "$ASSETS_DIR"

    if [[ ! -d "$OUT_DIR" ]]; then
        log_error "Diretório OUT-WEB-BIRD não encontrado"
        exit 1
    fi

    # 1. Scope
    build_scope

    # 2. Process data
    process_all_data

    # 3. DNS validation
    validate_subdomains

    # 4. Shodan enrichment
    enrich_with_shodan

    # 5. Rule-based analysis
    log_info "Gerando análise baseada em regras..."
    local analysis
    analysis=$(generate_analysis)
    log_success "Análise concluída"

    # 6. Generate pages
    log_info "Gerando páginas HTML..."
    generate_css
    generate_js
    generate_index "$analysis"
    generate_subdomains_page
    generate_brid_page
    generate_urls_page
    generate_tree_page
    generate_dns_page

    # Clean up removed pages
    rm -f "${DASHBOARD_DIR}/all-subdomains.html"
    rm -f "${DASHBOARD_DIR}/valid-subdomains.html"
    rm -f "${DASHBOARD_DIR}/fierce.html"
    rm -f "${DASHBOARD_DIR}/repos.html"

    log_success "Dashboard gerado em: ${DASHBOARD_DIR}/"
    log_info "Páginas: index.html, subdomains.html, brid-craftjs.html, urls.html, tree.html, dns.html"
}

# ============================================
# PAGE: DNS (dnsrecon + dnsenum tree + SPF)
# ============================================

generate_dns_page() {
    python3 << 'PYEOF'
import os, json, csv, re, glob
import html as h
from collections import defaultdict
from io import StringIO

OUT_DIR = os.environ.get("OUT_DIR", "OUT-WEB-BIRD")
DASHBOARD_DIR = os.environ.get("DASHBOARD_DIR", "dashboard")

# --- Parse dnsrecon CSV ---
dns_records = []  # list of dicts {domain, type, name, address, target, port, string}
for f in glob.glob(os.path.join(OUT_DIR, "*", "*-dnsrecon")):
    domain = os.path.basename(os.path.dirname(f))
    try:
        with open(f) as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                row['_source'] = 'dnsrecon'
                row['_domain'] = domain
                dns_records.append(row)
    except:
        pass

# --- Parse dnsenum text ---
for f in glob.glob(os.path.join(OUT_DIR, "*", "*-dnsenum")):
    domain = os.path.basename(os.path.dirname(f))
    try:
        with open(f) as fh:
            current_section = ""
            for line in fh:
                line = line.strip()
                if not line or line.startswith("dnsenum") or line.startswith("-----"):
                    continue
                if line.endswith(":") and not line.startswith(" "):
                    current_section = line.rstrip("_: ").strip()
                    continue
                # Parse DNS record lines
                parts = line.split()
                if len(parts) >= 5 and parts[2] == "IN":
                    name = parts[0].rstrip(".")
                    rtype = parts[3]
                    value = parts[4].rstrip(".") if len(parts) > 4 else ""
                    dns_records.append({
                        'Domain': domain,
                        'Type': rtype,
                        'Name': name,
                        'Address': value if rtype in ('A','AAAA') else '',
                        'Target': value if rtype not in ('A','AAAA') else '',
                        'Port': '',
                        'String': '',
                        '_source': 'dnsenum',
                        '_domain': domain
                    })
    except:
        pass

# --- Group by domain then by type ---
by_domain = defaultdict(lambda: defaultdict(list))
for r in dns_records:
    dom = r.get('_domain', r.get('Domain', '?'))
    rtype = r.get('Type', '?')
    by_domain[dom][rtype].append(r)

# --- SPF/DMARC analysis ---
spf_findings = []
dmarc_findings = []
for r in dns_records:
    rtype = r.get('Type', '')
    val = r.get('String', '') or r.get('Target', '') or r.get('Address', '')
    name = r.get('Name', '')
    dom = r.get('_domain', '')
    if rtype == 'TXT' and 'v=spf1' in val.lower():
        # Determine SPF policy
        if '-all' in val:
            policy = '-all (Hard Fail)'
            severity = 'good'
            color = '#4ade80'
            icon = '✅'
        elif '~all' in val:
            policy = '~all (Soft Fail)'
            severity = 'warn'
            color = '#fbbf24'
            icon = '⚠️'
        elif '?all' in val:
            policy = '?all (Neutral)'
            severity = 'danger'
            color = '#f87171'
            icon = '🔴'
        elif '+all' in val:
            policy = '+all (Pass All — DANGEROUS!)'
            severity = 'critical'
            color = '#ef4444'
            icon = '🚨'
        else:
            policy = 'No qualifier found'
            severity = 'warn'
            color = '#fbbf24'
            icon = '❓'
        spf_findings.append({'domain': dom, 'name': name, 'value': val, 'policy': policy, 'severity': severity, 'color': color, 'icon': icon})
    if rtype == 'TXT' and 'v=dmarc' in val.lower():
        dmarc_findings.append({'domain': dom, 'name': name, 'value': val})

# --- Generate HTML ---
out = open(os.path.join(DASHBOARD_DIR, "dns.html"), "w")
out.write('<!DOCTYPE html><html lang="pt-BR"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">\n')
out.write('<title>DNS Analysis - Dashboard</title><link rel="stylesheet" href="assets/style.css">\n')
out.write('<style>\n')
out.write('.dns-tree{margin:0.5rem 0}\n')
out.write('.dns-type-header{display:flex;align-items:center;gap:0.5rem;padding:0.6rem 1rem;cursor:pointer;border-radius:0.5rem;background:rgba(99,102,241,0.06);margin:0.3rem 0;transition:background 0.2s}\n')
out.write('.dns-type-header:hover{background:rgba(99,102,241,0.12)}\n')
out.write('.dns-type-badge{padding:0.15rem 0.5rem;border-radius:0.3rem;font-size:0.72rem;font-weight:bold;min-width:36px;text-align:center}\n')
out.write('.dns-type-A .dns-type-badge{background:rgba(96,165,250,0.2);color:#60a5fa}\n')
out.write('.dns-type-MX .dns-type-badge{background:rgba(251,146,60,0.2);color:#fdba74}\n')
out.write('.dns-type-NS .dns-type-badge{background:rgba(74,222,128,0.2);color:#4ade80}\n')
out.write('.dns-type-TXT .dns-type-badge{background:rgba(167,139,250,0.2);color:#a78bfa}\n')
out.write('.dns-type-SOA .dns-type-badge{background:rgba(248,113,113,0.2);color:#f87171}\n')
out.write('.dns-type-SRV .dns-type-badge{background:rgba(45,212,191,0.2);color:#2dd4bf}\n')
out.write('.dns-type-CNAME .dns-type-badge{background:rgba(251,191,36,0.2);color:#fbbf24}\n')
out.write('.dns-type-AAAA .dns-type-badge{background:rgba(129,140,248,0.2);color:#818cf8}\n')
out.write('.dns-records{display:none;padding:0.3rem 0 0.3rem 2.5rem}\n')
out.write('.dns-records.open{display:block}\n')
out.write('.dns-record{padding:0.35rem 0.8rem;font-size:0.8rem;border-left:2px solid rgba(99,102,241,0.2);margin:0.15rem 0;font-family:monospace;color:#cbd5e1}\n')
out.write('.dns-record .rec-name{color:#93c5fd}.dns-record .rec-val{color:#fca5a5}.dns-record .rec-target{color:#86efac}\n')
out.write('.dns-arrow{transition:transform 0.2s;color:#6366f1}.dns-arrow.open{transform:rotate(90deg)}\n')
out.write('.dns-count{font-size:0.7rem;color:#64748b}\n')
out.write('.spf-card{padding:1rem;border-radius:0.5rem;border-left:4px solid;margin:0.5rem 0}\n')
out.write('.spf-value{font-family:monospace;font-size:0.75rem;word-break:break-all;padding:0.5rem;border-radius:0.3rem;background:rgba(0,0,0,0.3);margin-top:0.5rem;color:#e2e8f0}\n')
out.write('.domain-section{margin-bottom:1.5rem}\n')
out.write('</style>\n')
out.write('</head><body>\n')
out.close()

# Nav
import subprocess
nav_html = subprocess.run(['bash', '-c', 'source ' + os.path.join(os.path.dirname(os.path.abspath(".")), "tool-web-dashboard.sh").replace("tool-web-dashboard.sh","") + '/tool-web-dashboard.sh 2>/dev/null; generate_nav dns 2>/dev/null || echo ""'], capture_output=True, text=True).stdout
# Fallback: write nav manually
out = open(os.path.join(DASHBOARD_DIR, "dns.html"), "a")

# Write nav manually since we can't source bash function from Python
out.write('<nav><div class="container"><h1>🦅 Bird Tool Web Analyzer <span class="llm-badge">📊 Auto</span></h1><div class="nav-links">')
out.write('<a href="index.html">Dashboard</a>')
out.write('<a href="subdomains.html">Subdominios</a>')
out.write('<a href="brid-craftjs.html">BRID-CRAFTJS</a>')
out.write('<a href="urls.html">URLs</a>')
out.write('<a href="tree.html">Tree</a>')
out.write('<a href="dns.html" class="active">DNS</a>')
out.write('</div></div></nav>\n')

out.write('<div class="container">\n')
out.write(f'<div class="card"><h2>📡 DNS Analysis <span class="llm-badge">📊 Auto</span></h2>')
out.write(f'<p>Registros DNS de <strong>{len(by_domain)}</strong> domínios • <strong>{len(dns_records)}</strong> registros totais • dnsrecon + dnsenum</p></div>\n')

# --- SPF Section ---
if spf_findings:
    out.write('<div class="card"><h3>🛡️ SPF Policy Analysis</h3>\n')
    for spf in spf_findings:
        border_color = spf['color']
        out.write(f'<div class="spf-card" style="border-color:{border_color}">')
        out.write(f'<strong>{spf["icon"]} {h.escape(spf["domain"])}</strong> — <span style="color:{border_color}">{h.escape(spf["policy"])}</span>')
        out.write(f'<div class="spf-value">{h.escape(spf["value"])}</div>')
        out.write('</div>\n')
    out.write('</div>\n')

# --- DMARC Section ---
if dmarc_findings:
    out.write('<div class="card"><h3>📧 DMARC Records</h3>\n')
    for dm in dmarc_findings:
        out.write(f'<div class="spf-card" style="border-color:#a78bfa">')
        out.write(f'<strong>📧 {h.escape(dm["domain"])}</strong> — {h.escape(dm["name"])}')
        out.write(f'<div class="spf-value">{h.escape(dm["value"])}</div>')
        out.write('</div>\n')
    out.write('</div>\n')

# --- DNS Tree per domain ---
type_order = ['SOA', 'NS', 'A', 'AAAA', 'MX', 'CNAME', 'TXT', 'SRV']

for domain in sorted(by_domain.keys()):
    types = by_domain[domain]
    total = sum(len(v) for v in types.values())
    out.write(f'<div class="card domain-section"><h3>🌐 {h.escape(domain)} <span class="dns-count">({total} registros)</span></h3>\n')
    out.write('<div class="dns-tree">\n')

    # Sort types by predefined order
    sorted_types = sorted(types.keys(), key=lambda x: type_order.index(x) if x in type_order else 99)

    for rtype in sorted_types:
        records = types[rtype]
        # Deduplicate records
        seen = set()
        unique_records = []
        for r in records:
            key = (r.get('Name',''), r.get('Address',''), r.get('Target',''), r.get('String',''))
            if key not in seen:
                seen.add(key)
                unique_records.append(r)

        tid = f"dns-{h.escape(domain)}-{h.escape(rtype)}".replace(".", "-")
        out.write(f'<div class="dns-type-{h.escape(rtype)}">')
        out.write(f'<div class="dns-type-header" onclick="var r=document.getElementById(\'{tid}\');r.classList.toggle(\'open\');this.querySelector(\'.dns-arrow\').classList.toggle(\'open\')">')
        out.write(f'<span class="dns-arrow">▶</span>')
        out.write(f'<span class="dns-type-badge">{h.escape(rtype)}</span>')
        out.write(f'<span style="color:#e2e8f0">{h.escape(rtype)} Records</span>')
        out.write(f'<span class="dns-count">{len(unique_records)}</span>')
        out.write('</div>')
        out.write(f'<div id="{tid}" class="dns-records">')

        for r in unique_records:
            name = r.get('Name', '')
            addr = r.get('Address', '')
            target = r.get('Target', '')
            string = r.get('String', '')
            port = r.get('Port', '')
            display = ''
            if name:
                display += f'<span class="rec-name">{h.escape(name)}</span> '
            if addr:
                display += f'→ <span class="rec-val">{h.escape(addr)}</span> '
            if target:
                display += f'→ <span class="rec-target">{h.escape(target)}</span> '
            if port:
                display += f':{h.escape(str(port))} '
            if string:
                display += f'<span style="color:#a78bfa">{h.escape(string[:120])}</span>'
            out.write(f'<div class="dns-record">{display}</div>\n')

        out.write('</div></div>\n')

    out.write('</div></div>\n')

out.write('</div>\n')
out.write('<script src="assets/script.js"></script></body></html>\n')
out.close()
print(f"[DNS] Generated dns.html with {len(dns_records)} records from {len(by_domain)} domains")
PYEOF
}

main "$@"
