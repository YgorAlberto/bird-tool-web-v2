#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# 🐦 BIRD TOOL WEB — Status Monitor v2
# Run in a separate terminal: ./status.sh [refresh_seconds]
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BIRD_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$BIRD_DIR/OUT-WEB-BIRD"
REFRESH=${1:-10}

# Colors
R='\033[0;31m'  G='\033[0;32m'  Y='\033[0;33m'
B='\033[0;34m'  M='\033[0;35m'  C='\033[0;36m'
W='\033[1;37m'  D='\033[0;90m'  N='\033[0m'
BG='\033[42;30m' BR='\033[41;37m' BY='\033[43;30m'

is_running() {
    pgrep -f "$1" &>/dev/null
}

any_running() {
    for t in "$@"; do is_running "$t" && return 0; done
    return 1
}

# How many targets in target.txt had output from a specific tool
count_tool_outputs() {
    local tool_pattern="$1"
    local count=0
    for d in "$OUT_DIR"/*/; do
        [[ ! -d "$d" ]] && continue
        ls "$d"/*${tool_pattern}* &>/dev/null && count=$((count + 1))
    done
    echo $count
}

while true; do
    clear

    # Gather info
    target_count=0
    [[ -f "$BIRD_DIR/target.txt" ]] && target_count=$(grep -c . "$BIRD_DIR/target.txt" 2>/dev/null)
    target_full_exists=false
    target_full_count=0
    if [[ -f "$BIRD_DIR/target-full.txt" ]]; then
        target_full_exists=true
        target_full_count=$(grep -c . "$BIRD_DIR/target-full.txt" 2>/dev/null)
    fi

    # KEY METRIC 1: File count in OUT-WEB-BIRD
    total_files=0
    [[ -d "$OUT_DIR" ]] && total_files=$(find "$OUT_DIR" -type f 2>/dev/null | wc -l)

    # Detection: if target-full.txt exists, parsing-domains.sh already ran → stage 3 done
    past_parsing=$target_full_exists

    # Detection: count output dirs (each target gets a dir)
    out_dirs=0
    [[ -d "$OUT_DIR" ]] && out_dirs=$(find "$OUT_DIR" -maxdepth 1 -type d | tail -n +2 | wc -l)

    # Tools currently running
    disc_tools=(assetfinder sublist3r subfinder dnsenum dnsrecon)
    sec_tools=(urlfinder fierce hakrawler waybackurls gau)
    all_scan_tools=("${disc_tools[@]}" "${sec_tools[@]}")

    running_list=()
    for t in "${all_scan_tools[@]}" katana bird-craftjs tool-web-dashboard; do
        is_running "$t" && running_list+=("$t")
    done

    disc_running=false; any_running "${disc_tools[@]}" && disc_running=true
    sec_running=false;  any_running "${sec_tools[@]}" && sec_running=true
    katana_running=false; is_running "katana" && katana_running=true
    brid_running=false; any_running "bird-craftjs" "tool-bird-craftjs" && brid_running=true
    dashboard_running=false; is_running "tool-web-dashboard" && dashboard_running=true

    # Dashboards exist?
    has_dashboard=false
    [[ -f "$BIRD_DIR/dashboard/index.html" ]] && has_dashboard=true
    has_llm=false
    [[ -f "$BIRD_DIR/dashboard-llm/index.html" ]] && has_llm=true

    # BRID output exists?
    has_brid=false
    for d in "$OUT_DIR"/*/; do
        tname=$(basename "$d" 2>/dev/null)
        [[ -f "$d/${tname}-BRID-CRAFTJS" ]] && has_brid=true && break
    done

    # --- Determine Stage ---
    # Flow: 1→ Discovery+Recon | 2→ Katana 1st | 3→ Parse+Validate | 4→ Rescan subs | 5→ Katana 2nd | 6→ BRID | 7→ Dashboard
    #
    # KEY METRIC 2: Running processes (which tools are alive)
    # KEY METRIC 3: Stage based on main script flow + target-full.txt
    #
    # Expected files per stage (used for progress %):
    #   Stage 1: ~10 files/target (1 per tool × N targets)
    #   Stage 2: +1 katana file/target
    #   Stage 4: ~5 files/target (secondary tools × M new targets)
    #   Stage 5: +1 katana file/target
    #   Stage 6: +1 BRID file/target
    stage=0; stage_name="Idle"; stage_pct=0

    if $dashboard_running; then
        stage=7; stage_name="📊 Generating Dashboard"; stage_pct=92
    elif $has_dashboard || $has_llm; then
        stage=8; stage_name="✅ COMPLETED"; stage_pct=100
    elif $brid_running; then
        stage=6; stage_name="🐦 JS Analysis (BRID-CRAFTJS)"; stage_pct=80
    elif $has_brid && ! $dashboard_running; then
        stage=7; stage_name="⏳ Waiting Dashboard"; stage_pct=85
    elif $past_parsing && $katana_running; then
        stage=5; stage_name="⚔️  Katana Crawl (2nd pass — subs)"; stage_pct=68
    elif $past_parsing && ($disc_running || $sec_running); then
        stage=4; stage_name="🔍 Rescanning Discovered Subs"; stage_pct=50
    elif $past_parsing && ! $katana_running && ! $disc_running && ! $sec_running && ! $brid_running; then
        stage=4; stage_name="⏳ Between stages"; stage_pct=45
    elif $katana_running && ! $past_parsing; then
        stage=2; stage_name="⚔️  Katana Crawl (1st pass — main)"; stage_pct=28
    elif ($disc_running || $sec_running) && ! $past_parsing; then
        stage=1; stage_name="🚀 Discovery & Recon (1st pass)"; stage_pct=5
    else
        stage=0; stage_name="💤 Not Running"; stage_pct=0
    fi

    # --- Refine progress % using file counts ---
    if [[ $stage -eq 1 && $target_count -gt 0 ]]; then
        # Stage 1: expect ~10 files per target (10 tools)
        expected=$((target_count * 10))
        [[ $expected -gt 0 ]] && stage_pct=$(( 2 + (total_files * 23 / expected) ))  # 2%-25%
        [[ $stage_pct -gt 25 ]] && stage_pct=25
    elif [[ $stage -eq 4 && $target_count -gt 0 ]]; then
        # Stage 4: expect ~5 new files per target (5 secondary tools)
        # Files from stage 1+2 already exist, so subtract baseline
        baseline_files=$((out_dirs * 11))  # ~11 files from first pass
        new_files=$((total_files - baseline_files))
        [[ $new_files -lt 0 ]] && new_files=0
        expected=$((target_count * 5))
        [[ $expected -gt 0 ]] && stage_pct=$(( 42 + (new_files * 18 / expected) ))  # 42%-60%
        [[ $stage_pct -gt 60 ]] && stage_pct=60
    fi

    # ═══ HEADER ═══
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo -e "${W}  🐦 BIRD TOOL WEB — Status Monitor${N}"
    echo -e "${D}  $(date '+%H:%M:%S') • Refresh: ${REFRESH}s${N}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
    echo ""

    # KEY METRICS summary line
    echo -e "  ${W}📁 ${total_files} files${N}  ${D}│${N}  ${W}⚙️  ${#running_list[@]} procs${N}  ${D}│${N}  ${W}🎯 ${target_count} targets${N}  ${D}│${N}  ${W}📂 ${out_dirs} dirs${N}"
    echo ""

    # ═══ STAGE + PROGRESS ═══
    if [[ $stage -eq 8 ]]; then
        echo -e "  ${BG} ✅ ALL DONE ${N}"
    elif [[ $stage -eq 0 ]]; then
        echo -e "  ${D}💤 No tools running${N}"
    else
        echo -e "  ${BY} STAGE $stage/7 ${N}  ${W}$stage_name${N}"
    fi
    echo ""

    # Progress bar
    bw=44; filled=$((stage_pct * bw / 100)); empty=$((bw - filled))
    bar=""; for ((i=0;i<filled;i++)); do bar+="█"; done; for ((i=0;i<empty;i++)); do bar+="░"; done
    echo -e "  ${G}${bar}${N} ${W}${stage_pct}%${N}"
    echo ""

    # ═══ PIPELINE ═══
    echo -e "  ${W}PIPELINE${N}"
    labels=("1. Discovery + Recon (main)"
            "2. Katana (1st — main targets)"
            "3. Parse & Validate Subs"
            "4. Rescan (discovered subs)"
            "5. Katana (2nd — all subs)"
            "6. BRID-CRAFTJS Analysis"
            "7. Generate Dashboard")
    for i in {0..6}; do
        s=$((i + 1))
        if [[ $s -lt $stage ]] || [[ $stage -eq 8 ]]; then
            echo -e "  ${G}  ✅ ${labels[$i]}${N}"
        elif [[ $s -eq $stage ]]; then
            echo -e "  ${Y}  ▶️  ${labels[$i]}  ${BY} NOW ${N}"
        else
            echo -e "  ${D}  ⬜ ${labels[$i]}${N}"
        fi
    done
    echo ""

    # ═══ RUNNING TOOLS ═══
    if [[ ${#running_list[@]} -gt 0 ]]; then
        echo -e "  ${W}⚡ RUNNING${N} ${D}(${#running_list[@]} tools)${N}"
        for t in "${running_list[@]}"; do
            pid=$(pgrep -f "$t" | head -1)
            cpu=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ')
            mem=$(ps -p "$pid" -o %mem= 2>/dev/null | tr -d ' ')
            elapsed=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ')
            c="$G"
            (( $(echo "${cpu:-0} > 50" | bc -l 2>/dev/null || echo 0) )) && c="$R"
            (( $(echo "${cpu:-0} > 10" | bc -l 2>/dev/null || echo 0) )) && c="$Y"

            # Count how many targets this tool has completed (output files)
            tool_done=$(count_tool_outputs "$t")
            tool_total=$out_dirs
            [[ $tool_done -gt $tool_total ]] && tool_done=$tool_total
            tool_remaining=$((tool_total - tool_done))

            printf "  ${c}  ● %-14s${N}" "$t"
            printf " ${W}%d${N}${D}/${N}${W}%d${N} ${D}targets${N}" "$tool_done" "$tool_total"
            printf "  ${D}CPU:${N}${c}%-5s${N}" "${cpu:-?}%"
            printf " ${D}⏱${N} %-8s" "${elapsed:-?}"
            if [[ $tool_remaining -gt 0 ]]; then
                printf " ${Y}(%d left)${N}" "$tool_remaining"
            else
                printf " ${G}(done)${N}"
            fi
            echo ""
        done

        # Chromium workers
        cc=$(pgrep -f "chrom.*katana" 2>/dev/null | wc -l)
        [[ $cc -gt 0 ]] && echo -e "  ${D}  └─ 🌐 $cc Chromium workers${N}"
        echo ""
    fi

    # ═══ TOOL STATUS (current stage) ═══
    if [[ $stage -eq 1 || $stage -eq 4 ]]; then
        if [[ $stage -eq 1 ]]; then
            check_tools=("${all_scan_tools[@]}")
            stage_label="1ST PASS"
        else
            check_tools=("${sec_tools[@]}")
            stage_label="2ND PASS"
        fi

        echo -e "  ${W}📋 TOOLS — $stage_label${N}"
        for t in "${check_tools[@]}"; do
            if is_running "$t"; then
                pid=$(pgrep -f "$t" | head -1)
                elapsed=$(ps -p "$pid" -o etime= 2>/dev/null | tr -d ' ')
                echo -e "  ${Y}  ⏳ $t${N} ${D}(running ${elapsed:-?})${N}"
            else
                c=$(count_tool_outputs "$t")
                if [[ $c -gt 0 ]]; then
                    echo -e "  ${G}  ✅ $t${N} ${D}($c targets done)${N}"
                else
                    echo -e "  ${D}  ⬜ $t${N} ${D}(not started)${N}"
                fi
            fi
        done
        echo ""
    fi

    # ═══ DATA ═══
    total_subs=0; total_urls=0; total_brid=0; total_katana=0
    if [[ -d "$OUT_DIR" ]]; then
        for td in "$OUT_DIR"/*/; do
            [[ ! -d "$td" ]] && continue
            tn=$(basename "$td")
            u=$(cat "$td"/${tn}-URL* 2>/dev/null | sort -u | wc -l | tr -d ' ')
            k=0; [[ -f "$td/${tn}-katana.json" ]] && k=$(wc -l < "$td/${tn}-katana.json" 2>/dev/null | tr -d ' ')
            b=0; [[ -f "$td/${tn}-BRID-CRAFTJS" ]] && b=$(wc -l < "$td/${tn}-BRID-CRAFTJS" 2>/dev/null | tr -d ' ')
            total_urls=$((total_urls + u))
            total_katana=$((total_katana + k))
            total_brid=$((total_brid + b))
        done
    fi
    [[ -f "$BIRD_DIR/target-full.txt" ]] && total_subs=$(grep -c . "$BIRD_DIR/target-full.txt" 2>/dev/null)

    echo -e "  ${W}📊 DATA${N}"
    printf "  ${C}  🎯 Targets:${N} ${W}%-5s${N}" "$target_count"
    printf "  ${C}🌐 Subs Found:${N} ${W}%-5s${N}" "$total_subs"
    printf "  ${C}📂 Dirs:${N} ${W}%-5s${N}\n" "$out_dirs"
    printf "  ${C}  🔗 URLs:${N}    ${W}%-5s${N}" "$total_urls"
    printf "  ${C}⚔️  Katana:${N}    ${W}%-5s${N}" "$total_katana"
    printf "  ${C}🐦 BRID:${N} ${W}%-5s${N}\n" "$total_brid"
    [[ -d "$OUT_DIR" ]] && echo -e "  ${C}  💾 Disk:${N}    ${W}$(du -sh "$OUT_DIR" 2>/dev/null | cut -f1)${N}"
    echo ""

    # ═══ DASHBOARDS ═══
    echo -e "  ${W}📄 DASHBOARDS${N}"
    for dname in "dashboard:Auto" "dashboard-llm:LLM"; do
        dir="${dname%%:*}"; label="${dname##*:}"
        if [[ -f "$BIRD_DIR/$dir/index.html" ]]; then
            t=$(stat -c '%Y' "$BIRD_DIR/$dir/index.html" 2>/dev/null)
            ago=$(( $(date +%s) - t ))
            [[ $ago -lt 60 ]] && ts="${ago}s ago" || { [[ $ago -lt 3600 ]] && ts="$(( ago / 60 ))m ago" || ts="$(( ago / 3600 ))h ago"; }
            echo -e "  ${G}  ✅ $label  ${D}$ts${N}"
        else
            echo -e "  ${D}  ⬜ $label${N}"
        fi
    done
    echo ""

    # ═══ SYSTEM ═══
    cpu=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{printf "%.0f", $2+$4}')
    mem=$(free -h 2>/dev/null | awk '/^Mem:/ {printf "%s/%s", $3, $2}')
    echo -e "  ${D}💻 CPU: ${W}${cpu:-?}%${N}  ${D}RAM: ${W}${mem:-?}${N}  ${D}Procs: ${W}${#running_list[@]}${N}"
    echo -e "${W}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"

    sleep "$REFRESH"
done
