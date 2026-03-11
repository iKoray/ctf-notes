#!/bin/bash

# ctf_recon.sh
# Purpose: CTF-focused recon pipeline with full TCP discovery, clean parsing,
# web fingerprinting, and dynamic next-step suggestions.

set -Eeuo pipefail

#############################################
# Defaults
#############################################

PROFILE="full"
TARGET=""
TARGET_FILE=""
OUTPUT_DIR=""
SKIP_DISCOVERY=false
UDP_SCAN=false
TIMESTAMP="$(date +"%Y-%m-%d_%H-%M-%S")"

# Full port discovery defaults
MIN_RATE_QUICK=2000
MIN_RATE_FULL=1000
MIN_RATE_WEB=1500

# Common web ports for extra web enum
COMMON_WEB_PORTS=("80" "81" "443" "591" "593" "8000" "8008" "8080" "8081" "8088" "8443" "8888")

#############################################
# UI helpers
#############################################

info()  { echo "[+] $*"; }
warn()  { echo "[!] $*" >&2; }
error() { echo "[x] $*" >&2; exit 1; }

#############################################
# Help
#############################################

show_help() {
    cat <<'EOF'
Usage:
  ./ctf_recon.sh -t <target> [-p profile] [-o output_dir]
  ./ctf_recon.sh -f <targets.txt> [-p profile] [-o output_dir] [-n] [-u]

Options:
  -t    Single target: IP, hostname, or CIDR
  -f    File containing targets
  -p    Profile: quick | full | web | udp-light
  -o    Output directory name
  -n    Skip host discovery and treat supplied targets as live
  -u    Run top-100 UDP scan after TCP workflow
  -h    Show this help

Examples:
  ./ctf_recon.sh -t 10.10.10.5
  ./ctf_recon.sh -t 10.10.10.0/24 -p full
  ./ctf_recon.sh -f targets.txt -p web -u
  ./ctf_recon.sh -t target.htb -n

Notes:
  - TCP discovery uses -p- to scan all TCP ports.
  - Service scans only run against discovered open ports.
  - Web fingerprinting runs automatically when web services are found.
EOF
    exit 0
}

#############################################
# Cleanup and error handling
#############################################

cleanup_on_error() {
    local exit_code=$?
    warn "Script exited unexpectedly with code $exit_code"
    warn "Check raw scan files under: ${OUTPUT_DIR:-current directory}"
    exit "$exit_code"
}
trap cleanup_on_error ERR

#############################################
# Dependency checks
#############################################

check_dependencies() {
    local required=(nmap awk grep sed sort cut tr paste tee)
    local missing=()

    for tool in "${required[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing+=("$tool")
        fi
    done

    if ((${#missing[@]} > 0)); then
        error "Missing required tools: ${missing[*]}"
    fi

    if [[ $EUID -ne 0 ]]; then
        warn "Not running as root. Nmap may fall back to connect scans and some detection may be reduced."
    fi

    if command -v whatweb >/dev/null 2>&1; then
        info "Optional tool detected: whatweb"
    else
        warn "Optional tool not found: whatweb. Web fingerprinting will still use curl and Nmap."
    fi

    if command -v curl >/dev/null 2>&1; then
        info "Optional tool detected: curl"
    else
        warn "Optional tool not found: curl. HTTP title and header grabbing will be limited."
    fi
}

#############################################
# Parse args
#############################################

parse_args() {
    while getopts ":t:f:p:o:nuh" opt; do
        case "$opt" in
            t) TARGET="$OPTARG" ;;
            f) TARGET_FILE="$OPTARG" ;;
            p) PROFILE="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
            n) SKIP_DISCOVERY=true ;;
            u) UDP_SCAN=true ;;
            h) show_help ;;
            :) error "Option -$OPTARG requires an argument." ;;
            \?) error "Invalid option: -$OPTARG" ;;
        esac
    done

    [[ -z "$TARGET" && -z "$TARGET_FILE" ]] && error "Supply either -t or -f"
    [[ -n "$TARGET" && -n "$TARGET_FILE" ]] && error "Use either -t or -f, not both"

    case "$PROFILE" in
        quick|full|web|udp-light) ;;
        *) error "Invalid profile: $PROFILE" ;;
    esac

    if [[ -n "$TARGET_FILE" && ! -f "$TARGET_FILE" ]]; then
        error "Target file does not exist: $TARGET_FILE"
    fi
}

#############################################
# Output structure
#############################################

setup_output_dirs() {
    if [[ -z "$OUTPUT_DIR" ]]; then
        if [[ -n "$TARGET" ]]; then
            local safe_target
            safe_target="$(echo "$TARGET" | sed 's#[/: ]#_#g')"
            OUTPUT_DIR="recon_${TIMESTAMP}_${safe_target}"
        else
            OUTPUT_DIR="recon_${TIMESTAMP}_targets"
        fi
    fi

    mkdir -p "$OUTPUT_DIR"/{scans,parsed,logs,notes,web}
    touch "$OUTPUT_DIR/notes/manual_notes.md"

    info "Output directory: $OUTPUT_DIR"
}

#############################################
# Build target list
#############################################

build_target_list() {
    TARGET_LIST="$OUTPUT_DIR/parsed/targets.txt"

    if [[ -n "$TARGET" ]]; then
        printf "%s\n" "$TARGET" > "$TARGET_LIST"
    else
        sed '/^[[:space:]]*$/d; /^[[:space:]]*#/d' "$TARGET_FILE" > "$TARGET_LIST"
    fi

    [[ ! -s "$TARGET_LIST" ]] && error "No usable targets found."

    info "Targets queued:"
    cat "$TARGET_LIST"
}

#############################################
# Host discovery
#############################################

run_host_discovery() {
    local live_file="$OUTPUT_DIR/parsed/live_hosts.txt"

    if [[ "$SKIP_DISCOVERY" == true ]]; then
        info "Skipping host discovery. Treating supplied targets as live."
        cp "$TARGET_LIST" "$live_file"
        return
    fi

    info "Running host discovery"

    # Discovery first. If nothing responds, fall back to treating targets as live.
    nmap -sn -iL "$TARGET_LIST" -oA "$OUTPUT_DIR/scans/host_discovery" | tee "$OUTPUT_DIR/logs/host_discovery.log" >/dev/null || true

    awk '/Status: Up/{print $2}' "$OUTPUT_DIR/scans/host_discovery.gnmap" | sort -u > "$live_file" || true

    if [[ ! -s "$live_file" ]]; then
        warn "No live hosts found via discovery. ICMP may be blocked."
        warn "Falling back to supplied targets. You can also rerun with -n."
        cp "$TARGET_LIST" "$live_file"
    fi

    info "Live targets:"
    cat "$live_file"
}

#############################################
# TCP discovery scan
#############################################

get_min_rate() {
    case "$PROFILE" in
        quick) echo "$MIN_RATE_QUICK" ;;
        full) echo "$MIN_RATE_FULL" ;;
        web) echo "$MIN_RATE_WEB" ;;
        udp-light) echo "$MIN_RATE_FULL" ;;
    esac
}

run_tcp_discovery() {
    local rate
    rate="$(get_min_rate)"

    info "Running full TCP discovery with -p-"
    info "Profile: $PROFILE | min-rate: $rate"

    if [[ "$SKIP_DISCOVERY" == true ]]; then
        nmap -Pn -p- --min-rate "$rate" -T4 -iL "$OUTPUT_DIR/parsed/live_hosts.txt" \
            -oA "$OUTPUT_DIR/scans/tcp_discovery" | tee "$OUTPUT_DIR/logs/tcp_discovery.log" >/dev/null
    else
        nmap -p- --min-rate "$rate" -T4 -iL "$OUTPUT_DIR/parsed/live_hosts.txt" \
            -oA "$OUTPUT_DIR/scans/tcp_discovery" | tee "$OUTPUT_DIR/logs/tcp_discovery.log" >/dev/null
    fi
}

#############################################
# Better parsing logic
# Upgrade 1: clean host -> port mapping
#############################################

parse_open_ports() {
    local gnmap="$OUTPUT_DIR/scans/tcp_discovery.gnmap"
    local map_file="$OUTPUT_DIR/parsed/host_ports.csv"
    local readable_file="$OUTPUT_DIR/parsed/open_ports_by_host.txt"
    local all_open_file="$OUTPUT_DIR/parsed/all_open_ports.txt"
    local odd_ports_file="$OUTPUT_DIR/parsed/odd_ports.txt"

    : > "$map_file"
    : > "$readable_file"
    : > "$all_open_file"
    : > "$odd_ports_file"

    info "Parsing TCP discovery results"

    awk '
    /^Host: / && /Ports: / {
        host=$2
        ports_part=$0
        sub(/^.*Ports: /, "", ports_part)
        sub(/ Ignored State:.*$/, "", ports_part)

        n=split(ports_part, arr, ", ")
        ports=""

        for (i=1; i<=n; i++) {
            split(arr[i], fields, "/")
            port=fields[1]
            state=fields[2]
            proto=fields[3]
            svc=fields[5]

            if (state == "open" && proto == "tcp") {
                if (ports == "") {
                    ports=port
                } else {
                    ports=ports "," port
                }
                print host "|" port "|" svc
            }
        }

        if (ports != "") {
            print host "," ports > MAPFILE
        }
    }
    ' MAPFILE="$map_file" "$gnmap" > "$all_open_file"

    if [[ ! -s "$map_file" ]]; then
        warn "No open TCP ports found."
        return
    fi

    while IFS=',' read -r host ports; do
        printf "%s -> %s\n" "$host" "$ports" >> "$readable_file"

        IFS=',' read -ra port_array <<< "$ports"
        for p in "${port_array[@]}"; do
            case "$p" in
                21|22|25|53|80|81|88|110|111|123|135|139|143|161|389|443|445|465|514|587|593|631|636|873|993|995|1080|1433|1521|1723|1883|2049|2375|2376|3000|3128|3306|3389|5000|5432|5601|5900|5985|5986|6379|8000|8008|8080|8081|8088|8443|8888|9000|9090|9200|9418|11211|27017)
                    ;;
                *)
                    printf "%s -> %s\n" "$host" "$p" >> "$odd_ports_file"
                    ;;
            esac
        done
    done < "$map_file"

    info "Open ports by host:"
    cat "$readable_file"
}

#############################################
# Detailed service scan
#############################################

run_service_scan() {
    local map_file="$OUTPUT_DIR/parsed/host_ports.csv"
    local aggregate="$OUTPUT_DIR/parsed/service_summary.txt"

    : > "$aggregate"

    [[ ! -s "$map_file" ]] && { warn "Skipping service scan. No open ports were parsed."; return; }

    info "Running targeted service scans"

    while IFS=',' read -r host ports; do
        [[ -z "$host" || -z "$ports" ]] && continue

        info "Service scan on $host ports: $ports"

        if [[ "$SKIP_DISCOVERY" == true ]]; then
            nmap -Pn -sC -sV -p "$ports" "$host" \
                -oA "$OUTPUT_DIR/scans/service_${host}" | tee "$OUTPUT_DIR/logs/service_${host}.log" >/dev/null
        else
            nmap -sC -sV -p "$ports" "$host" \
                -oA "$OUTPUT_DIR/scans/service_${host}" | tee "$OUTPUT_DIR/logs/service_${host}.log" >/dev/null
        fi

        {
            echo "### $host ###"
            awk '
            /^[0-9]+\/tcp/ {
                printf "%s %s %s %s %s %s\n", $1, $2, $3, $4, $5, $6
            }' "$OUTPUT_DIR/scans/service_${host}.nmap"
            echo
        } >> "$aggregate"
    done < "$map_file"
}

#############################################
# Optional UDP scan
#############################################

run_udp_scan() {
    [[ "$UDP_SCAN" != true && "$PROFILE" != "udp-light" ]] && return

    info "Running top-100 UDP scan"

    if [[ "$SKIP_DISCOVERY" == true ]]; then
        nmap -Pn -sU --top-ports 100 -iL "$OUTPUT_DIR/parsed/live_hosts.txt" \
            -oA "$OUTPUT_DIR/scans/udp_top100" | tee "$OUTPUT_DIR/logs/udp_top100.log" >/dev/null || true
    else
        nmap -sU --top-ports 100 -iL "$OUTPUT_DIR/parsed/live_hosts.txt" \
            -oA "$OUTPUT_DIR/scans/udp_top100" | tee "$OUTPUT_DIR/logs/udp_top100.log" >/dev/null || true
    fi
}

#############################################
# Classify services
#############################################

classify_services() {
    local service_summary="$OUTPUT_DIR/parsed/service_summary.txt"

    : > "$OUTPUT_DIR/parsed/web_services.txt"
    : > "$OUTPUT_DIR/parsed/ssh_services.txt"
    : > "$OUTPUT_DIR/parsed/smb_services.txt"
    : > "$OUTPUT_DIR/parsed/ftp_services.txt"
    : > "$OUTPUT_DIR/parsed/db_services.txt"
    : > "$OUTPUT_DIR/parsed/remote_access_services.txt"

    [[ ! -s "$service_summary" ]] && { warn "No service summary to classify."; return; }

    grep -Ei 'http|ssl/http|https|http-proxy' "$service_summary" > "$OUTPUT_DIR/parsed/web_services.txt" || true
    grep -Ei 'ssh' "$service_summary" > "$OUTPUT_DIR/parsed/ssh_services.txt" || true
    grep -Ei 'microsoft-ds|netbios-ssn|smb' "$service_summary" > "$OUTPUT_DIR/parsed/smb_services.txt" || true
    grep -Ei 'ftp' "$service_summary" > "$OUTPUT_DIR/parsed/ftp_services.txt" || true
    grep -Ei 'mysql|postgres|mongodb|redis|ms-sql|oracle|mariadb' "$service_summary" > "$OUTPUT_DIR/parsed/db_services.txt" || true
    grep -Ei 'rdp|ms-wbt-server|winrm|vnc|ssh' "$service_summary" > "$OUTPUT_DIR/parsed/remote_access_services.txt" || true
}

#############################################
# Web enum helpers
# Upgrade 2: automatic web detection tools
#############################################

is_common_web_port() {
    local needle="$1"
    for p in "${COMMON_WEB_PORTS[@]}"; do
        [[ "$needle" == "$p" ]] && return 0
    done
    return 1
}

scheme_for_port() {
    local port="$1"
    case "$port" in
        443|8443) echo "https" ;;
        *) echo "http" ;;
    esac
}

gather_web_targets() {
    local map_file="$OUTPUT_DIR/parsed/host_ports.csv"
    local web_targets="$OUTPUT_DIR/parsed/web_targets.txt"

    : > "$web_targets"
    [[ ! -s "$map_file" ]] && return

    while IFS=',' read -r host ports; do
        IFS=',' read -ra port_array <<< "$ports"
        for p in "${port_array[@]}"; do
            if is_common_web_port "$p"; then
                printf "%s|%s\n" "$host" "$p" >> "$web_targets"
            fi
        done
    done < "$map_file"

    sort -u "$web_targets" -o "$web_targets" || true
}

run_web_enum() {
    local web_targets="$OUTPUT_DIR/parsed/web_targets.txt"
    local summary="$OUTPUT_DIR/web/web_summary.txt"

    gather_web_targets
    : > "$summary"

    [[ ! -s "$web_targets" ]] && { info "No obvious web ports found for extra web enum."; return; }

    info "Running extra web fingerprinting"

    while IFS='|' read -r host port; do
        [[ -z "$host" || -z "$port" ]] && continue

        local scheme url safe_name
        scheme="$(scheme_for_port "$port")"
        url="${scheme}://${host}:${port}"
        safe_name="${host}_${port}"

        {
            echo "### $url ###"
            echo
        } >> "$summary"

        # Nmap http-title and common header info
        if [[ "$SKIP_DISCOVERY" == true ]]; then
            nmap -Pn -p "$port" --script http-title,http-headers "$host" \
                -oN "$OUTPUT_DIR/web/nmap_http_${safe_name}.txt" >/dev/null 2>&1 || true
        else
            nmap -p "$port" --script http-title,http-headers "$host" \
                -oN "$OUTPUT_DIR/web/nmap_http_${safe_name}.txt" >/dev/null 2>&1 || true
        fi

        echo "[Nmap http-title/http-headers]" >> "$summary"
        sed -n '1,200p' "$OUTPUT_DIR/web/nmap_http_${safe_name}.txt" >> "$summary"
        echo >> "$summary"

        # curl headers and title
        if command -v curl >/dev/null 2>&1; then
            echo "[curl headers]" >> "$summary"
            curl -skI --max-time 8 "$url" >> "$summary" 2>/dev/null || echo "curl headers failed" >> "$summary"
            echo >> "$summary"

            echo "[curl title]" >> "$summary"
            curl -skL --max-time 10 "$url" 2>/dev/null \
                | tr '\n' ' ' \
                | sed 's/<script[^>]*>.*<\/script>/ /Ig; s/<style[^>]*>.*<\/style>/ /Ig' \
                | grep -oi '<title[^>]*>[^<]*</title>' \
                | head -n 1 \
                | sed 's/<[^>]*>//g' >> "$summary" || true
            echo >> "$summary"
        fi

        # whatweb
        if command -v whatweb >/dev/null 2>&1; then
            echo "[whatweb]" >> "$summary"
            whatweb --no-errors "$url" >> "$summary" 2>/dev/null || echo "whatweb failed" >> "$summary"
            echo >> "$summary"
        fi

        echo "----------------------------------------" >> "$summary"
        echo >> "$summary"
    done < "$web_targets"
}

#############################################
# Upgrade 3: dynamic service-based suggestions
#############################################

append_suggestion_for_port() {
    local host="$1"
    local port="$2"
    local outfile="$3"

    case "$port" in
        21)
            echo "  * FTP on $port: test anonymous login, list files, look for backups, creds, and writable dirs." >> "$outfile"
            ;;
        22)
            echo "  * SSH on $port: inspect banner/version, collect usernames elsewhere first, avoid blind brute forcing." >> "$outfile"
            ;;
        53)
            echo "  * DNS on $port: try zone transfer, inspect records, brute subdomains if hostname context exists." >> "$outfile"
            ;;
        80|81|443|591|593|8000|8008|8080|8081|8088|8443|8888)
            echo "  * Web on $port: inspect source, headers, cookies, tech stack, hidden endpoints, vhosts, and run dir busting." >> "$outfile"
            ;;
        88)
            echo "  * Kerberos on $port: likely AD path. Look for usernames, domain names, SPNs, and LDAP exposure." >> "$outfile"
            ;;
        111|2049)
            echo "  * NFS/RPC on $port: enumerate RPC services and exported shares." >> "$outfile"
            ;;
        139|445)
            echo "  * SMB on $port: enumerate shares, null sessions, users, groups, and domain/workgroup info." >> "$outfile"
            ;;
        389|636)
            echo "  * LDAP on $port: query naming contexts, users, groups, and domain metadata if anonymous bind is allowed." >> "$outfile"
            ;;
        3306)
            echo "  * MySQL on $port: check for weak or default creds, banner leakage, and accessible schemas." >> "$outfile"
            ;;
        5432)
            echo "  * PostgreSQL on $port: test access controls, default roles, and visible databases." >> "$outfile"
            ;;
        6379)
            echo "  * Redis on $port: check if unauthenticated access is possible." >> "$outfile"
            ;;
        27017)
            echo "  * MongoDB on $port: test for exposed databases and weak access controls." >> "$outfile"
            ;;
        3389)
            echo "  * RDP on $port: note for later access if creds are found. Gather OS clues first." >> "$outfile"
            ;;
        5985|5986)
            echo "  * WinRM on $port: note as a likely post-credential access path." >> "$outfile"
            ;;
        *)
            echo "  * Uncommon service on $port: banner grab it, browse it if HTTP-like, and inspect manually." >> "$outfile"
            ;;
    esac
}

generate_next_steps() {
    local map_file="$OUTPUT_DIR/parsed/host_ports.csv"
    local notes="$OUTPUT_DIR/notes/next_steps.txt"

    : > "$notes"

    {
        echo "Dynamic Next Steps"
        echo "=================="
        echo
    } >> "$notes"

    [[ ! -s "$map_file" ]] && { echo "No open ports found, so no dynamic next steps were generated." >> "$notes"; return; }

    while IFS=',' read -r host ports; do
        [[ -z "$host" || -z "$ports" ]] && continue

        {
            echo "$host"
            echo "$(printf '%.0s=' $(seq 1 ${#host}))"
        } >> "$notes"

        IFS=',' read -ra port_array <<< "$ports"
        for p in "${port_array[@]}"; do
            append_suggestion_for_port "$host" "$p" "$notes"
        done

        echo >> "$notes"
    done < "$map_file"
}

#############################################
# Generate summary
#############################################

generate_summary() {
    local summary="$OUTPUT_DIR/summary.txt"

    : > "$summary"

    {
        echo "CTF Recon Summary"
        echo "================="
        echo
        echo "Profile: $PROFILE"
        echo "Output Directory: $OUTPUT_DIR"
        echo "Host Discovery Skipped: $SKIP_DISCOVERY"
        echo "UDP Scan Enabled: $UDP_SCAN"
        echo
        echo "Live Hosts"
        echo "----------"
        cat "$OUTPUT_DIR/parsed/live_hosts.txt" 2>/dev/null || true
        echo
        echo "Open Ports By Host"
        echo "------------------"
        cat "$OUTPUT_DIR/parsed/open_ports_by_host.txt" 2>/dev/null || true
        echo
        echo "Interesting Uncommon Ports"
        echo "--------------------------"
        cat "$OUTPUT_DIR/parsed/odd_ports.txt" 2>/dev/null || true
        echo
        echo "Web Services"
        echo "------------"
        cat "$OUTPUT_DIR/parsed/web_services.txt" 2>/dev/null || true
        echo
        echo "SSH Services"
        echo "------------"
        cat "$OUTPUT_DIR/parsed/ssh_services.txt" 2>/dev/null || true
        echo
        echo "SMB Services"
        echo "------------"
        cat "$OUTPUT_DIR/parsed/smb_services.txt" 2>/dev/null || true
        echo
        echo "FTP Services"
        echo "------------"
        cat "$OUTPUT_DIR/parsed/ftp_services.txt" 2>/dev/null || true
        echo
        echo "Database Services"
        echo "-----------------"
        cat "$OUTPUT_DIR/parsed/db_services.txt" 2>/dev/null || true
        echo
        if [[ -s "$OUTPUT_DIR/web/web_summary.txt" ]]; then
            echo "Web Fingerprinting"
            echo "------------------"
            cat "$OUTPUT_DIR/web/web_summary.txt"
            echo
        fi
        echo "Dynamic Next Steps"
        echo "------------------"
        cat "$OUTPUT_DIR/notes/next_steps.txt" 2>/dev/null || true
    } >> "$summary"

    info "Summary generated: $summary"
}

#############################################
# Final terminal report
#############################################

print_final_report() {
    echo
    info "Recon workflow complete"
    info "Main summary: $OUTPUT_DIR/summary.txt"
    info "Open ports:   $OUTPUT_DIR/parsed/open_ports_by_host.txt"
    info "Next steps:   $OUTPUT_DIR/notes/next_steps.txt"

    if [[ -s "$OUTPUT_DIR/parsed/odd_ports.txt" ]]; then
        echo
        info "Interesting uncommon ports found:"
        cat "$OUTPUT_DIR/parsed/odd_ports.txt"
    fi
}

#############################################
# Main
#############################################

main() {
    parse_args "$@"
    check_dependencies
    setup_output_dirs
    build_target_list
    run_host_discovery
    run_tcp_discovery
    parse_open_ports
    run_service_scan
    run_udp_scan
    classify_services
    run_web_enum
    generate_next_steps
    generate_summary
    print_final_report
}

main "$@"
