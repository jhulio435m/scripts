#!/bin/bash
set -u

INTERVALO=60
TORRC="/etc/tor/torrc"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()  { echo -e "${BLUE}[*] $1${NC}"; }
ok()    { echo -e "${GREEN}[+] $1${NC}"; }
warn()  { echo -e "${YELLOW}[!] $1${NC}"; }
error() { echo -e "${RED}[x] $1${NC}"; }

check_deps() {
  local missing=0
  for cmd in nc curl sed grep sudo; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      error "Falta dependencia: $cmd"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
}

edit_torrc() {
  info "Abriendo configuración de Tor con sudo..."
  sudo ${EDITOR:-nano} "$TORRC"
}

show_tor_hints() {
  cat <<'EOF'

Asegúrate de revisar en /etc/tor/torrc algo como esto:

ControlPort 9051
CookieAuthentication 0

Si usas autenticación por contraseña o cookie, tu script debe adaptarse.
Luego reinicia Tor:
  sudo systemctl restart tor

EOF
}

check_controlport() {
  if nc -z 127.0.0.1 9051; then
    ok "Tor ControlPort responde en 127.0.0.1:9051"
  else
    error "Tor ControlPort (9051) no responde."
    warn "Revisa $TORRC y el estado del servicio Tor."
    exit 1
  fi
}

send_newnym() {
  printf 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n' | nc 127.0.0.1 9051 >/dev/null 2>&1
}

get_ip_info() {
  local info_resp ip country
  info_resp="$(curl -fsS --connect-timeout 10 https://api.ipify.org 2>/dev/null)" || return 1
  ip="$info_resp"

  country="$(curl -fsS --connect-timeout 10 "https://ipapi.co/${ip}/country_name/" 2>/dev/null)" || country="Desconocido"

  if [ -n "$ip" ]; then
    echo "$ip|$country"
    return 0
  fi
  return 1
}

rotate_once() {
  info "Solicitando nueva identidad a Tor..."
  if send_newnym; then
    ok "Señal NEWNYM enviada."
    info "Esperando 10 segundos..."
    sleep 10
  else
    error "No se pudo enviar NEWNYM al ControlPort."
    return 1
  fi

  local result ip country
  result="$(get_ip_info)" || {
    error "No se pudo obtener IP actual."
    return 1
  }

  ip="${result%%|*}"
  country="${result#*|}"

  ok "IP actual: $ip | País: $country"
}

usage() {
  cat <<EOF
Uso: $0 [opción]

Opciones:
  --edit-config   Abrir /etc/tor/torrc con sudo
  --show-hints    Mostrar ejemplo de configuración útil
  --check         Verificar dependencias y ControlPort
  --once          Ejecutar una sola rotación y mostrar IP
  --loop          Ejecutar en bucle cada ${INTERVALO}s
EOF
}

main() {
  check_deps

  case "${1:-}" in
    --edit-config)
      edit_torrc
      ;;
    --show-hints)
      show_tor_hints
      ;;
    --check)
      check_controlport
      ;;
    --once)
      check_controlport
      rotate_once
      ;;
    --loop)
      check_controlport
      info "=== Rotación de identidad Tor ==="
      while true; do
        echo
        echo "--------------------------------------"
        rotate_once || warn "La rotación o la consulta de IP falló."
        info "Próxima verificación en ${INTERVALO}s..."
        sleep "$INTERVALO"
      done
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
