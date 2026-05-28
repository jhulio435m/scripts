#!/bin/bash
set -u

INTERVALO=60
TORRC="/opt/tools/network/nipe/.configs/arch-torrc"
SOCKS="127.0.0.1:9050"

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
  for cmd in nc curl sed grep; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      error "Falta dependencia: $cmd"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ] || exit 1
}

edit_torrc() {
  if command -v sudo &>/dev/null; then
    sudo ${EDITOR:-nano} "$TORRC"
  else
    ${EDITOR:-nano} "$TORRC"
  fi
}

show_tor_hints() {
  cat <<'EOF'
Asegúrate de que el torrc tenga:

ControlPort 9051
CookieAuthentication 0
SOCKSPort 9050

Luego reiniciá Tor:
  sudo killall tor; cd /opt/tools/network/nipe && sudo tor -f .configs/arch-torrc
EOF
}

check_controlport() {
  if nc -z 127.0.0.1 9051; then
    ok "Tor ControlPort responde en 127.0.0.1:9051"
  else
    error "Tor ControlPort (9051) no responde."
    warn "Ejecutá: cd /opt/tools/network/nipe && sudo tor -f .configs/arch-torrc"
    exit 1
  fi
}

send_newnym() {
  printf 'AUTHENTICATE ""\r\nSIGNAL NEWNYM\r\nQUIT\r\n' | nc 127.0.0.1 9051 >/dev/null 2>&1
}

check_ipv6_leak() {
  local v6
  v6="$(curl -6 -fsS --connect-timeout 5 https://api.ipify.org 2>/dev/null)" || return 0
  if [ -n "$v6" ]; then
    warn "IPv6 detectada: $v6 — tu IP real está expuesta!"
    warn "Usá --secure para bloquear IPv6 o --unsecure para restaurarla"
    return 1
  fi
  return 0
}

block_ipv6() {
  if command -v ip6tables &>/dev/null; then
    sudo ip6tables -F OUTPUT 2>/dev/null
    sudo ip6tables -A OUTPUT -o lo -j ACCEPT 2>/dev/null
    sudo ip6tables -A OUTPUT -j REJECT 2>/dev/null
    ok "IPv6 bloqueado con ip6tables"
  fi
}

unblock_ipv6() {
  if command -v ip6tables &>/dev/null; then
    sudo ip6tables -F OUTPUT 2>/dev/null
    sudo ip6tables -P OUTPUT ACCEPT 2>/dev/null
    ok "IPv6 restaurado"
  fi
}

tor_start() {
  if nc -z 127.0.0.1 9051; then
    ok "Tor ya está corriendo"
    return 0
  fi
  info "Iniciando Tor..."
  cd /opt/tools/network/nipe && sudo tor -f .configs/arch-torrc >/dev/null 2>&1
  sleep 2
  if nc -z 127.0.0.1 9051; then
    ok "Tor iniciado"
  else
    error "No se pudo iniciar Tor"
    return 1
  fi
}

tor_stop() {
  if command -v killall &>/dev/null; then
    sudo killall tor 2>/dev/null
    ok "Tor detenido"
  fi
}

redirect_v4() {
  local tor_uid
  tor_uid="$(id -u tor 2>/dev/null || echo 0)"

  sudo iptables -t nat -F OUTPUT 2>/dev/null

  # DNS through Tor
  sudo iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 9061
  sudo iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 9061

  # Don't redirect Tor's own traffic
  sudo iptables -t nat -A OUTPUT -m owner --uid-owner "$tor_uid" -j RETURN

  # Don't redirect local/private ranges
  sudo iptables -t nat -A OUTPUT -d 127.0.0.1/8 -j RETURN
  sudo iptables -t nat -A OUTPUT -d 192.168.0.0/16 -j RETURN
  sudo iptables -t nat -A OUTPUT -d 172.16.0.0/12 -j RETURN
  sudo iptables -t nat -A OUTPUT -d 10.0.0.0/8 -j RETURN

  # Don't redirect the TransPort itself (loop prevention)
  sudo iptables -t nat -A OUTPUT -p tcp --dport 9040 -j RETURN

  # Redirect all TCP through Tor TransPort
  sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-ports 9040

  # Block all other UDP (covers WebRTC, QUIC, etc.)
  sudo iptables -t filter -F OUTPUT 2>/dev/null
  sudo iptables -t filter -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  sudo iptables -t filter -A OUTPUT -o lo -j ACCEPT
  sudo iptables -t filter -A OUTPUT -p udp --dport 53 -j ACCEPT
  sudo iptables -t filter -A OUTPUT -p tcp -j ACCEPT
  sudo iptables -t filter -A OUTPUT -j REJECT

  ok "IPv4 redirigido por Tor (TransPort 9040) + UDP bloqueado"
}

restore_v4() {
  sudo iptables -t nat -F OUTPUT 2>/dev/null
  sudo iptables -t filter -F OUTPUT 2>/dev/null
  sudo iptables -t filter -P OUTPUT ACCEPT 2>/dev/null
  ok "IPv4 restaurado"
}

get_ip_info() {
  local info_resp ip country
  info_resp="$(curl -fsS --connect-timeout 10 --socks5-hostname "$SOCKS" https://api.ipify.org 2>/dev/null)" || return 1
  ip="$info_resp"

  country="$(curl -fsS --connect-timeout 10 --socks5-hostname "$SOCKS" "https://ipapi.co/${ip}/country_name/" 2>/dev/null)" || country="Desconocido"

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
Uso: dinamic-ip [opción]

Opciones:
  --edit-config   Abrir torrc con sudo
  --show-hints    Mostrar ejemplo de configuración
  --check         Verificar dependencias y ControlPort
  --once          Rotar IP y mostrar nueva
  --loop          Rotar IP cada ${INTERVALO}s (bucle)
  --on            Iniciar Tor + redirigir IPv4 + bloquear IPv6
  --off           Restaurar IPv4 + IPv6 + detener Tor
  --checkv6       Verificar si hay leak de IPv6
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
      check_ipv6_leak
      while true; do
        echo
        echo "--------------------------------------"
        rotate_once || warn "La rotación o la consulta de IP falló."
        info "Próxima verificación en ${INTERVALO}s..."
        sleep "$INTERVALO"
      done
      ;;
    --on)
      tor_start && redirect_v4 && block_ipv6
      info "IPv4 ahora: $(curl -fsS --connect-timeout 10 --socks5-hostname "$SOCKS" https://api.ipify.org 2>/dev/null || echo 'verificando...')"
      ;;
    --off)
      restore_v4 && unblock_ipv6 && tor_stop
      ok "Todo restaurado — IP original visible"
      ;;
    --checkv6)
      check_ipv6_leak
      ;;
    *)
      usage
      ;;
  esac
}

main "$@"
