#!/usr/bin/env bash
# Install the Counselor NIDS as systemd services, so live monitoring starts at boot, restarts
# any part that crashes, and is checked every minute.
#
#   sudo deploy/install-systemd.sh wlan0          install and start, watching wlan0
#   sudo deploy/install-systemd.sh --uninstall    stop and remove the services
#
# Services run as the user who owns this folder, not root: capture and Snort get only the
# two network capabilities they need. Logs go to the system journal:
#   journalctl -u 'nids-*' -f            follow everything
#   systemctl status nids.target          what is running
#   journalctl -u nids-health             the minute-by-minute health check
# Needs ./start.sh setup to have run (Python env, packages, models, dashboard login).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
UNITS=/etc/systemd/system
ENV_DIR=/etc/nids

die() { printf '\033[31mxx\033[0m %s\n' "$*" >&2; exit 1; }
say() { printf '\033[1m==>\033[0m %s\n' "$*"; }

[[ $EUID -eq 0 ]] || die "run with sudo"

if [[ "${1:-}" == "--uninstall" ]]; then
  systemctl disable --now nids.target nids-health.timer 2>/dev/null || true
  systemctl stop 'nids-*' 2>/dev/null || true
  rm -f "$UNITS"/nids.target "$UNITS"/nids-*.service "$UNITS"/nids-*.timer
  rm -rf "$UNITS"/nids.target.wants
  systemctl daemon-reload
  say "removed (settings kept in $ENV_DIR)"
  exit 0
fi

INTERFACE="${1:-}"
[[ -n "$INTERFACE" ]] || die "usage: sudo $0 <interface>   (ip link lists them)"
[[ -e "/sys/class/net/$INTERFACE" ]] || die "no network interface called $INTERFACE"
USER_NAME="$(stat -c %U "$ROOT")"
[[ -x "$ROOT/.venv/bin/nids" ]] || die "Python environment missing — run ./start.sh setup first"
compgen -G "$ROOT/models/live/*.joblib" >/dev/null || die "no live detectors in models/live/"
(cd "$ROOT/models/live" && sha256sum --quiet -c SHA256SUMS) || die "models/live/ does not match SHA256SUMS"
NPX="$(sudo -u "$USER_NAME" bash -lc 'command -v npx')" || die "npx not found for $USER_NAME"
REDIS_UNIT=$(systemctl list-unit-files --no-legend 'redis*.service' | awk '{print $1}' | grep -m1 -E '^redis(-server)?\.service$') \
  || die "no Redis service installed (apt install redis-server)"

mapfile -t MODELS < <(cd "$ROOT/models/live" && ls *.joblib | sed 's/\.joblib$//')

say "settings in $ENV_DIR/nids.env"
mkdir -p "$ENV_DIR"
if [[ ! -f "$ENV_DIR/nids.env" ]]; then
  cat > "$ENV_DIR/nids.env" <<EOF
NIDS_REDIS_URL=redis://localhost:6379/0
NIDS_ROOT=$ROOT
DJANGO_DEBUG=0
AUTH_COOKIE_SECURE=0
CORS_ALLOWED_ORIGINS=http://localhost:3000
NEXT_PUBLIC_API_URL=http://localhost:8000
EOF
fi

if ! grep -q '^DJANGO_SECRET_KEY=' "$ROOT/backend/.env" 2>/dev/null; then
  say "generating a secret key in backend/.env"
  sudo -u "$USER_NAME" bash -c "umask 077; printf 'DJANGO_SECRET_KEY=%s\n' \"\$('$ROOT/.venv/bin/python' -c 'import secrets; print(secrets.token_urlsafe(50))')\" >> '$ROOT/backend/.env'"
fi

say "building the dashboard"
sudo -u "$USER_NAME" bash -lc "cd '$ROOT/backend' && set -a && . $ENV_DIR/nids.env && set +a && ../.venv/bin/python manage.py collectstatic --noinput -v 0"
sudo -u "$USER_NAME" bash -lc "cd '$ROOT/frontend' && set -a && . $ENV_DIR/nids.env && set +a && npx next build" >/dev/null

say "installing units for $INTERFACE (user $USER_NAME, ${#MODELS[@]} detectors: ${MODELS[*]})"
for unit in "$ROOT"/deploy/systemd/*; do
  sed -e "s|@ROOT@|$ROOT|g" -e "s|@USER@|$USER_NAME|g" -e "s|@INTERFACE@|$INTERFACE|g" \
      -e "s|@DETECTORS@|${#MODELS[@]}|g" -e "s|@NPX@|$NPX|g" \
      -e "s|redis-server.service|$REDIS_UNIT|g" "$unit" > "$UNITS/$(basename "$unit")"
done
systemctl daemon-reload
systemctl enable "$REDIS_UNIT" nids.target nids-api nids-web nids-capture nids-observer nids-snort \
  nids-journal nids-health.timer "${MODELS[@]/#/nids-detector@}" >/dev/null
systemctl restart nids.target
say "started — dashboard on http://localhost:3000; status: systemctl status nids.target"
