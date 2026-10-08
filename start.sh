#!/usr/bin/env bash
# Start the counselor NIDS with one command.
#
#   ./start.sh setup              one-time: Python env, packages, database, login user,
#                                 Snort rules, frontend packages
#   ./start.sh                    dashboard (Redis, Django API :8000, Next.js :3000);
#                                 start replays from the browser
#   ./start.sh live eth0          live: Snort + ML detectors on a network interface, plus the
#                                 dashboard (asks for sudo once: capturing needs root)
#   ./start.sh live file.pcap     the same on a recorded capture (no sudo)
#   ./start.sh --prod [live ...]  the same on production servers: Daphne for the API,
#                                 an optimised Next.js build, DEBUG off, a generated secret key
#
# Ctrl+C stops everything. Logs go to logs/.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
PY="$ROOT/.venv/bin/python"
NIDS="$ROOT/.venv/bin/nids"
LOGS="$ROOT/logs"
API_PORT="${API_PORT:-8000}"
WEB_PORT="${WEB_PORT:-3000}"
export NIDS_REDIS_URL="${NIDS_REDIS_URL:-redis://localhost:6379/0}"
PROD=0
mkdir -p "$LOGS"
# keep logs bounded: a service log past 20 MB is moved to <name>.log.1 (one old copy kept).
# logs/journal/ is data, not a log: `nids journal` prunes it (one year by default).
for log in "$LOGS"/*.log; do
  [[ -f "$log" ]] && (( $(stat -c %s "$log") > 20000000 )) && mv -f "$log" "$log.1"
done

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33m!!\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mxx\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- checks

need_setup() {
  [[ -x "$NIDS" ]] || die "Python environment missing — run: ./start.sh setup"
  [[ -d frontend/node_modules ]] || die "frontend packages missing — run: ./start.sh setup"
}

port_free() { ! ss -ltn "( sport = :$1 )" 2>/dev/null | grep -q ":$1"; }

ensure_redis() {
  if redis-cli -u "$NIDS_REDIS_URL" ping >/dev/null 2>&1; then return; fi
  command -v redis-server >/dev/null || die "Redis is not running and redis-server is not installed"
  say "starting Redis"
  redis-server --port 6379 --daemonize yes --dir "$LOGS" --save "" --logfile "$LOGS/redis.log"
  for _ in $(seq 1 20); do redis-cli -u "$NIDS_REDIS_URL" ping >/dev/null 2>&1 && return; sleep 0.25; done
  die "Redis did not start (see logs/redis.log)"
}

have_models() { compgen -G "models/live/*.joblib" >/dev/null; }

have_user() {
  (cd backend && "$PY" manage.py shell -c \
    "from django.contrib.auth import get_user_model; print(get_user_model().objects.exists())" 2>/dev/null) \
    | grep -q True
}

# ---------------------------------------------------------------- processes

PIDS=()       # everything started (stopped on exit)
SERVICES=()   # long-running services the script watches; one-shot jobs are not in here
SUDO_PIDS=()

STOPPING=0
cleanup() {
  (( STOPPING )) && return
  STOPPING=1
  trap '' TERM
  echo
  say "stopping"
  # root-owned capture processes need sudo to be signalled
  for pid in "${SUDO_PIDS[@]}"; do sudo kill -TERM "$pid" 2>/dev/null || true; done
  # everything else, children included (next dev starts its own server process):
  # the whole process group, which a terminal gives to this script alone
  kill -TERM 0 2>/dev/null || true
  wait 2>/dev/null || true
}

run_bg() {  # run_bg <log name> <command...>   (a job that may finish on its own)
  local name=$1; shift
  "$@" >"$LOGS/$name.log" 2>&1 &
  PIDS+=($!)
}

run_service() {  # like run_bg, but watched: if it dies, everything stops
  run_bg "$@"
  SERVICES+=("${PIDS[-1]}")
}

run_bg_sudo() {
  local name=$1; shift
  sudo --preserve-env=NIDS_REDIS_URL "$@" >"$LOGS/$name.log" 2>&1 &
  SUDO_PIDS+=($!)
}

wait_http() {  # wait_http <url> <name>
  for _ in $(seq 1 120); do
    curl -s -o /dev/null "$1" && return
    sleep 0.5
  done
  die "$2 did not start (see logs/)"
}

start_dashboard() {
  port_free "$API_PORT" || die "port $API_PORT is in use (set API_PORT=...)"
  port_free "$WEB_PORT" || die "port $WEB_PORT is in use (set WEB_PORT=...)"
  (cd backend && "$PY" manage.py migrate --noinput -v 0)
  if ! have_user; then
    say "no dashboard login yet — create one"
    (cd backend && "$PY" manage.py createsuperuser)
  fi
  export CORS_ALLOWED_ORIGINS="http://localhost:$WEB_PORT" NEXT_PUBLIC_API_URL="http://localhost:$API_PORT"
  if (( PROD )); then
    prepare_prod
    say "starting API (Daphne) on :$API_PORT and dashboard (production build) on :$WEB_PORT"
    run_service api bash -c "cd backend && exec '$ROOT/.venv/bin/daphne' -b 127.0.0.1 -p $API_PORT config.asgi:application"
    run_service web bash -c "cd frontend && exec npx next start -p $WEB_PORT"
  else
    say "starting API on :$API_PORT and dashboard on :$WEB_PORT"
    run_service api bash -c "cd backend && exec '$PY' manage.py runserver 127.0.0.1:$API_PORT --noreload"
    run_service web bash -c "cd frontend && exec npx next dev -p $WEB_PORT"
  fi
  wait_http "http://127.0.0.1:$API_PORT/api/auth/me/" "API"
  wait_http "http://localhost:$WEB_PORT/login" "dashboard"
}

prepare_prod() {
  # A secret key generated once and kept in backend/.env (git-ignored, owner-only).
  if ! grep -q '^DJANGO_SECRET_KEY=' backend/.env 2>/dev/null; then
    say "generating a secret key in backend/.env"
    (umask 077; printf 'DJANGO_SECRET_KEY=%s\n' "$("$PY" -c 'import secrets; print(secrets.token_urlsafe(50))')" >> backend/.env)
  fi
  export DJANGO_DEBUG=0
  # Secure cookies need HTTPS; locally the dashboard is plain http. Put a TLS proxy in
  # front and set AUTH_COOKIE_SECURE=1 when serving to other machines.
  export AUTH_COOKIE_SECURE="${AUTH_COOKIE_SECURE:-0}"
  (cd backend && "$PY" manage.py collectstatic --noinput -v 0)
  say "building the dashboard (production)"
  (cd frontend && npx next build >"$LOGS/web-build.log" 2>&1) || die "dashboard build failed (see logs/web-build.log)"
}

watch() {  # keep running until Ctrl+C or a service dies
  say "dashboard: http://localhost:$WEB_PORT   (logs in logs/, Ctrl+C to stop)"
  while true; do
    for pid in "${SERVICES[@]}"; do
      if ! kill -0 "$pid" 2>/dev/null; then
        # Ctrl+C reaches the services too; give its handler a moment to run first
        sleep 0.5 & wait $! || true
        warn "a service stopped — see logs/"
        return
      fi
    done
    sleep 2 & wait $! || true  # interruptible, so Ctrl+C is handled at once
  done
}

on_signals() {
  trap 'cleanup; exit 130' INT TERM
  trap cleanup EXIT
}

# ---------------------------------------------------------------- commands

cmd_setup() {
  say "Python environment"
  [[ -x "$PY" ]] || python3 -m venv .venv
  "$PY" -m pip install -q --upgrade pip
  "$PY" -m pip install -q -e ".[web,live]"

  say "frontend packages"
  (cd frontend && npm install --no-audit --no-fund)

  ensure_redis
  say "database"
  (cd backend && "$PY" manage.py migrate --noinput -v 0)
  have_user || (cd backend && "$PY" manage.py createsuperuser)

  if have_models; then
    say "live detectors found in models/live/ (shipped with the repository)"
  else
    warn "no live detectors in models/live/ — restore them (git checkout models/live) or rebuild them:"
    warn "  .venv/bin/pip install -e '.[train]' && see 'Live detectors' in README.md"
  fi

  [[ -f snort/rules/community/snort3-community.rules ]] || {
    say "Snort 3 community rules"
    mkdir -p snort/rules/community
    curl -fsSL https://www.snort.org/downloads/community/snort3-community-rules.tar.gz \
      | tar xz -C snort/rules/community --strip-components=1 \
      || warn "could not download the community rules — Snort will use snort/rules/nids.rules only"
  }
  command -v snort >/dev/null || warn "Snort is not installed — live mode will run the ML only"
  say "done — now run: ./start.sh"
}

cmd_dashboard() {
  need_setup
  ensure_redis
  have_models || warn "no live detectors in models/live/ — run ./start.sh setup"
  on_signals
  start_dashboard
  watch
}

cmd_live() {
  local target=${1:-}
  [[ -n "$target" ]] || die "usage: ./start.sh live <interface | file.pcap>"
  need_setup
  have_models || die "no live detectors in models/live/ — run ./start.sh setup"
  ensure_redis

  local capture=(run_bg)
  if [[ "$target" == *.pcap || "$target" == *.pcapng ]]; then
    [[ -f "$target" ]] || die "no such capture: $target"
    target="$(realpath "$target")"
  else
    ip link show "$target" >/dev/null 2>&1 || die "no network interface '$target' (see: ip link)"
    say "capturing on $target needs root — sudo will ask once"
    sudo -v
    capture=(run_bg_sudo)
  fi

  # model files are pickles, so loading one runs code: only load the promoted, checksummed set
  [[ -f models/live/SHA256SUMS ]] && (cd models/live && sha256sum --quiet -c SHA256SUMS) \
    || die "models/live/ does not match its SHA256SUMS — restore it (git checkout models/live) or retrain"
  local models=(models/live/*.joblib)
  local snort=1
  command -v snort >/dev/null || { warn "Snort is not installed — running the ML only"; snort=0; }

  on_signals
  "$NIDS" reset >/dev/null
  start_dashboard

  say "starting observer and ${#models[@]} detectors"
  run_service observer "$NIDS" observe
  # live alerts are also kept in logs/journal/ — `nids journal-report` gives the false-alarm rate
  [[ "$target" == /* ]] || run_service journal "$NIDS" journal
  for model in "${models[@]}"; do
    run_service "detect-$(basename "$model" .joblib)" "$NIDS" detect "$model" --sources live --cross-check --suppress-fallback
  done
  if (( snort )); then
    say "starting Snort on $target"
    if [[ "$target" == /* ]]; then
      "${capture[@]}" snort "$NIDS" snort --pcap "$target"
    else
      "${capture[@]}" snort "$NIDS" snort --interface "$target"
    fi
  fi
  say "capturing flows from $target"
  "${capture[@]}" extractor "$NIDS" extract --live "$target" --source live --wait-for "${#models[@]}"
  [[ "$target" == /* ]] || warn "live flows appear when connections end or time out, so expect a short delay"
  watch
}

if [[ "${1:-}" == "--prod" ]]; then
  PROD=1
  shift
fi

case "${1:-}" in
  setup) cmd_setup ;;
  live) shift; cmd_live "$@" ;;
  ""|dashboard) cmd_dashboard ;;
  -h|--help|help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//' ;;
  *) die "unknown command '$1' — see ./start.sh --help" ;;
esac
