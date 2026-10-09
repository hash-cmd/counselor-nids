#!/bin/sh
# One-command API startup: make a stable secret, set up the database, create the
# dashboard login if it doesn't exist yet, then serve. Everything here is safe to
# run on every start.
set -e
cd /app/backend

DB_DIR="$(dirname "${DJANGO_DB_PATH:-/db/db.sqlite3}")"
mkdir -p "$DB_DIR"

# A secret key that survives restarts (generated once, kept in the db volume).
if [ -z "${DJANGO_SECRET_KEY:-}" ]; then
  KEYFILE="$DB_DIR/secret_key"
  if [ ! -f "$KEYFILE" ]; then
    python -c "import secrets; print(secrets.token_urlsafe(50))" > "$KEYFILE"
  fi
  DJANGO_SECRET_KEY="$(cat "$KEYFILE")"
  export DJANGO_SECRET_KEY
fi

python manage.py migrate --noinput
python manage.py collectstatic --noinput -v 0

# Create the dashboard login on first run (change the password after signing in).
USER="${DJANGO_SUPERUSER_USERNAME:-admin}"
PASS="${DJANGO_SUPERUSER_PASSWORD:-admin}"
MAIL="${DJANGO_SUPERUSER_EMAIL:-admin@example.com}"
python - "$USER" "$PASS" "$MAIL" <<'PY'
import os
import sys
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")
django.setup()
from django.contrib.auth import get_user_model

name, password, email = sys.argv[1:4]
User = get_user_model()
if not User.objects.filter(username=name).exists():
    User.objects.create_superuser(name, email, password)
    print(f"created dashboard login '{name}' (change its password after signing in)")
else:
    print(f"dashboard login '{name}' already exists")
PY

exec daphne -b 0.0.0.0 -p 8000 config.asgi:application
