#!/usr/bin/env bash
# Luca updater. Requires Git access to the Luca repository, which may be private.
set -euo pipefail

APP_DIR="/usr/share/luca"
SOURCE_REPO="${LUCA_SOURCE_REPO:-https://github.com/topherchris420/Luca.git}"
if [[ "${EUID}" -ne 0 ]]; then
  echo "Run with sudo: sudo bash $0" >&2
  exit 1
fi
if [[ ! -f "$APP_DIR/config.yaml" ]]; then
  echo "Luca is not installed at $APP_DIR" >&2
  exit 1
fi
if ! command -v git >/dev/null; then
  echo "Git is required for updates." >&2
  exit 1
fi

# Never remove a working installation if cloning fails.
STAGING="$(mktemp -d /tmp/luca-update.XXXXXXXX)"
trap 'rm -rf "$STAGING"' EXIT
git clone --depth 1 "$SOURCE_REPO" "$STAGING/source"
for dir in analysis app server assets; do
  test -d "$STAGING/source/$dir" || { echo "Missing source directory: $dir" >&2; exit 1; }
done
python3 -m pip install -r "$STAGING/source/assets/requirements.txt"

# Build prior to replacing the installed applications.
for ui in frontend backend; do
  (cd "$STAGING/source/app/$ui" && npm install && npm run build)
done

# Retain local configuration, indicator database and TLS certificate.
# Preserve installed TLS credentials before replacing server files.
mkdir -p "$STAGING/tls"
for f in cert.pem key.pem; do
  if [[ -f "$APP_DIR/server/backend/$f" ]]; then cp "$APP_DIR/server/backend/$f" "$STAGING/tls/$f"; fi
done

for dir in analysis app server assets; do
  rm -rf "$APP_DIR/$dir"
  cp -a "$STAGING/source/$dir" "$APP_DIR/$dir"
done
for f in cert.pem key.pem; do
  if [[ -f "$STAGING/tls/$f" ]]; then cp "$STAGING/tls/$f" "$APP_DIR/server/backend/$f"; fi
done
for f in install.sh update.sh uninstall.sh kiosk.sh; do
  cp "$STAGING/source/$f" "$APP_DIR/$f"
done

# Keep NOTICE and LICENSE with the installed derivative distribution.
cp "$STAGING/source/NOTICE.txt" "$APP_DIR/NOTICE.txt"
cp "$STAGING/source/LICENSE.txt" "$APP_DIR/LICENSE.txt"

git -C "$STAGING/source" rev-parse --short HEAD > "$APP_DIR/VERSION"
systemctl restart luca-backend luca-frontend luca-watchers
echo "Luca updated."
