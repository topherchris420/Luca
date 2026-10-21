#!/usr/bin/env bash
# Installs, rebuilds or removes Luca's optional kernel observatory.
#
#   sudo bash /usr/share/luca/observatory/scripts/install-observatory.sh            install and enable
#   sudo bash /usr/share/luca/observatory/scripts/install-observatory.sh --rebuild  rebuild the collector
#   sudo bash /usr/share/luca/observatory/scripts/install-observatory.sh --uninstall
#
# Nothing here runs unless an administrator asks for it: Luca's main
# installer only calls this script after an explicit "yes".
set -euo pipefail

LUCA_DIR="${LUCA_DIR:-/usr/share/luca}"
OBS_DIR="$LUCA_DIR/observatory"
UNIT=/lib/systemd/system/luca-observatory.service
SERVICE_USER=luca-observatory
PACKAGES=(clang llvm libbpf-dev libelf-dev zlib1g-dev make gcc pkg-config git)

info() { echo -e "\e[39m[+] $*\e[39m"; }
ok() { echo -e "\e[92m    [✔] $*\e[39m"; }
warn() { echo -e "\e[93m    [!] $*\e[39m"; }

set_enabled() {
    # Only the "enabled" key of the observatory section.
    sed -i "/^observatory:/,/^[^ #]/ s/^\(  enabled:\) .*/\1 $1/" "$LUCA_DIR/config.yaml"
}

build() {
    info "Building the collector"
    make -C "$OBS_DIR" clean >/dev/null
    make -C "$OBS_DIR"
    ok "collector built in $OBS_DIR/build"
}

install() {
    if [[ "$(uname -s)" != "Linux" ]]; then
        echo "The kernel observatory needs Linux." >&2
        exit 1
    fi
    info "Checking the kernel"
    bash "$OBS_DIR/scripts/check-host.sh" || warn "check-host.sh reported problems; the service will report them too"

    info "Installing build dependencies: ${PACKAGES[*]}"
    apt-get install -y "${PACKAGES[@]}"
    build

    info "Creating the $SERVICE_USER system user"
    getent group "$SERVICE_USER" >/dev/null || groupadd --system "$SERVICE_USER"
    id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --gid "$SERVICE_USER" --no-create-home \
        --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
    ok "user $SERVICE_USER"

    info "Installing the luca-observatory service"
    chmod 0755 "$OBS_DIR/luca-observatoryd"
    install -m 0644 "$OBS_DIR/systemd/luca-observatory.service" "$UNIT"
    set_enabled true
    systemctl daemon-reload
    systemctl enable luca-observatory &>/dev/null
    systemctl restart luca-observatory
    ok "service enabled; settings are read from observatory: in $LUCA_DIR/config.yaml"
    echo "    After changing those settings, run: sudo systemctl restart luca-observatory"
}

uninstall() {
    info "Removing the luca-observatory service"
    if [[ -f "$UNIT" ]]; then
        systemctl disable --now luca-observatory &>/dev/null || true
        rm -f "$UNIT"
        systemctl daemon-reload
    fi
    id -u "$SERVICE_USER" >/dev/null 2>&1 && userdel "$SERVICE_USER" || true
    getent group "$SERVICE_USER" >/dev/null && groupdel "$SERVICE_USER" || true
    rm -rf /var/lib/luca-observatory
    if [[ -f "$LUCA_DIR/config.yaml" ]]; then
        set_enabled false
    fi
    ok "observatory removed (build dependencies are left installed)"
}

if [[ $EUID -ne 0 ]]; then
    echo "Run as root: sudo bash $0 [--rebuild|--uninstall]" >&2
    exit 1
fi
case "${1:-}" in
    "") install ;;
    --rebuild) build; systemctl try-restart luca-observatory || true ;;
    --uninstall) uninstall ;;
    *) echo "usage: $0 [--rebuild|--uninstall]" >&2; exit 1 ;;
esac
