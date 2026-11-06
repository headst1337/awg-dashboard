#!/usr/bin/env bash
set -Eeuo pipefail

REPOSITORY_URL="${AWG_DASHBOARD_REPO_URL:-https://github.com/headst1337/awg-dashboard.git}"
REPOSITORY_REF="${AWG_DASHBOARD_REF:-main}"
APP_DIR="${AWG_DASHBOARD_APP_DIR:-/opt/awg-dashboard}"
STATE_DIR="/var/lib/awg-dashboard"
CONFIG_DIR="/etc/awg-dashboard"
ENV_FILE="$CONFIG_DIR/api.env"
SERVICE_FILE="/etc/systemd/system/awg-dashboard-api.service"

if [[ "$EUID" -ne 0 ]]; then
    echo "Run this installer as root (for example: curl ... | sudo bash)." >&2
    exit 1
fi

for command in curl git systemctl docker; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Required command not found: $command" >&2
        exit 1
    fi
done

if ! docker info >/dev/null 2>&1; then
    echo "Docker Engine is not accessible to root. Start/check Docker first." >&2
    exit 1
fi

UV_BIN="$(command -v uv || true)"
if [[ -z "$UV_BIN" ]]; then
    echo "Installing uv..."
    curl --proto '=https' --tlsv1.2 -fsSL https://astral.sh/uv/install.sh \
        | env UV_INSTALL_DIR=/usr/local/bin UV_NO_MODIFY_PATH=1 sh
    UV_BIN="/usr/local/bin/uv"
fi
if [[ ! -x "$UV_BIN" ]]; then
    echo "uv installation failed; executable not found at $UV_BIN" >&2
    exit 1
fi

if [[ -d "$APP_DIR/.git" ]]; then
    current_origin="$(git -C "$APP_DIR" remote get-url origin)"
    if [[ "$current_origin" != "$REPOSITORY_URL" ]]; then
        echo "Existing checkout at $APP_DIR has a different origin: $current_origin" >&2
        exit 1
    fi
    git -C "$APP_DIR" pull --ff-only origin "$REPOSITORY_REF"
elif [[ -e "$APP_DIR" ]]; then
    echo "Refusing to use non-Git install directory: $APP_DIR" >&2
    exit 1
else
    git clone \
        --depth 1 \
        --filter=blob:none \
        --sparse \
        --branch "$REPOSITORY_REF" \
        "$REPOSITORY_URL" \
        "$APP_DIR"
    git -C "$APP_DIR" sparse-checkout set \
        src pyproject.toml uv.lock README.md .python-version
fi

cd "$APP_DIR"
UV_PYTHON_DOWNLOADS=automatic "$UV_BIN" sync --frozen --no-dev

install -d -m 0700 "$CONFIG_DIR" "$STATE_DIR"
chmod 0700 "$CONFIG_DIR"
chmod 0700 "$STATE_DIR"
umask 077
touch "$ENV_FILE"
chmod 0600 "$ENV_FILE"

ensure_setting() {
    local name="$1"
    local value="$2"
    if ! grep -q "^${name}=" "$ENV_FILE"; then
        printf '%s=%s\n' "$name" "$value" >>"$ENV_FILE"
    fi
}

if grep -q '^AWG_DASHBOARD_API_TOKEN=' "$ENV_FILE"; then
    if ! grep -q '^AWG_DASHBOARD_API_TOKEN=.' "$ENV_FILE"; then
        echo "API token is present but empty in $ENV_FILE" >&2
        exit 1
    fi
else
    api_token="$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')"
    printf 'AWG_DASHBOARD_API_TOKEN=%s\n' "$api_token" >>"$ENV_FILE"
    echo "Generated a new API bearer token. It is stored in $ENV_FILE."
fi
ensure_setting AWG_DASHBOARD_HOST "127.0.0.1"
ensure_setting AWG_DASHBOARD_PORT "8000"

cat >"$SERVICE_FILE" <<UNIT
[Unit]
Description=AWG Dashboard API
After=network-online.target docker.service
Wants=network-online.target docker.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$APP_DIR
EnvironmentFile=$ENV_FILE
Environment=PYTHONDONTWRITEBYTECODE=1
UMask=0077
ExecStart=$APP_DIR/.venv/bin/uvicorn awg_dashboard.api:app --host=\${AWG_DASHBOARD_HOST} --port=\${AWG_DASHBOARD_PORT}
Restart=on-failure
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$STATE_DIR
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6

[Install]
WantedBy=multi-user.target
UNIT

chmod 0644 "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable awg-dashboard-api.service
systemctl restart awg-dashboard-api.service

echo
echo "AWG Dashboard API is running at http://127.0.0.1:8000"
echo "API token is stored in: $ENV_FILE (root-readable only)"
echo "Check: systemctl status awg-dashboard-api.service"
echo "Logs:  journalctl -u awg-dashboard-api.service -f"
echo "The API binds to localhost by default; use SSH forwarding or a TLS reverse proxy."
