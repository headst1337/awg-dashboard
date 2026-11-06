# AWG Dashboard mechanisms

This project contains a FastAPI service and Python mechanisms for managing an
AmneziaWG server through the local Docker Engine. It does not include a UI or a
Dockerfile for the API service.

`AwgManager` exposes install, status, settings update, image upgrade, client
create/list/revoke, native client `.conf` export, and SVG QR generation. The
manager uses `DockerRuntime` for local Docker Engine operations and `StateStore`
for persistent configuration and client metadata. The HTTP API exposes those
operations under `/api/v1`.

## API

All `/api/v1` routes require an `Authorization: Bearer <token>` header.

- `GET /api/v1/status`
- `POST /api/v1/server/install`
- `PUT /api/v1/server/settings`
- `POST /api/v1/server/upgrade`
- `GET|POST /api/v1/clients`
- `GET /api/v1/clients/{client_id}/config`
- `GET /api/v1/clients/{client_id}/qr.svg`
- `DELETE /api/v1/clients/{client_id}`
- `GET /healthz` (process health; no authentication)

Interactive API documentation is available at `/docs`.

Example request body for installation:

```json
{"endpoint_host": "vpn.example.com"}
```

## Install on a Linux server

After this repository version has been pushed to the `main` branch, install and
start the systemd service with:

```sh
curl -fsSL https://raw.githubusercontent.com/headst1337/awg-dashboard/main/scripts/install.sh | sudo bash
```

The installer checks Docker, clones/updates a shallow sparse checkout in
`/opt/awg-dashboard`, installs `uv` and the Python dependencies, generates a
bearer token, and enables `awg-dashboard-api.service`. It does not install or
start an AWG server. The token is stored in
`/etc/awg-dashboard/api.env` (mode `0600`); retrieve it with:

```sh
sudo sed -n 's/^AWG_DASHBOARD_API_TOKEN=//p' /etc/awg-dashboard/api.env
```

Use the token for authenticated requests:

```sh
TOKEN="$(sudo sed -n 's/^AWG_DASHBOARD_API_TOKEN=//p' /etc/awg-dashboard/api.env)"
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/status
```

The API binds to `127.0.0.1:8000` by default. For remote access, use an SSH
tunnel or a TLS-terminating reverse proxy; do not expose the service directly
to the internet. The service runs as root so it can control Docker. Possession
of its bearer token therefore grants effectively root-level control of the
server, including the ability to launch privileged containers. Keep the token
secret and restrict API access.

Check the service with `systemctl status awg-dashboard-api` and view logs with
`journalctl -u awg-dashboard-api -f`.

## Runtime and state requirements

- The API service needs the Docker CLI and access to the local Docker Engine.
  The installer runs it as root to access Docker. The managed AWG container
  also runs `--privileged` to configure its tunnel and firewall; only trusted
  operators should be able to invoke manager operations.
- If running the API inside a container instead of using the systemd
  installer, mount the Docker socket and mount the state directory at the
  **same absolute path** inside the API container. Docker resolves bind-mount
  sources on the daemon host, not inside the API container.
- The state directory contains the server private key and peer PSKs in
  `awg0.conf`, client private keys encrypted in `clients.json`, server metadata,
  and a Fernet master key. The directory and secret files are created with
  restrictive permissions. Back up the full directory securely.
- By default, `StateStore` creates and uses `master.key` in the state directory.
  Deployments may instead set `AWG_DASHBOARD_MASTER_KEY` to a Fernet key (for
  example, one produced by `Fernet.generate_key()`), and provide it consistently
  across restarts. Changing or losing that key makes stored client private keys
  unavailable; do not rotate it without re-encrypting those keys.
- The manager pulls an image on install/upgrade and records its immutable Docker
  image ID. Runtime containers and key-generation commands use that ID so a
  mutable tag cannot change the active runtime unexpectedly.

Client routes and server tunnel addresses currently support IPv4. IPv6 endpoint
hostnames/addresses are accepted, but IPv6 tunnel routing and server egress need
separate configuration and are not enabled here.

Run local checks with:

```sh
uv run ruff format --check src tests
uv run ruff check src tests
uv run python -m unittest discover -s tests -v
```
