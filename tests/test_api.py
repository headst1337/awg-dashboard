from __future__ import annotations

import base64
import unittest
from datetime import UTC, datetime
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient

from awg_dashboard.api import create_app
from awg_dashboard.errors import ClientNotFoundError
from awg_dashboard.models import (
    AwgSettings,
    AwgSettingsView,
    ClientView,
    HostInfo,
    ServerSnapshot,
)
from awg_dashboard.service import AwgManager


def key(value: int) -> str:
    return base64.b64encode(bytes([value]) * 32).decode("ascii")


def snapshot() -> ServerSnapshot:
    settings = AwgSettings("vpn.example.test")
    return ServerSnapshot(
        status="running",
        endpoint="vpn.example.test:55424",
        listen_port=55424,
        protocol_version="3.1",
        image=settings.image,
        image_id=f"sha256:{'a' * 64}",
        server_public_key=key(1),
        settings=AwgSettingsView.from_settings(settings),
        configured_peers=0,
        active_peers=0,
        observed_at=datetime.now(UTC).isoformat(),
        host=HostInfo("Linux", "6.1", "x86_64", 4, 1024, "/var/lib/docker"),
    )


def client_view() -> ClientView:
    return ClientView(
        client_id="client-1",
        name="Phone",
        address="10.8.1.2",
        public_key=key(2),
        allowed_ips=("0.0.0.0/0",),
        created_at=datetime.now(UTC).isoformat(),
    )


class ApiTests(unittest.TestCase):
    def setup_client(self) -> tuple[Mock, TestClient]:
        manager = Mock(spec=AwgManager)
        app = create_app(manager=manager, api_token="test-token")
        return manager, TestClient(app)

    def test_api_requires_bearer_token(self) -> None:
        manager, client = self.setup_client()

        response = client.get("/api/v1/status")

        self.assertEqual(response.status_code, 401)
        manager.status.assert_not_called()

    def test_default_manager_is_created_lazily_from_state_dir(self) -> None:
        manager = Mock(spec=AwgManager)
        manager.status.return_value = snapshot()
        app = create_app(api_token="test-token")

        with (
            patch.dict(
                "os.environ", {"AWG_DASHBOARD_STATE_DIR": "/tmp/api-state"}
            ),
            patch(
                "awg_dashboard.api.AwgManager", return_value=manager
            ) as factory,
            TestClient(app) as client,
        ):
            response = client.get(
                "/api/v1/status",
                headers={"Authorization": "Bearer test-token"},
            )

        self.assertEqual(response.status_code, 200)
        factory.assert_called_once_with(state_dir="/tmp/api-state")

    def test_status_is_authenticated_and_does_not_expose_secrets(self) -> None:
        manager, client = self.setup_client()
        manager.status.return_value = snapshot()

        response = client.get(
            "/api/v1/status",
            headers={"Authorization": "Bearer test-token"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["status"], "running")
        self.assertNotIn("private_key", response.text)
        self.assertNotIn("header_protection_key", response.text)

    def test_install_converts_payload_into_domain_settings(self) -> None:
        manager, client = self.setup_client()
        manager.install.return_value = snapshot()

        response = client.post(
            "/api/v1/server/install",
            headers={"Authorization": "Bearer test-token"},
            json={
                "endpoint_host": "VPN.Example.Test",
                "listen_port": 12345,
                "dns_servers": ["1.1.1.1"],
            },
        )

        self.assertEqual(response.status_code, 201)
        settings = manager.install.call_args.args[0]
        self.assertIsInstance(settings, AwgSettings)
        self.assertEqual(settings.endpoint_host, "vpn.example.test")
        self.assertEqual(settings.listen_port, 12345)
        self.assertEqual(settings.dns_servers, ("1.1.1.1",))

    def test_settings_upgrade_and_client_list_routes(self) -> None:
        manager, client = self.setup_client()
        manager.update_settings.return_value = snapshot()
        manager.upgrade.return_value = snapshot()
        manager.list_clients.return_value = (client_view(),)
        headers = {"Authorization": "Bearer test-token"}
        settings_payload = {"endpoint_host": "vpn.example.test"}

        updated = client.put(
            "/api/v1/server/settings",
            headers=headers,
            json=settings_payload,
        )
        upgraded = client.post(
            "/api/v1/server/upgrade",
            headers=headers,
            json={"image": "amneziavpn/amneziawg-go:3.1"},
        )
        clients = client.get("/api/v1/clients", headers=headers)
        health = client.get("/healthz")

        self.assertEqual(updated.status_code, 200)
        self.assertEqual(upgraded.status_code, 200)
        self.assertEqual(clients.json()[0]["client_id"], "client-1")
        self.assertEqual(health.json(), {"status": "ok"})
        self.assertEqual(
            manager.update_settings.call_args.args[0].endpoint_host,
            "vpn.example.test",
        )
        manager.upgrade.assert_called_once_with("amneziavpn/amneziawg-go:3.1")

    def test_validation_errors_do_not_echo_request_secrets(self) -> None:
        _, client = self.setup_client()
        secret = "request-secret-that-must-not-be-echoed"

        response = client.post(
            "/api/v1/server/install",
            headers={"Authorization": "Bearer test-token"},
            json={"endpoint_host": "vpn.example.test", "unexpected": secret},
        )

        self.assertEqual(response.status_code, 422)
        self.assertNotIn(secret, response.text)

    def test_client_export_and_revoke_routes(self) -> None:
        manager, client = self.setup_client()
        client_data = client_view()
        manager.create_client.return_value = client_data
        manager.get_client_config.return_value = (
            "[Interface]\nPrivateKey = secret\n"
        )
        manager.get_client_qr_svg.return_value = "<svg></svg>"

        headers = {"Authorization": "Bearer test-token"}
        created = client.post(
            "/api/v1/clients",
            headers=headers,
            json={"name": "Phone", "allowed_ips": ["0.0.0.0/0"]},
        )
        exported = client.get(
            "/api/v1/clients/client-1/config", headers=headers
        )
        qr = client.get("/api/v1/clients/client-1/qr.svg", headers=headers)
        revoked = client.delete("/api/v1/clients/client-1", headers=headers)

        self.assertEqual(created.status_code, 201)
        self.assertEqual(created.json()["client_id"], "client-1")
        self.assertEqual(exported.status_code, 200)
        self.assertTrue(
            exported.headers["content-type"].startswith("text/plain")
        )
        self.assertEqual(exported.headers["cache-control"], "no-store")
        self.assertIn("PrivateKey = secret", exported.text)
        self.assertTrue(qr.headers["content-type"].startswith("image/svg+xml"))
        self.assertEqual(qr.headers["cache-control"], "no-store")
        self.assertEqual(revoked.status_code, 204)
        manager.revoke_client.assert_called_once_with("client-1")

    def test_manager_not_found_maps_to_http_404(self) -> None:
        manager, client = self.setup_client()
        manager.get_client_config.side_effect = ClientNotFoundError(
            "client was not found"
        )

        response = client.get(
            "/api/v1/clients/missing/config",
            headers={"Authorization": "Bearer test-token"},
        )

        self.assertEqual(response.status_code, 404)
