from __future__ import annotations

import base64
import hashlib
import subprocess
import tempfile
import time
import unittest
from dataclasses import asdict, replace
from pathlib import Path
from unittest.mock import patch

from awg_dashboard.config import (
    allocate_client_address,
    build_client_config,
    parse_server_config,
    render_server_config,
)
from awg_dashboard.errors import (
    ConflictError,
    DockerRuntimeError,
    ValidationError,
)
from awg_dashboard.models import (
    AwgProtocolParameters,
    AwgSettings,
    HostInfo,
    PeerConfig,
)
from awg_dashboard.runtime import ContainerStatus, DockerRuntime, RuntimePeer
from awg_dashboard.service import AwgManager
from awg_dashboard.store import StateStore


def key(value: int) -> str:
    return base64.b64encode(bytes([value]) * 32).decode("ascii")


class FakeRuntime:
    def __init__(self) -> None:
        self.status: ContainerStatus | None = None
        self.generated_keys = 0
        self.pulled_images: list[str] = []
        self.key_generation_images: list[str] = []
        self.created: list[tuple[str, int, Path]] = []
        self.peers: dict[str, RuntimePeer] = {}
        self.fail_next_apply = False
        self.fail_next_create = False

    def host_info(self) -> HostInfo:
        return HostInfo(
            operating_system="Test Linux",
            kernel_version="6.1.0",
            architecture="x86_64",
            cpu_count=4,
            memory_bytes=1024,
            docker_root_dir="/var/lib/docker",
        )

    def pull_image(self, image: str) -> None:
        self.pulled_images.append(image)

    @staticmethod
    def image_id(image: str) -> str:
        return f"sha256:{hashlib.sha256(image.encode()).hexdigest()}"

    def generate_key_pair(self, image: str) -> tuple[str, str]:
        self.key_generation_images.append(image)
        self.generated_keys += 1
        return key(self.generated_keys), key(self.generated_keys + 50)

    def generate_preshared_key(self, image: str) -> str:
        self.key_generation_images.append(image)
        self.generated_keys += 1
        return key(self.generated_keys + 100)

    def create_container(
        self,
        settings: AwgSettings,
        *,
        image: str,
        config_path: Path,
    ) -> None:
        if self.fail_next_create:
            self.fail_next_create = False
            raise DockerRuntimeError("injected container create failure")
        self.created.append((image, settings.listen_port, config_path))
        self.status = ContainerStatus("running", 0)

    def remove_container(self) -> None:
        self.status = None

    def stop_container(self) -> None:
        if self.status:
            self.status = ContainerStatus("exited", self.status.restart_count)

    def container_status(self) -> ContainerStatus | None:
        return self.status

    def apply_config(self) -> None:
        if self.fail_next_apply:
            self.fail_next_apply = False
            raise DockerRuntimeError("injected apply failure")

    def runtime_peers(self) -> dict[str, RuntimePeer]:
        return self.peers


class ConfigTests(unittest.TestCase):
    def test_server_config_round_trips_awg_fields_and_peers(self) -> None:
        settings = AwgSettings(
            "vpn.example.test",
            parameters=AwgProtocolParameters(header_protection_key=key(9)),
        )
        peer = PeerConfig(
            public_key=key(10),
            preshared_key=key(11),
            allowed_ips=("10.8.1.2/32",),
        )
        rendered = render_server_config(
            settings,
            private_key=key(8),
            parameters=settings.parameters,
            peers=(peer,),
        )

        parsed = parse_server_config(rendered)

        self.assertEqual(parsed.private_key, key(8))
        self.assertEqual(parsed.listen_port, 55424)
        self.assertEqual(parsed.peers, (peer,))
        self.assertEqual(parsed.parameters.header_protection_key, key(9))
        self.assertIn("# I1 =", rendered)

    def test_client_config_is_native_awg_conf(self) -> None:
        settings = AwgSettings("2001:db8::1")
        config = build_client_config(
            settings,
            client_address="10.8.1.2",
            private_key=key(1),
            server_public_key=key(2),
            preshared_key=key(3),
            parameters=AwgProtocolParameters(header_protection_key=key(4)),
        )

        self.assertTrue(config.startswith("[Interface]\n"))
        self.assertIn("Jc = 4\n", config)
        self.assertIn("HeaderProtectionKey =", config)
        self.assertIn("Endpoint = [2001:db8::1]:55424\n", config)
        self.assertIn("[Peer]\n", config)
        self.assertNotIn("vpn://", config)

    def test_allocator_skips_server_and_existing_peers(self) -> None:
        settings = AwgSettings("vpn.example.test")
        peers = (
            PeerConfig(key(1), key(2), ("10.8.1.2/32",)),
            PeerConfig(key(3), key(4), ("10.8.1.4/32",)),
        )

        self.assertEqual(
            str(allocate_client_address(settings, peers)), "10.8.1.3"
        )

    def test_rejects_invalid_endpoint_and_ipv6_routes(self) -> None:
        with self.assertRaises(ValidationError):
            AwgSettings("bad host; docker rm -f")
        with self.assertRaises(ValidationError):
            AwgSettings("vpn.example.test", allowed_ips=("::/0",))


class AwgManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.state_dir = Path(self.temporary_directory.name) / "state"
        self.store = StateStore(self.state_dir)
        self.runtime = FakeRuntime()
        self.manager = AwgManager(runtime=self.runtime, store=self.store)
        self.settings = AwgSettings("vpn.example.test")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_install_and_status_never_expose_server_secrets(self) -> None:
        snapshot = self.manager.install(self.settings)
        metadata = self.store.load_server_metadata()

        self.assertEqual(snapshot.status, "running")
        self.assertEqual(snapshot.settings.subnet, "10.8.1.0/24")
        self.assertEqual(
            snapshot.image_id, self.runtime.image_id(self.settings.image)
        )
        self.assertEqual(metadata["image_id"], snapshot.image_id)
        self.assertEqual(self.runtime.created[0][0], snapshot.image_id)
        self.assertTrue(self.runtime.key_generation_images)
        self.assertTrue(
            all(
                image == snapshot.image_id
                for image in self.runtime.key_generation_images
            )
        )
        self.assertEqual(self.runtime.pulled_images, [self.settings.image])
        self.assertEqual(snapshot.configured_peers, 0)
        self.assertEqual(
            (self.state_dir / "awg0.conf").stat().st_mode & 0o777, 0o600
        )
        self.assertNotIn("header_protection_key", asdict(snapshot))
        with self.assertRaises(ConflictError):
            self.manager.install(self.settings)

    def test_status_reports_partial_persistent_state_as_inconsistent(
        self,
    ) -> None:
        self.store.save_config("partial state")

        self.assertEqual(self.manager.status().status, "inconsistent")

    def test_create_client_returns_native_conf_and_qr(self) -> None:
        self.manager.install(self.settings)
        client = self.manager.create_client("  Phone   one ")
        config = self.manager.get_client_config(client.client_id)
        qr_svg = self.manager.get_client_qr_svg(client.client_id)

        self.assertEqual(client.name, "Phone one")
        self.assertEqual(client.address, "10.8.1.2")
        self.assertIn("Address = 10.8.1.2/32", config)
        self.assertIn("Endpoint = vpn.example.test:55424", config)
        self.assertNotIn("vpn://", config)
        self.assertIn("<svg", qr_svg)
        self.assertNotIn("vpn://", qr_svg)
        now = time.time_ns() // 1_000_000_000
        self.runtime.peers[client.public_key] = RuntimePeer(
            public_key=client.public_key,
            latest_handshake=now - 30,
            received_bytes=1024,
            sent_bytes=2048,
        )
        self.assertEqual(self.manager.status().active_peers, 1)
        self.assertEqual(self.manager.list_clients()[0].received_bytes, 1024)
        self.runtime.peers[client.public_key] = RuntimePeer(
            public_key=client.public_key,
            latest_handshake=now - 240,
            received_bytes=1024,
            sent_bytes=2048,
        )
        self.assertEqual(self.manager.status().active_peers, 0)

        clients_file = (self.state_dir / "clients.json").read_text(
            encoding="utf-8"
        )
        self.assertNotIn(
            config.split("PrivateKey = ", 1)[1].splitlines()[0], clients_file
        )
        self.assertEqual(self.manager.status().configured_peers, 1)

    def test_create_client_rolls_back_config_if_live_apply_fails(self) -> None:
        self.manager.install(self.settings)
        original_config = self.store.read_config()
        self.runtime.fail_next_apply = True

        with self.assertRaises(DockerRuntimeError):
            self.manager.create_client("Phone")

        self.assertEqual(self.store.read_config(), original_config)
        self.assertEqual(self.store.load_clients(), [])

    def test_revoke_client_removes_peer_and_metadata(self) -> None:
        self.manager.install(self.settings)
        client = self.manager.create_client("Phone")

        self.manager.revoke_client(client.client_id)

        self.assertEqual(
            parse_server_config(self.store.read_config()).peers, ()
        )
        self.assertEqual(self.store.load_clients(), [])
        self.assertEqual(self.manager.status().configured_peers, 0)

    def test_update_and_upgrade_preserve_server_identity_and_peers(
        self,
    ) -> None:
        self.manager.install(self.settings)
        client = self.manager.create_client("Laptop")
        original_document = parse_server_config(self.store.read_config())

        updated = self.manager.update_settings(
            replace(self.settings, listen_port=55425)
        )
        updated_document = parse_server_config(self.store.read_config())

        self.assertEqual(updated.listen_port, 55425)
        self.assertEqual(
            updated_document.private_key, original_document.private_key
        )
        self.assertEqual(len(updated_document.peers), 1)
        self.assertIn(
            "Endpoint = vpn.example.test:55425",
            self.manager.get_client_config(client.client_id),
        )

        upgraded = self.manager.upgrade("amneziavpn/amneziawg-go:3.1")

        self.assertEqual(upgraded.image, "amneziavpn/amneziawg-go:3.1")
        self.assertEqual(
            upgraded.image_id,
            self.runtime.image_id("amneziavpn/amneziawg-go:3.1"),
        )
        self.assertEqual(self.runtime.created[-1][0], upgraded.image_id)
        self.assertEqual(
            parse_server_config(self.store.read_config()).peers,
            updated_document.peers,
        )
        self.assertEqual(
            self.manager.list_clients()[0].client_id, client.client_id
        )

    def test_update_rejects_subnet_that_excludes_managed_client(self) -> None:
        self.manager.install(self.settings)
        self.manager.create_client("Phone")
        original_config = self.store.read_config()

        with self.assertRaisesRegex(ValidationError, "excludes an address"):
            self.manager.update_settings(
                replace(self.settings, subnet="10.9.0.0/24")
            )

        self.assertEqual(self.store.read_config(), original_config)

    def test_upgrade_rolls_back_to_previous_image_on_failure(self) -> None:
        self.manager.install(self.settings)
        original_config = self.store.read_config()
        self.runtime.fail_next_create = True

        with self.assertRaises(DockerRuntimeError):
            self.manager.upgrade("amneziavpn/amneziawg-go:3.1")

        metadata = self.store.load_server_metadata()
        self.assertEqual(metadata["image"], self.settings.image)
        self.assertEqual(
            metadata["image_id"], self.runtime.image_id(self.settings.image)
        )
        self.assertEqual(self.store.read_config(), original_config)
        self.assertEqual(self.runtime.status.status, "running")


class DockerRuntimeTests(unittest.TestCase):
    def test_container_status_reads_state_and_restart_count(self) -> None:
        runtime = DockerRuntime()
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout="running|3\n",
            stderr="",
        )
        with patch(
            "awg_dashboard.runtime.subprocess.run", return_value=completed
        ):
            status = runtime.container_status()

        self.assertEqual(status, ContainerStatus("running", 3))

    def test_create_container_uses_udp_publish_and_shared_config(self) -> None:
        runtime = DockerRuntime()
        settings = AwgSettings("vpn.example.test")
        with tempfile.NamedTemporaryFile() as config_file:
            completed = subprocess.CompletedProcess(
                args=["docker"],
                returncode=0,
                stdout="container-id\n",
                stderr="",
            )
            with patch(
                "awg_dashboard.runtime.subprocess.run", return_value=completed
            ) as run:
                runtime.create_container(
                    settings,
                    image=settings.image,
                    config_path=Path(config_file.name),
                )

        command = run.call_args.args[0]
        self.assertIn("55424:55424/udp", command)
        self.assertIn("--privileged", command)
        self.assertIn("/lib/modules:/lib/modules:ro", command)
        self.assertIn("net.ipv4.ip_forward=1", command)
        self.assertFalse(run.call_args.kwargs.get("shell", False))

    def test_runtime_peer_dump_does_not_expose_peer_preshared_key(self) -> None:
        runtime = DockerRuntime()
        dump = "\t".join(
            (key(20), key(21), "(none)", "10.8.1.2/32", "30", "40", "50", "25")
        )
        completed = subprocess.CompletedProcess(
            args=["docker"],
            returncode=0,
            stdout=f"interface-private\tinterface-public\t55424\t0\n{dump}\n",
            stderr="",
        )
        with patch(
            "awg_dashboard.runtime.subprocess.run", return_value=completed
        ):
            peers = runtime.runtime_peers()

        self.assertEqual(
            peers[key(20)],
            RuntimePeer(
                key(20), latest_handshake=30, received_bytes=40, sent_bytes=50
            ),
        )


class StateStoreTests(unittest.TestCase):
    def test_encryption_key_persists_across_store_instances(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            state_dir = Path(temporary_directory) / "state"
            first_store = StateStore(state_dir)
            encrypted = first_store.encrypt_secret("private client key")
            second_store = StateStore(state_dir)

            self.assertNotEqual(encrypted, "private client key")
            self.assertEqual(
                second_store.decrypt_secret(encrypted), "private client key"
            )
            self.assertEqual(
                (state_dir / "master.key").stat().st_mode & 0o777, 0o600
            )


if __name__ == "__main__":
    unittest.main()
