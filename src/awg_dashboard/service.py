from __future__ import annotations

import ipaddress
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from .config import (
    ServerDocument,
    allocate_client_address,
    build_client_config,
    parse_server_config,
    peer_client_address,
    render_server_config,
    validate_peer_addresses,
)
from .errors import (
    ClientNotFoundError,
    ConflictError,
    DockerRuntimeError,
    NotInstalledError,
    ReconciliationError,
    StateStoreError,
    ValidationError,
)
from .models import (
    AwgSettings,
    AwgSettingsView,
    ClientView,
    HostInfo,
    PeerConfig,
    ServerSnapshot,
    StoredClient,
    format_endpoint,
    validate_client_name,
)
from .qr import generate_awg_qr_svg
from .runtime import ContainerStatus, DockerRuntime
from .store import StateStore


class AwgManager:
    def __init__(
        self,
        *,
        runtime: DockerRuntime | None = None,
        store: StateStore | None = None,
        state_dir: Path | str = "/var/lib/awg-dashboard",
    ) -> None:
        self.runtime = runtime or DockerRuntime()
        self.store = store or StateStore(state_dir)

    def install(self, settings: AwgSettings) -> ServerSnapshot:
        with self.store.locked():
            if (
                self.store.config_path.exists()
                or self.store.load_server_metadata() is not None
            ):
                raise ConflictError("AmneziaWG is already configured")
            if self.runtime.container_status() is not None:
                raise ConflictError("the managed AWG container already exists")

            host = self.runtime.host_info()
            self.runtime.pull_image(settings.image)
            image_id = self.runtime.image_id(settings.image)
            private_key, public_key = self.runtime.generate_key_pair(image_id)
            parameters = settings.parameters
            if (
                settings.protocol_version == "3.1"
                and not parameters.header_protection_key
            ):
                protection_key, _ = self.runtime.generate_key_pair(image_id)
                parameters = replace(
                    parameters, header_protection_key=protection_key
                )
            effective_settings = replace(settings, parameters=parameters)
            config_text = render_server_config(
                effective_settings,
                private_key=private_key,
                parameters=parameters,
            )
            created_at = datetime.now(UTC).isoformat()
            try:
                self.store.save_config(config_text)
                self.store.save_server_metadata(
                    effective_settings,
                    image=effective_settings.image,
                    server_public_key=public_key,
                    runtime_image_id=image_id,
                    created_at=created_at,
                )
                self.runtime.create_container(
                    effective_settings,
                    image=image_id,
                    config_path=self.store.config_path,
                )
                status = self._require_running_container()
            except Exception as install_error:
                try:
                    self.runtime.remove_container()
                except Exception as rollback_error:
                    raise ReconciliationError(
                        "AWG installation failed and the partial container could not be removed"
                    ) from rollback_error
                self.store.delete_config()
                self.store.delete_server_metadata()
                raise install_error
            return self._snapshot(
                effective_settings,
                status,
                public_key,
                host,
                image_id=image_id,
            )

    def status(self) -> ServerSnapshot:
        with self.store.locked():
            return self._status_unlocked()

    def _status_unlocked(self) -> ServerSnapshot:
        host = self.runtime.host_info()
        container = self.runtime.container_status()
        metadata = self.store.load_server_metadata()
        config_exists = self.store.config_path.exists()
        if not config_exists and metadata is None:
            return ServerSnapshot(
                status="not_installed" if container is None else "inconsistent",
                endpoint=None,
                listen_port=None,
                protocol_version=None,
                image=None,
                image_id=None,
                server_public_key=None,
                settings=None,
                configured_peers=0,
                active_peers=0,
                observed_at=datetime.now(UTC).isoformat(),
                host=host,
            )
        if not config_exists or metadata is None:
            return ServerSnapshot(
                status="inconsistent",
                endpoint=None,
                listen_port=None,
                protocol_version=None,
                image=None,
                image_id=None,
                server_public_key=None,
                settings=None,
                configured_peers=0,
                active_peers=0,
                observed_at=datetime.now(UTC).isoformat(),
                host=host,
            )

        document = parse_server_config(self.store.read_config())
        settings = self._settings_from_state(metadata, document)
        peer_stats = (
            self.runtime.runtime_peers()
            if container and container.status == "running"
            else {}
        )
        clients = self._client_views(document.peers, peer_stats)
        status = container.status if container else "missing"
        return self._snapshot(
            settings,
            container,
            metadata.get("server_public_key"),
            host,
            image_id=self._stored_image_id(metadata),
            status=status,
            clients=clients,
        )

    def update_settings(self, settings: AwgSettings) -> ServerSnapshot:
        with self.store.locked():
            metadata, old_settings, old_document = self._load_installed_state()
            runtime_image_id = self._runtime_image_id(
                metadata, old_settings.image
            )
            if settings.image != old_settings.image:
                raise ValidationError(
                    "use upgrade() to change the AWG runtime image"
                )
            parameters = settings.parameters
            if (
                settings.protocol_version == "3.1"
                and not parameters.header_protection_key
            ):
                protection_key, _ = self.runtime.generate_key_pair(
                    runtime_image_id
                )
                parameters = replace(
                    parameters,
                    header_protection_key=(
                        old_document.parameters.header_protection_key
                        or protection_key
                    ),
                )
            effective_settings = replace(settings, parameters=parameters)
            self._validate_peer_addresses(
                effective_settings, old_document.peers
            )
            old_config = self.store.read_config()
            new_config = render_server_config(
                effective_settings,
                private_key=old_document.private_key,
                parameters=parameters,
                peers=old_document.peers,
            )
            current_status = self.runtime.container_status()
            requires_recreate = (
                effective_settings.listen_port != old_settings.listen_port
                or effective_settings.subnet != old_settings.subnet
                or current_status is None
            )
            self.store.save_config(new_config)
            try:
                if requires_recreate:
                    self.runtime.remove_container()
                    self.runtime.create_container(
                        effective_settings,
                        image=runtime_image_id,
                        config_path=self.store.config_path,
                    )
                    self._require_running_container()
                elif current_status.status == "running":
                    self.runtime.apply_config()
                self.store.save_server_metadata(
                    effective_settings,
                    image=old_settings.image,
                    server_public_key=metadata["server_public_key"],
                    runtime_image_id=runtime_image_id,
                    created_at=metadata.get("created_at"),
                )
                if (
                    current_status
                    and current_status.status != "running"
                    and requires_recreate
                ):
                    self.runtime.stop_container()
            except Exception as update_error:
                self._rollback_config_update(
                    old_config,
                    old_settings,
                    old_document,
                    runtime_image_id=runtime_image_id,
                    previous_container_status=current_status,
                    update_error=update_error,
                )
                raise
            return self._status_unlocked()

    def upgrade(self, image: str) -> ServerSnapshot:
        with self.store.locked():
            metadata, old_settings, document = self._load_installed_state()
            old_container_status = self.runtime.container_status()
            old_image_id = self._runtime_image_id(metadata, old_settings.image)
            upgraded_settings = replace(old_settings, image=image)
            old_image = old_settings.image
            self.runtime.pull_image(image)
            new_image_id = self.runtime.image_id(image)
            try:
                self.runtime.remove_container()
                self.runtime.create_container(
                    upgraded_settings,
                    image=new_image_id,
                    config_path=self.store.config_path,
                )
                self._require_running_container()
                self.store.save_server_metadata(
                    upgraded_settings,
                    image=image,
                    server_public_key=metadata["server_public_key"],
                    runtime_image_id=new_image_id,
                    created_at=metadata.get("created_at"),
                )
                if (
                    old_container_status
                    and old_container_status.status != "running"
                ):
                    self.runtime.stop_container()
            except Exception as update_error:
                try:
                    self._remove_container_safely()
                    if old_container_status:
                        self.runtime.create_container(
                            old_settings,
                            image=old_image_id,
                            config_path=self.store.config_path,
                        )
                        self._require_running_container()
                        if old_container_status.status != "running":
                            self.runtime.stop_container()
                    self.store.save_server_metadata(
                        old_settings,
                        image=old_image,
                        server_public_key=metadata["server_public_key"],
                        runtime_image_id=old_image_id,
                        created_at=metadata.get("created_at"),
                    )
                except Exception as rollback_error:
                    raise ReconciliationError(
                        "AWG upgrade failed and the previous runtime could not be restored"
                    ) from rollback_error
                raise update_error
            if parse_server_config(self.store.read_config()) != document:
                raise StateStoreError(
                    "AWG config changed unexpectedly during upgrade"
                )
            return self._status_unlocked()

    def create_client(
        self,
        name: str,
        *,
        allowed_ips: tuple[str, ...] | None = None,
    ) -> ClientView:
        with self.store.locked():
            metadata, settings, document = self._load_installed_state()
            self._require_running_container()
            normalized_name = validate_client_name(name)
            client_allowed_ips = tuple(
                settings.allowed_ips if allowed_ips is None else allowed_ips
            )
            self._validate_networks(client_allowed_ips)
            address = allocate_client_address(settings, document.peers)
            runtime_image_id = self._runtime_image_id(metadata, settings.image)
            private_key, public_key = self.runtime.generate_key_pair(
                runtime_image_id
            )
            preshared_key = self.runtime.generate_preshared_key(
                runtime_image_id
            )
            peer = PeerConfig(
                public_key=public_key,
                preshared_key=preshared_key,
                allowed_ips=(f"{address}/32",),
            )
            encrypted_private_key = self.store.encrypt_secret(private_key)
            client = StoredClient.create(
                name=normalized_name,
                address=str(address),
                public_key=public_key,
                allowed_ips=client_allowed_ips,
                encrypted_private_key=encrypted_private_key,
            )
            clients_before = self.store.load_clients()
            config_before = self.store.read_config()
            config_after = render_server_config(
                settings,
                private_key=document.private_key,
                parameters=document.parameters,
                peers=(*document.peers, peer),
            )
            try:
                self.store.save_config(config_after)
                self.store.save_clients([*clients_before, client])
                self.runtime.apply_config()
            except Exception as apply_error:
                self._rollback_client_change(
                    config_before,
                    clients_before,
                    apply_error,
                )
                raise
            return client.public_view()

    def list_clients(self) -> tuple[ClientView, ...]:
        with self.store.locked():
            _, _, document = self._load_installed_state()
            container = self.runtime.container_status()
            peer_stats = (
                self.runtime.runtime_peers()
                if container and container.status == "running"
                else {}
            )
            return tuple(self._client_views(document.peers, peer_stats))

    def get_client_config(self, client_id: str) -> str:
        with self.store.locked():
            return self._get_client_config_unlocked(client_id)

    def _get_client_config_unlocked(self, client_id: str) -> str:
        metadata, settings, document = self._load_installed_state()
        clients = self.store.load_clients()
        client = next(
            (item for item in clients if item.client_id == client_id), None
        )
        if client is None:
            raise ClientNotFoundError("client was not found")
        peer = next(
            (
                item
                for item in document.peers
                if item.public_key == client.public_key
            ),
            None,
        )
        if peer is None:
            raise ClientNotFoundError(
                "client peer is not present in the AWG config"
            )
        private_key = self.store.decrypt_secret(client.encrypted_private_key)
        return build_client_config(
            settings,
            client_address=client.address,
            private_key=private_key,
            server_public_key=metadata["server_public_key"],
            preshared_key=peer.preshared_key,
            parameters=document.parameters,
            allowed_ips=client.allowed_ips,
        )

    def get_client_qr_svg(self, client_id: str) -> str:
        return generate_awg_qr_svg(self.get_client_config(client_id))

    def revoke_client(self, client_id: str) -> None:
        with self.store.locked():
            _, settings, document = self._load_installed_state()
            clients_before = self.store.load_clients()
            stored_client = next(
                (
                    item
                    for item in clients_before
                    if item.client_id == client_id
                ),
                None,
            )
            if stored_client is not None:
                public_key = stored_client.public_key
            elif client_id.startswith("external:"):
                public_key = client_id.removeprefix("external:")
            else:
                raise ClientNotFoundError("client was not found")
            peers_after = tuple(
                peer for peer in document.peers if peer.public_key != public_key
            )
            if len(peers_after) == len(document.peers):
                raise ClientNotFoundError(
                    "client peer is not present in the AWG config"
                )
            clients_after = [
                client
                for client in clients_before
                if client.public_key != public_key
            ]
            config_before = self.store.read_config()
            config_after = render_server_config(
                settings,
                private_key=document.private_key,
                parameters=document.parameters,
                peers=peers_after,
            )
            try:
                self.store.save_config(config_after)
                self.store.save_clients(clients_after)
                container = self.runtime.container_status()
                if container and container.status == "running":
                    self.runtime.apply_config()
            except Exception as apply_error:
                self._rollback_client_change(
                    config_before,
                    clients_before,
                    apply_error,
                )
                raise

    def _load_installed_state(
        self,
    ) -> tuple[dict[str, object], AwgSettings, ServerDocument]:
        metadata = self.store.load_server_metadata()
        if metadata is None or not self.store.config_path.exists():
            raise NotInstalledError("AmneziaWG has not been installed")
        document = parse_server_config(self.store.read_config())
        settings = self._settings_from_state(metadata, document)
        return metadata, settings, document

    @staticmethod
    def _settings_from_state(
        metadata: dict[str, object],
        document: ServerDocument,
    ) -> AwgSettings:
        settings_data = metadata.get("settings")
        if not isinstance(settings_data, dict):
            raise StateStoreError("server settings are missing")
        values = dict(settings_data)
        values["image"] = str(metadata.get("image", values.get("image", "")))
        values["listen_port"] = document.listen_port
        interface = ipaddress.ip_interface(document.address)
        values["subnet"] = str(interface.network)
        values["parameters"] = document.parameters.to_dict()
        try:
            return AwgSettings.from_dict(values)
        except (TypeError, ValueError, ValidationError) as error:
            raise StateStoreError("stored AWG settings are invalid") from error

    @staticmethod
    def _stored_image_id(metadata: dict[str, object]) -> str | None:
        image_id = metadata.get("image_id")
        if not isinstance(image_id, str) or not image_id.startswith("sha256:"):
            return None
        digest = image_id.removeprefix("sha256:")
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            return None
        return image_id

    @classmethod
    def _runtime_image_id(
        cls,
        metadata: dict[str, object],
        fallback_image: str,
    ) -> str:
        return cls._stored_image_id(metadata) or fallback_image

    def _snapshot(
        self,
        settings: AwgSettings,
        container: ContainerStatus | None,
        server_public_key: str | None,
        host: HostInfo | None,
        *,
        image_id: str | None,
        status: str | None = None,
        clients: list[ClientView] | None = None,
    ) -> ServerSnapshot:
        now = int(datetime.now(UTC).timestamp())
        return ServerSnapshot(
            status=status or (container.status if container else "missing"),
            endpoint=format_endpoint(
                settings.endpoint_host, settings.listen_port
            ),
            listen_port=settings.listen_port,
            protocol_version=settings.protocol_version,
            image=settings.image,
            image_id=image_id,
            server_public_key=server_public_key,
            settings=AwgSettingsView.from_settings(settings),
            configured_peers=len(clients or ()),
            active_peers=sum(
                client.latest_handshake is not None
                and 0 <= now - client.latest_handshake < 180
                for client in clients or ()
            ),
            observed_at=datetime.now(UTC).isoformat(),
            host=host,
            clients=tuple(clients or ()),
        )

    def _client_views(
        self,
        peers: tuple[PeerConfig, ...],
        peer_stats: dict[str, object],
    ) -> list[ClientView]:
        stored_by_key = {
            client.public_key: client for client in self.store.load_clients()
        }
        clients: list[ClientView] = []
        for peer in peers:
            stat = peer_stats.get(peer.public_key)
            stored = stored_by_key.get(peer.public_key)
            address = peer_client_address(peer) or ""
            if stored:
                clients.append(
                    stored.public_view(
                        latest_handshake=getattr(
                            stat, "latest_handshake", None
                        ),
                        received_bytes=getattr(stat, "received_bytes", None),
                        sent_bytes=getattr(stat, "sent_bytes", None),
                    )
                )
            else:
                clients.append(
                    ClientView(
                        client_id=f"external:{peer.public_key}",
                        name="Unmanaged peer",
                        address=address,
                        public_key=peer.public_key,
                        allowed_ips=peer.allowed_ips,
                        created_at="",
                        latest_handshake=getattr(
                            stat, "latest_handshake", None
                        ),
                        received_bytes=getattr(stat, "received_bytes", None),
                        sent_bytes=getattr(stat, "sent_bytes", None),
                    )
                )
        return clients

    def _validate_peer_addresses(
        self,
        settings: AwgSettings,
        peers: tuple[PeerConfig, ...],
    ) -> None:
        network = settings.network
        for client in self.store.load_clients():
            address = ipaddress.IPv4Address(client.address)
            if (
                address not in network
                or address == settings.server_address
                or address
                in {network.network_address, network.broadcast_address}
            ):
                raise ValidationError(
                    "the new subnet excludes an address assigned to a managed client"
                )
        validate_peer_addresses(settings, peers)

    @staticmethod
    def _validate_networks(networks: tuple[str, ...]) -> None:
        if not networks:
            raise ValidationError("at least one AllowedIPs network is required")
        for network in networks:
            try:
                parsed = ipaddress.ip_network(network, strict=False)
            except ValueError as error:
                raise ValidationError(
                    f"invalid AllowedIPs network: {network}"
                ) from error
            if not isinstance(parsed, ipaddress.IPv4Network):
                raise ValidationError(
                    "IPv6 routes require an IPv6-enabled AWG server"
                )

    def _require_running_container(self) -> ContainerStatus:
        status = self.runtime.container_status()
        if status is None or status.status != "running":
            raise DockerRuntimeError(
                "AWG container did not reach the running state"
            )
        return status

    def _rollback_client_change(
        self,
        old_config: str,
        old_clients: list[StoredClient],
        original_error: Exception,
    ) -> None:
        try:
            self.store.save_config(old_config)
            self.store.save_clients(old_clients)
            status = self.runtime.container_status()
            if status and status.status == "running":
                self.runtime.apply_config()
        except Exception as rollback_error:
            raise ReconciliationError(
                "client change failed and the previous AWG state could not be restored"
            ) from rollback_error
        raise original_error

    def _rollback_config_update(
        self,
        old_config: str,
        old_settings: AwgSettings,
        old_document: ServerDocument,
        *,
        runtime_image_id: str,
        previous_container_status: ContainerStatus | None,
        update_error: Exception,
    ) -> None:
        try:
            self.store.save_config(old_config)
            current_metadata = self.store.load_server_metadata()
            if current_metadata is None:
                raise StateStoreError(
                    "server metadata disappeared during update"
                )
            self.store.save_server_metadata(
                old_settings,
                image=old_settings.image,
                server_public_key=str(current_metadata["server_public_key"]),
                runtime_image_id=runtime_image_id,
                created_at=current_metadata.get("created_at"),
            )
            self.runtime.remove_container()
            if previous_container_status:
                self.runtime.create_container(
                    old_settings,
                    image=runtime_image_id,
                    config_path=self.store.config_path,
                )
                self._require_running_container()
                if previous_container_status.status != "running":
                    self.runtime.stop_container()
            elif parse_server_config(self.store.read_config()) != old_document:
                raise StateStoreError("previous AWG config was not restored")
        except Exception as rollback_error:
            raise ReconciliationError(
                "settings update failed and the previous AWG state could not be restored"
            ) from rollback_error
        raise update_error

    def _remove_container_safely(self) -> None:
        try:
            self.runtime.remove_container()
        except Exception:
            pass
