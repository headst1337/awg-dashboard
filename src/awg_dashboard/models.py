from __future__ import annotations

import base64
import ipaddress
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from uuid import UUID, uuid4

from .errors import ValidationError

DEFAULT_IMAGE = "amneziavpn/amneziawg-go:latest"
DEFAULT_SPECIAL_JUNK_1 = (
    "<r 2><b 0x858000010001000000000669636c6f756403636f6d0000010001"
    "c00c000100010000105a00044d583737>"
)
_DOMAIN_LABEL = re.compile(r"^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$")
_IMAGE_REFERENCE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9._/:@-]{0,254}$")
_RANGE_VALUE = re.compile(r"^\d+(?:-\d+)?$")
_SPECIAL_JUNK = re.compile(r"^<r \d+><b 0x[0-9a-fA-F]+>$")


def validate_key(value: str, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field_name} must be a base64 WireGuard key")
    try:
        decoded = base64.b64decode(value, validate=True)
    except (ValueError, TypeError) as error:
        raise ValidationError(
            f"{field_name} must be a base64 WireGuard key"
        ) from error
    if len(decoded) != 32:
        raise ValidationError(f"{field_name} must decode to 32 bytes")
    return value


def validate_endpoint_host(value: str) -> str:
    host = value.strip()
    if not host or any(character.isspace() for character in host):
        raise ValidationError("endpoint_host must be an IP address or hostname")

    unbracketed = (
        host[1:-1] if host.startswith("[") and host.endswith("]") else host
    )
    try:
        ipaddress.ip_address(unbracketed)
        return unbracketed
    except ValueError:
        pass

    if len(host) > 253 or host.endswith("."):
        raise ValidationError("endpoint_host must be a valid hostname")
    labels = host.split(".")
    if not all(_DOMAIN_LABEL.fullmatch(label) for label in labels):
        raise ValidationError("endpoint_host must be a valid hostname")
    return host.lower()


def format_endpoint(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    if address.version == 6:
        return f"[{address.compressed}]:{port}"
    return f"{address.compressed}:{port}"


@dataclass(frozen=True, slots=True)
class AwgProtocolParameters:
    junk_packet_count: int = 4
    junk_packet_min_size: int = 10
    junk_packet_max_size: int = 50
    init_packet_junk_size: int = 12
    response_packet_junk_size: int = 12
    cookie_reply_packet_junk_size: int = 12
    transport_packet_junk_size: int = 12
    init_packet_magic_header: str = "1"
    response_packet_magic_header: str = "2"
    underload_packet_magic_header: str = "3"
    transport_packet_magic_header: str = "4"
    special_junk_1: str = DEFAULT_SPECIAL_JUNK_1
    special_junk_2: str = ""
    special_junk_3: str = ""
    special_junk_4: str = ""
    special_junk_5: str = ""
    header_protection_key: str = ""
    content_padding_addition: str = "10-100"
    rekey_after_time: str = "100-120"
    rekey_timeout: str = "3-7"
    reject_after_time: str = "150-180"
    keepalive_timeout: str = "5-15"
    max_handshake_attempts: str = "15-20"
    random_trailers: str = "on"
    disable_cookies: str = "on"

    def __post_init__(self) -> None:
        if not 0 <= self.junk_packet_count <= 128:
            raise ValidationError("junk_packet_count must be between 0 and 128")
        if (
            not 0
            <= self.junk_packet_min_size
            <= self.junk_packet_max_size
            <= 65535
        ):
            raise ValidationError(
                "junk packet sizes must be ordered and within 0..65535"
            )
        for name in (
            "init_packet_junk_size",
            "response_packet_junk_size",
            "cookie_reply_packet_junk_size",
            "transport_packet_junk_size",
        ):
            if not 0 <= getattr(self, name) <= 150:
                raise ValidationError(f"{name} must be between 0 and 150")
        for name in (
            "init_packet_magic_header",
            "response_packet_magic_header",
            "underload_packet_magic_header",
            "transport_packet_magic_header",
        ):
            value = getattr(self, name)
            if not _RANGE_VALUE.fullmatch(value):
                raise ValidationError(
                    f"{name} must be a number or an inclusive range"
                )
            parts = [int(part) for part in value.split("-")]
            if any(part > 2**32 - 1 for part in parts) or (
                len(parts) == 2 and parts[0] > parts[1]
            ):
                raise ValidationError(f"{name} is outside the supported range")
        for name in (
            "content_padding_addition",
            "rekey_after_time",
            "rekey_timeout",
            "reject_after_time",
            "keepalive_timeout",
            "max_handshake_attempts",
        ):
            if not _RANGE_VALUE.fullmatch(getattr(self, name)):
                raise ValidationError(
                    f"{name} must be a number or an inclusive range"
                )
            parts = [int(part) for part in getattr(self, name).split("-")]
            if len(parts) == 2 and parts[0] > parts[1]:
                raise ValidationError(f"{name} range must be ordered")
        for name in (
            "special_junk_1",
            "special_junk_2",
            "special_junk_3",
            "special_junk_4",
            "special_junk_5",
        ):
            value = getattr(self, name)
            if value and (
                len(value) > 1024 or not _SPECIAL_JUNK.fullmatch(value)
            ):
                raise ValidationError(
                    f"{name} has an invalid AWG junk packet format"
                )
        for name in ("random_trailers", "disable_cookies"):
            if getattr(self, name) not in {
                "on",
                "off",
                "true",
                "false",
                "1",
                "0",
            }:
                raise ValidationError(f"{name} must be a boolean AWG value")
        if self.header_protection_key:
            validate_key(self.header_protection_key, "header_protection_key")

    def to_awg_fields(
        self,
        *,
        include_special_junk: bool = True,
        protocol_version: str = "3.1",
    ) -> list[tuple[str, str]]:
        fields = [
            ("Jc", str(self.junk_packet_count)),
            ("Jmin", str(self.junk_packet_min_size)),
            ("Jmax", str(self.junk_packet_max_size)),
            ("S1", str(self.init_packet_junk_size)),
            ("S2", str(self.response_packet_junk_size)),
            ("S3", str(self.cookie_reply_packet_junk_size)),
            ("S4", str(self.transport_packet_junk_size)),
            ("H1", self.init_packet_magic_header),
            ("H2", self.response_packet_magic_header),
            ("H3", self.underload_packet_magic_header),
            ("H4", self.transport_packet_magic_header),
        ]
        special = [
            ("I1", self.special_junk_1),
            ("I2", self.special_junk_2),
            ("I3", self.special_junk_3),
            ("I4", self.special_junk_4),
            ("I5", self.special_junk_5),
        ]
        if include_special_junk:
            fields.extend(special)
        elif any(value for _, value in special):
            fields.extend((f"# {name}", value) for name, value in special)
        if protocol_version == "1.5":
            fields = [item for item in fields if item[0] not in {"S3", "S4"}]
        if protocol_version == "3.1":
            if self.header_protection_key:
                fields.append(
                    ("HeaderProtectionKey", self.header_protection_key)
                )
            fields.extend(
                [
                    ("ContentPaddingAddition", self.content_padding_addition),
                    ("RekeyAfterTime", self.rekey_after_time),
                    ("RekeyTimeout", self.rekey_timeout),
                    ("RejectAfterTime", self.reject_after_time),
                    ("KeepaliveTimeout", self.keepalive_timeout),
                    ("MaxHandshakeAttempts", self.max_handshake_attempts),
                    ("RandomTrailers", self.random_trailers),
                    ("DisableCookies", self.disable_cookies),
                ]
            )
        return [(name, value) for name, value in fields if value]

    def to_dict(self, *, include_secret: bool = True) -> dict[str, Any]:
        values = asdict(self)
        if not include_secret:
            values["header_protection_key"] = ""
        return values


@dataclass(frozen=True, slots=True)
class AwgSettings:
    endpoint_host: str
    listen_port: int = 55424
    subnet: str = "10.8.1.0/24"
    dns_servers: tuple[str, ...] = ("8.8.8.8", "8.8.4.4")
    allowed_ips: tuple[str, ...] = ("0.0.0.0/0",)
    mtu: int = 1376
    persistent_keepalive: int = 25
    protocol_version: str = "3.1"
    image: str = DEFAULT_IMAGE
    parameters: AwgProtocolParameters = field(
        default_factory=AwgProtocolParameters
    )

    def __post_init__(self) -> None:
        object.__setattr__(self, "dns_servers", tuple(self.dns_servers))
        object.__setattr__(self, "allowed_ips", tuple(self.allowed_ips))
        if not isinstance(self.parameters, AwgProtocolParameters):
            raise ValidationError("parameters must be AWG protocol parameters")
        object.__setattr__(
            self, "endpoint_host", validate_endpoint_host(self.endpoint_host)
        )
        try:
            network = ipaddress.ip_network(self.subnet, strict=False)
        except ValueError as error:
            raise ValidationError("subnet must be an IPv4 network") from error
        if (
            not isinstance(network, ipaddress.IPv4Network)
            or network.prefixlen > 30
        ):
            raise ValidationError(
                "subnet must be an IPv4 network with at least 1 client address"
            )
        object.__setattr__(self, "subnet", str(network))
        if not 1 <= self.listen_port <= 65535:
            raise ValidationError("listen_port must be between 1 and 65535")
        if not 576 <= self.mtu <= 9000:
            raise ValidationError("mtu must be between 576 and 9000")
        if not 0 <= self.persistent_keepalive <= 65535:
            raise ValidationError(
                "persistent_keepalive must be between 0 and 65535"
            )
        if not self.dns_servers:
            raise ValidationError("at least one DNS server is required")
        for server in self.dns_servers:
            try:
                address = ipaddress.ip_address(server)
            except ValueError as error:
                raise ValidationError(
                    f"invalid DNS server address: {server}"
                ) from error
            if not isinstance(address, ipaddress.IPv4Address):
                raise ValidationError(
                    "IPv6 DNS requires an IPv6-enabled AWG server"
                )
        if not self.allowed_ips:
            raise ValidationError("at least one AllowedIPs network is required")
        for network_value in self.allowed_ips:
            try:
                network = ipaddress.ip_network(network_value, strict=False)
            except ValueError as error:
                raise ValidationError(
                    f"invalid AllowedIPs network: {network_value}"
                ) from error
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValidationError(
                    "IPv6 routes require an IPv6-enabled AWG server"
                )
        if self.protocol_version not in {"1.5", "2", "3.1"}:
            raise ValidationError(
                "protocol_version must be one of 1.5, 2, or 3.1"
            )
        if not _IMAGE_REFERENCE.fullmatch(self.image):
            raise ValidationError(
                "image must be a valid Docker image reference"
            )

    @property
    def network(self) -> ipaddress.IPv4Network:
        return ipaddress.ip_network(self.subnet)

    @property
    def server_address(self) -> ipaddress.IPv4Address:
        return ipaddress.IPv4Address(int(self.network.network_address) + 1)

    def to_dict(self, *, include_secret: bool = False) -> dict[str, Any]:
        values = asdict(self)
        values["dns_servers"] = list(self.dns_servers)
        values["allowed_ips"] = list(self.allowed_ips)
        values["parameters"] = self.parameters.to_dict(
            include_secret=include_secret
        )
        return values

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> AwgSettings:
        data = dict(values)
        data["dns_servers"] = tuple(
            data.get("dns_servers", ("8.8.8.8", "8.8.4.4"))
        )
        data["allowed_ips"] = tuple(data.get("allowed_ips", ("0.0.0.0/0",)))
        data["parameters"] = AwgProtocolParameters(**data.get("parameters", {}))
        return cls(**data)


@dataclass(frozen=True, slots=True)
class PeerConfig:
    public_key: str
    preshared_key: str
    allowed_ips: tuple[str, ...]

    def __post_init__(self) -> None:
        object.__setattr__(self, "allowed_ips", tuple(self.allowed_ips))
        validate_key(self.public_key, "public_key")
        validate_key(self.preshared_key, "preshared_key")
        if not self.allowed_ips:
            raise ValidationError(
                "peer must have at least one AllowedIPs network"
            )
        for allowed_ip in self.allowed_ips:
            try:
                ipaddress.ip_network(allowed_ip, strict=False)
            except ValueError as error:
                raise ValidationError(
                    f"invalid peer AllowedIPs network: {allowed_ip}"
                ) from error


@dataclass(frozen=True, slots=True)
class StoredClient:
    client_id: str
    name: str
    address: str
    public_key: str
    allowed_ips: tuple[str, ...]
    created_at: str
    encrypted_private_key: str

    def __post_init__(self) -> None:
        try:
            UUID(self.client_id)
            address = ipaddress.ip_address(self.address)
        except ValueError as error:
            raise ValidationError(
                "stored client identity or address is invalid"
            ) from error
        if not isinstance(address, ipaddress.IPv4Address):
            raise ValidationError("stored client address must be IPv4")
        validate_client_name(self.name)
        validate_key(self.public_key, "stored client public key")
        if not self.allowed_ips or not self.encrypted_private_key:
            raise ValidationError("stored client is missing required data")
        for allowed_ip in self.allowed_ips:
            try:
                network = ipaddress.ip_network(allowed_ip, strict=False)
            except ValueError as error:
                raise ValidationError(
                    "stored client AllowedIPs is invalid"
                ) from error
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValidationError("stored client AllowedIPs must be IPv4")

    @classmethod
    def create(
        cls,
        *,
        name: str,
        address: str,
        public_key: str,
        allowed_ips: tuple[str, ...],
        encrypted_private_key: str,
    ) -> StoredClient:
        return cls(
            client_id=str(uuid4()),
            name=name,
            address=address,
            public_key=public_key,
            allowed_ips=allowed_ips,
            created_at=datetime.now(UTC).isoformat(),
            encrypted_private_key=encrypted_private_key,
        )

    def public_view(
        self,
        *,
        latest_handshake: int | None = None,
        received_bytes: int | None = None,
        sent_bytes: int | None = None,
    ) -> ClientView:
        return ClientView(
            client_id=self.client_id,
            name=self.name,
            address=self.address,
            public_key=self.public_key,
            allowed_ips=self.allowed_ips,
            created_at=self.created_at,
            latest_handshake=latest_handshake,
            received_bytes=received_bytes,
            sent_bytes=sent_bytes,
        )

    def to_dict(self) -> dict[str, Any]:
        values = asdict(self)
        values["allowed_ips"] = list(self.allowed_ips)
        return values

    @classmethod
    def from_dict(cls, values: dict[str, Any]) -> StoredClient:
        data = dict(values)
        data["allowed_ips"] = tuple(data["allowed_ips"])
        return cls(**data)


@dataclass(frozen=True, slots=True)
class ClientView:
    client_id: str
    name: str
    address: str
    public_key: str
    allowed_ips: tuple[str, ...]
    created_at: str
    latest_handshake: int | None = None
    received_bytes: int | None = None
    sent_bytes: int | None = None


@dataclass(frozen=True, slots=True)
class HostInfo:
    operating_system: str
    kernel_version: str
    architecture: str
    cpu_count: int
    memory_bytes: int
    docker_root_dir: str


@dataclass(frozen=True, slots=True)
class AwgParametersView:
    junk_packet_count: int
    junk_packet_min_size: int
    junk_packet_max_size: int
    init_packet_junk_size: int
    response_packet_junk_size: int
    cookie_reply_packet_junk_size: int
    transport_packet_junk_size: int
    init_packet_magic_header: str
    response_packet_magic_header: str
    underload_packet_magic_header: str
    transport_packet_magic_header: str
    special_junk_1: str
    special_junk_2: str
    special_junk_3: str
    special_junk_4: str
    special_junk_5: str
    content_padding_addition: str
    rekey_after_time: str
    rekey_timeout: str
    reject_after_time: str
    keepalive_timeout: str
    max_handshake_attempts: str
    random_trailers: str
    disable_cookies: str

    @classmethod
    def from_parameters(
        cls, parameters: AwgProtocolParameters
    ) -> AwgParametersView:
        values = parameters.to_dict(include_secret=False)
        values.pop("header_protection_key")
        return cls(**values)


@dataclass(frozen=True, slots=True)
class AwgSettingsView:
    endpoint_host: str
    listen_port: int
    subnet: str
    dns_servers: tuple[str, ...]
    allowed_ips: tuple[str, ...]
    mtu: int
    persistent_keepalive: int
    protocol_version: str
    image: str
    parameters: AwgParametersView

    @classmethod
    def from_settings(cls, settings: AwgSettings) -> AwgSettingsView:
        return cls(
            endpoint_host=settings.endpoint_host,
            listen_port=settings.listen_port,
            subnet=settings.subnet,
            dns_servers=settings.dns_servers,
            allowed_ips=settings.allowed_ips,
            mtu=settings.mtu,
            persistent_keepalive=settings.persistent_keepalive,
            protocol_version=settings.protocol_version,
            image=settings.image,
            parameters=AwgParametersView.from_parameters(settings.parameters),
        )


@dataclass(frozen=True, slots=True)
class ServerSnapshot:
    status: str
    endpoint: str | None
    listen_port: int | None
    protocol_version: str | None
    image: str | None
    image_id: str | None
    server_public_key: str | None
    settings: AwgSettingsView | None
    configured_peers: int
    active_peers: int
    observed_at: str
    host: HostInfo | None
    clients: tuple[ClientView, ...] = ()


def validate_client_name(name: str) -> str:
    if any(ord(character) < 32 for character in name):
        raise ValidationError("client name must not contain control characters")
    normalized = " ".join(name.split())
    if not normalized or len(normalized) > 80:
        raise ValidationError("client name must contain 1 to 80 characters")
    return normalized
