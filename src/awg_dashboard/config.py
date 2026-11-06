from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from .errors import ValidationError
from .models import (
    AwgProtocolParameters,
    AwgSettings,
    PeerConfig,
    format_endpoint,
    validate_key,
)

_PARAMETER_KEYS = {
    "Jc": "junk_packet_count",
    "Jmin": "junk_packet_min_size",
    "Jmax": "junk_packet_max_size",
    "S1": "init_packet_junk_size",
    "S2": "response_packet_junk_size",
    "S3": "cookie_reply_packet_junk_size",
    "S4": "transport_packet_junk_size",
    "H1": "init_packet_magic_header",
    "H2": "response_packet_magic_header",
    "H3": "underload_packet_magic_header",
    "H4": "transport_packet_magic_header",
    "I1": "special_junk_1",
    "I2": "special_junk_2",
    "I3": "special_junk_3",
    "I4": "special_junk_4",
    "I5": "special_junk_5",
    "HeaderProtectionKey": "header_protection_key",
    "ContentPaddingAddition": "content_padding_addition",
    "RekeyAfterTime": "rekey_after_time",
    "RekeyTimeout": "rekey_timeout",
    "RejectAfterTime": "reject_after_time",
    "KeepaliveTimeout": "keepalive_timeout",
    "MaxHandshakeAttempts": "max_handshake_attempts",
    "RandomTrailers": "random_trailers",
    "DisableCookies": "disable_cookies",
}
_INTEGER_PARAMETER_FIELDS = {
    "junk_packet_count",
    "junk_packet_min_size",
    "junk_packet_max_size",
    "init_packet_junk_size",
    "response_packet_junk_size",
    "cookie_reply_packet_junk_size",
    "transport_packet_junk_size",
}


@dataclass(frozen=True, slots=True)
class ServerDocument:
    private_key: str
    address: str
    listen_port: int
    parameters: AwgProtocolParameters
    peers: tuple[PeerConfig, ...] = ()

    def __post_init__(self) -> None:
        validate_key(self.private_key, "server private key")
        try:
            interface = ipaddress.ip_interface(self.address)
        except ValueError as error:
            raise ValidationError(
                "server address must be an IPv4 interface address"
            ) from error
        if not isinstance(interface, ipaddress.IPv4Interface):
            raise ValidationError(
                "server address must be an IPv4 interface address"
            )
        if not 1 <= self.listen_port <= 65535:
            raise ValidationError(
                "server listen port must be between 1 and 65535"
            )
        public_keys = [peer.public_key for peer in self.peers]
        if len(public_keys) != len(set(public_keys)):
            raise ValidationError(
                "server config contains duplicate peer public keys"
            )


def render_server_config(
    settings: AwgSettings,
    *,
    private_key: str,
    parameters: AwgProtocolParameters,
    peers: tuple[PeerConfig, ...] = (),
) -> str:
    document = ServerDocument(
        private_key=private_key,
        address=f"{settings.server_address}/{settings.network.prefixlen}",
        listen_port=settings.listen_port,
        parameters=parameters,
        peers=peers,
    )
    lines = [
        "[Interface]",
        f"PrivateKey = {document.private_key}",
        f"Address = {document.address}",
        f"ListenPort = {document.listen_port}",
    ]
    for name, value in document.parameters.to_awg_fields(
        include_special_junk=False,
        protocol_version=settings.protocol_version,
    ):
        if name.startswith("# "):
            lines.append(f"# {name[2:]} = {value}")
        else:
            lines.append(f"{name} = {value}")
    for peer in document.peers:
        lines.extend(
            [
                "",
                "[Peer]",
                f"PublicKey = {peer.public_key}",
                f"PresharedKey = {peer.preshared_key}",
                f"AllowedIPs = {', '.join(peer.allowed_ips)}",
            ]
        )
    return "\n".join(lines) + "\n"


def parse_server_config(config: str) -> ServerDocument:
    interface: dict[str, str] = {}
    peers: list[dict[str, str]] = []
    current: dict[str, str] | None = None

    for raw_line in config.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            content = line[1:].strip()
            name, separator, value = content.partition("=")
            if separator and name.strip() in {"I1", "I2", "I3", "I4", "I5"}:
                interface[name.strip()] = value.strip()
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            if section == "Interface":
                if current is not None:
                    raise ValidationError(
                        "server config contains multiple Interface sections"
                    )
                current = interface
            elif section == "Peer":
                current = {}
                peers.append(current)
            else:
                raise ValidationError(
                    f"unsupported AWG config section: {section}"
                )
            continue
        if current is None:
            raise ValidationError("AWG config has settings outside a section")
        name, separator, value = line.partition("=")
        if not separator:
            raise ValidationError("AWG config contains a malformed setting")
        key = name.strip()
        if key in current:
            raise ValidationError(
                f"AWG config contains duplicate setting: {key}"
            )
        current[key] = value.strip()

    try:
        private_key = interface["PrivateKey"]
        address = interface["Address"]
        listen_port = int(interface["ListenPort"])
    except (KeyError, ValueError) as error:
        raise ValidationError(
            "AWG config is missing required interface settings"
        ) from error

    parameter_values: dict[str, str | int] = {}
    for awg_name, attribute in _PARAMETER_KEYS.items():
        value = interface.get(awg_name, "")
        if value:
            try:
                parameter_values[attribute] = (
                    int(value)
                    if attribute in _INTEGER_PARAMETER_FIELDS
                    else value
                )
            except ValueError as error:
                raise ValidationError(
                    f"AWG config has an invalid {awg_name} value"
                ) from error
    try:
        parameters = AwgProtocolParameters(**parameter_values)
    except TypeError as error:
        raise ValidationError(
            "AWG config contains invalid protocol parameters"
        ) from error

    parsed_peers: list[PeerConfig] = []
    for peer in peers:
        try:
            parsed_peers.append(
                PeerConfig(
                    public_key=peer["PublicKey"],
                    preshared_key=peer["PresharedKey"],
                    allowed_ips=tuple(
                        item.strip()
                        for item in peer["AllowedIPs"].split(",")
                        if item.strip()
                    ),
                )
            )
        except KeyError as error:
            raise ValidationError(
                "AWG peer is missing required settings"
            ) from error

    return ServerDocument(
        private_key=private_key,
        address=address,
        listen_port=listen_port,
        parameters=parameters,
        peers=tuple(parsed_peers),
    )


def build_client_config(
    settings: AwgSettings,
    *,
    client_address: str,
    private_key: str,
    server_public_key: str,
    preshared_key: str,
    parameters: AwgProtocolParameters,
    allowed_ips: tuple[str, ...] | None = None,
) -> str:
    validate_key(private_key, "client private key")
    validate_key(server_public_key, "server public key")
    validate_key(preshared_key, "preshared key")
    try:
        address = ipaddress.ip_address(client_address)
    except ValueError as error:
        raise ValidationError("client_address must be an IP address") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValidationError("client_address must be an IPv4 address")

    lines = [
        "[Interface]",
        f"Address = {address}/32",
        f"DNS = {', '.join(settings.dns_servers)}",
        f"PrivateKey = {private_key}",
        f"MTU = {settings.mtu}",
    ]
    lines.extend(
        f"{name} = {value}"
        for name, value in parameters.to_awg_fields(
            protocol_version=settings.protocol_version
        )
    )
    peer_allowed_ips = allowed_ips or settings.allowed_ips
    lines.extend(
        [
            "",
            "[Peer]",
            f"PublicKey = {server_public_key}",
            f"PresharedKey = {preshared_key}",
            f"AllowedIPs = {', '.join(peer_allowed_ips)}",
            f"Endpoint = {format_endpoint(settings.endpoint_host, settings.listen_port)}",
            f"PersistentKeepalive = {settings.persistent_keepalive}",
        ]
    )
    return "\n".join(lines) + "\n"


def allocate_client_address(
    settings: AwgSettings,
    peers: tuple[PeerConfig, ...],
) -> ipaddress.IPv4Address:
    validate_peer_addresses(settings, peers)
    network = settings.network
    occupied = {settings.server_address}
    for peer in peers:
        for allowed_ip in peer.allowed_ips:
            try:
                parsed = ipaddress.ip_network(allowed_ip, strict=False)
            except ValueError:
                continue
            if (
                isinstance(parsed, ipaddress.IPv4Network)
                and parsed.prefixlen == 32
            ):
                occupied.add(parsed.network_address)

    candidate = ipaddress.IPv4Address(int(network.network_address) + 2)
    last_host = ipaddress.IPv4Address(int(network.broadcast_address) - 1)
    while int(candidate) <= int(last_host):
        if candidate not in occupied:
            return candidate
        candidate = ipaddress.IPv4Address(int(candidate) + 1)
    raise ValidationError("no free client addresses remain in the AWG subnet")


def peer_client_address(peer: PeerConfig) -> str | None:
    for allowed_ip in peer.allowed_ips:
        parsed = ipaddress.ip_network(allowed_ip, strict=False)
        if isinstance(parsed, ipaddress.IPv4Network) and parsed.prefixlen == 32:
            return str(parsed.network_address)
    return None


def validate_peer_addresses(
    settings: AwgSettings,
    peers: tuple[PeerConfig, ...],
) -> None:
    network = settings.network
    occupied = {settings.server_address}
    for peer in peers:
        for allowed_ip in peer.allowed_ips:
            parsed = ipaddress.ip_network(allowed_ip, strict=False)
            if not isinstance(
                parsed, ipaddress.IPv4Network
            ) or not parsed.overlaps(network):
                continue
            if parsed.prefixlen != 32:
                raise ValidationError(
                    "an existing peer overlaps the AWG client subnet"
                )
            address = parsed.network_address
            if (
                address in {network.network_address, network.broadcast_address}
                or address == settings.server_address
                or address in occupied
            ):
                raise ValidationError(
                    "existing peers contain a conflicting client address"
                )
            occupied.add(address)
