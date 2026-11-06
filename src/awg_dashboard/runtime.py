from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .errors import DockerRuntimeError
from .models import AwgSettings, HostInfo, validate_key

CONTAINER_NAME = "awg-dashboard-amneziawg"
CONTAINER_CONFIG_PATH = "/opt/amnezia/awg/awg0.conf"
_START_COMMAND = """set -eu
awg-quick up /opt/amnezia/awg/awg0.conf
iptables -A INPUT -i awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -j ACCEPT
iptables -A OUTPUT -o awg0 -j ACCEPT
iptables -A FORWARD -i awg0 -o eth0 -s "$AWG_SUBNET" -j ACCEPT
iptables -A FORWARD -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A POSTROUTING -s "$AWG_SUBNET" -o eth0 -j MASQUERADE
exec tail -f /dev/null"""
_SYNC_COMMAND = """set -eu
trap 'rm -f /tmp/awg-dashboard-sync.conf' EXIT
cat > /tmp/awg-dashboard-sync.conf
awg syncconf awg0 /tmp/awg-dashboard-sync.conf"""


@dataclass(frozen=True, slots=True)
class ContainerStatus:
    status: str
    restart_count: int


@dataclass(frozen=True, slots=True)
class RuntimePeer:
    public_key: str
    latest_handshake: int | None
    received_bytes: int
    sent_bytes: int


class DockerRuntime:
    def __init__(
        self,
        *,
        docker_command: str = "docker",
        command_timeout: float = 60.0,
        container_name: str = CONTAINER_NAME,
    ) -> None:
        self.docker_command = docker_command
        self.command_timeout = command_timeout
        self.container_name = container_name

    def host_info(self) -> HostInfo:
        output = self._run(
            [
                "info",
                "--format",
                "{{.OperatingSystem}}|{{.KernelVersion}}|{{.Architecture}}|"
                "{{.NCPU}}|{{.MemTotal}}|{{.DockerRootDir}}",
            ]
        ).stdout.strip()
        fields = output.split("|")
        if len(fields) != 6:
            raise DockerRuntimeError(
                "Docker returned incomplete host information"
            )
        try:
            return HostInfo(
                operating_system=fields[0],
                kernel_version=fields[1],
                architecture=fields[2],
                cpu_count=int(fields[3]),
                memory_bytes=int(fields[4]),
                docker_root_dir=fields[5],
            )
        except ValueError as error:
            raise DockerRuntimeError(
                "Docker returned invalid host information"
            ) from error

    def pull_image(self, image: str) -> None:
        self._run(["pull", image], timeout=max(self.command_timeout, 600.0))

    def image_id(self, image: str) -> str:
        image_id = self._run(
            ["image", "inspect", "--format", "{{.Id}}", image]
        ).stdout.strip()
        digest = image_id.removeprefix("sha256:")
        if len(digest) != 64 or any(
            character not in "0123456789abcdef" for character in digest
        ):
            raise DockerRuntimeError(
                "Docker returned an invalid image identifier"
            )
        return image_id

    def generate_key_pair(self, image: str) -> tuple[str, str]:
        private_key = self._run(
            [
                "run",
                "--rm",
                "--pull=missing",
                "--entrypoint",
                "awg",
                image,
                "genkey",
            ]
        ).stdout.strip()
        validate_key(private_key, "generated private key")
        public_key = self._run(
            [
                "run",
                "--rm",
                "-i",
                "--pull=missing",
                "--entrypoint",
                "awg",
                image,
                "pubkey",
            ],
            input_text=f"{private_key}\n",
        ).stdout.strip()
        validate_key(public_key, "generated public key")
        return private_key, public_key

    def generate_preshared_key(self, image: str) -> str:
        value = self._run(
            [
                "run",
                "--rm",
                "--pull=missing",
                "--entrypoint",
                "awg",
                image,
                "genpsk",
            ]
        ).stdout.strip()
        return validate_key(value, "generated preshared key")

    def create_container(
        self,
        settings: AwgSettings,
        *,
        image: str,
        config_path: Path,
    ) -> None:
        host_config = config_path.resolve()
        if not host_config.is_file():
            raise DockerRuntimeError("AWG config file does not exist")
        command = [
            "run",
            "--detach",
            "--name",
            self.container_name,
            "--restart",
            "unless-stopped",
            "--privileged",
            "--publish",
            f"{settings.listen_port}:{settings.listen_port}/udp",
            "--volume",
            f"{host_config}:{CONTAINER_CONFIG_PATH}:ro",
            "--env",
            f"AWG_SUBNET={settings.subnet}",
            "--sysctl",
            "net.ipv4.conf.all.src_valid_mark=1",
            "--sysctl",
            "net.ipv4.ip_forward=1",
            "--volume",
            "/lib/modules:/lib/modules:ro",
        ]
        command.extend(
            [
                "--entrypoint",
                "/bin/sh",
                image,
                "-c",
                _START_COMMAND,
            ]
        )
        self._run(command, timeout=max(self.command_timeout, 180.0))

    def remove_container(self) -> None:
        if self.container_status() is None:
            return
        self._run(["rm", "--force", self.container_name])

    def stop_container(self) -> None:
        status = self.container_status()
        if status is not None and status.status == "running":
            self._run(["stop", self.container_name])

    def container_status(self) -> ContainerStatus | None:
        result = self._run(
            [
                "inspect",
                "--format",
                "{{.State.Status}}|{{.RestartCount}}",
                self.container_name,
            ],
            check=False,
        )
        if result.returncode != 0:
            if (
                "no such object" in result.stderr.lower()
                or "not found" in result.stderr.lower()
            ):
                return None
            raise DockerRuntimeError("failed to inspect the AWG container")
        try:
            status, restart_count = result.stdout.strip().split("|", maxsplit=1)
            return ContainerStatus(
                status=status,
                restart_count=int(restart_count),
            )
        except (ValueError, TypeError) as error:
            raise DockerRuntimeError(
                "Docker returned invalid container state"
            ) from error

    def apply_config(self) -> None:
        stripped = self._run(
            [
                "exec",
                self.container_name,
                "awg-quick",
                "strip",
                CONTAINER_CONFIG_PATH,
            ]
        ).stdout
        if not stripped.strip():
            raise DockerRuntimeError("AWG produced an empty runtime config")
        self._run(
            [
                "exec",
                "--interactive",
                self.container_name,
                "sh",
                "-c",
                _SYNC_COMMAND,
            ],
            input_text=stripped,
        )

    def runtime_peers(self) -> dict[str, RuntimePeer]:
        output = self._run(
            ["exec", self.container_name, "awg", "show", "awg0", "dump"]
        ).stdout
        peers: dict[str, RuntimePeer] = {}
        for line in output.splitlines()[1:]:
            fields = line.split("\t")
            if len(fields) < 8:
                continue
            public_key = fields[0]
            try:
                handshake = int(fields[4])
                received = int(fields[5])
                sent = int(fields[6])
            except ValueError as error:
                raise DockerRuntimeError(
                    "AWG returned invalid peer statistics"
                ) from error
            peers[public_key] = RuntimePeer(
                public_key=public_key,
                latest_handshake=handshake or None,
                received_bytes=received,
                sent_bytes=sent,
            )
        return peers

    def _run(
        self,
        arguments: list[str],
        *,
        input_text: str | None = None,
        check: bool = True,
        timeout: float | None = None,
    ) -> subprocess.CompletedProcess[str]:
        try:
            result = subprocess.run(
                [self.docker_command, *arguments],
                input=input_text,
                capture_output=True,
                check=False,
                text=True,
                timeout=timeout or self.command_timeout,
                env={**os.environ, "LC_ALL": "C"},
            )
        except FileNotFoundError as error:
            raise DockerRuntimeError(
                "Docker CLI is not installed in the dashboard container"
            ) from error
        except subprocess.TimeoutExpired:
            raise DockerRuntimeError("Docker command timed out") from None
        if check and result.returncode != 0:
            raise DockerRuntimeError(
                f"Docker command failed with exit code {result.returncode}"
            )
        return result
