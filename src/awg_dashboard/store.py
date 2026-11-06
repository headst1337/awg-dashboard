from __future__ import annotations

import fcntl
import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from cryptography.fernet import Fernet, InvalidToken

from .errors import StateStoreError, ValidationError
from .models import AwgSettings, StoredClient


class StateStore:
    def __init__(
        self,
        root: Path | str = "/var/lib/awg-dashboard",
        *,
        master_key: bytes | str | None = None,
    ) -> None:
        self.root = Path(root).expanduser().absolute()
        if self.root.is_symlink():
            raise StateStoreError("state directory must not be a symlink")
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(self.root, 0o700)
        with self.locked():
            self._fernet = self._load_fernet(master_key)

    @property
    def config_path(self) -> Path:
        return self.root / "awg0.conf"

    def read_config(self) -> str:
        try:
            return self.config_path.read_text(encoding="utf-8")
        except OSError as error:
            raise StateStoreError(
                "failed to read the AWG server config"
            ) from error

    def save_config(self, config: str) -> None:
        self._atomic_write(self.config_path, config.encode("utf-8"), 0o600)

    def delete_config(self) -> None:
        try:
            self.config_path.unlink(missing_ok=True)
        except OSError as error:
            raise StateStoreError(
                "failed to remove the AWG server config"
            ) from error

    def encrypt_secret(self, value: str) -> str:
        return self._fernet.encrypt(value.encode("utf-8")).decode("ascii")

    def decrypt_secret(self, value: str) -> str:
        try:
            return self._fernet.decrypt(value.encode("ascii")).decode("utf-8")
        except (InvalidToken, UnicodeError, ValueError) as error:
            raise StateStoreError(
                "failed to decrypt a stored client secret"
            ) from error

    def load_clients(self) -> list[StoredClient]:
        path = self.root / "clients.json"
        if not path.exists():
            return []
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(raw, list):
                raise ValueError("client store is not a list")
            clients = [StoredClient.from_dict(item) for item in raw]
        except (
            OSError,
            ValueError,
            TypeError,
            KeyError,
            ValidationError,
        ) as error:
            raise StateStoreError(
                "client state is invalid or unreadable"
            ) from error
        ids = [client.client_id for client in clients]
        public_keys = [client.public_key for client in clients]
        if len(ids) != len(set(ids)) or len(public_keys) != len(
            set(public_keys)
        ):
            raise StateStoreError("client state contains duplicate identifiers")
        return clients

    def save_clients(self, clients: list[StoredClient]) -> None:
        contents = json.dumps(
            [client.to_dict() for client in clients],
            ensure_ascii=False,
            indent=2,
        ).encode("utf-8")
        self._atomic_write(self.root / "clients.json", contents, 0o600)

    def load_server_metadata(self) -> dict[str, Any] | None:
        path = self.root / "server.json"
        if not path.exists():
            return None
        try:
            values = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(values, dict):
                raise ValueError("server state is not an object")
            return values
        except (OSError, ValueError, TypeError) as error:
            raise StateStoreError(
                "server metadata is invalid or unreadable"
            ) from error

    def save_server_metadata(
        self,
        settings: AwgSettings,
        *,
        image: str,
        server_public_key: str,
        runtime_image_id: str | None = None,
        created_at: str | None = None,
    ) -> None:
        previous = self.load_server_metadata()
        values = {
            "settings": settings.to_dict(include_secret=False),
            "image": image,
            "image_id": runtime_image_id or (previous or {}).get("image_id"),
            "server_public_key": server_public_key,
            "created_at": created_at or (previous or {}).get("created_at"),
        }
        contents = json.dumps(values, ensure_ascii=False, indent=2).encode(
            "utf-8"
        )
        self._atomic_write(self.root / "server.json", contents, 0o600)

    def delete_server_metadata(self) -> None:
        try:
            (self.root / "server.json").unlink(missing_ok=True)
        except OSError as error:
            raise StateStoreError("failed to remove server metadata") from error

    @contextmanager
    def locked(self) -> Iterator[None]:
        lock_path = self.root / ".state.lock"
        descriptor: int | None = None
        try:
            descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            if descriptor is not None:
                os.close(descriptor)
            raise StateStoreError("failed to lock dashboard state") from error
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _load_fernet(self, master_key: bytes | str | None) -> Fernet:
        configured_key = (
            master_key
            if master_key is not None
            else os.environ.get("AWG_DASHBOARD_MASTER_KEY")
        )
        if configured_key is not None:
            key = (
                configured_key.encode("ascii")
                if isinstance(configured_key, str)
                else configured_key
            )
            try:
                return Fernet(key)
            except (TypeError, ValueError) as error:
                raise StateStoreError(
                    "configured state encryption key is invalid"
                ) from error

        key_path = self.root / "master.key"
        try:
            descriptor = os.open(
                key_path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            try:
                key = key_path.read_bytes()
                mode = key_path.stat().st_mode & 0o777
            except OSError as error:
                raise StateStoreError(
                    "failed to read the state encryption key"
                ) from error
            if mode & 0o077:
                raise StateStoreError(
                    "state encryption key permissions must be 0600"
                )
        except OSError as error:
            raise StateStoreError(
                "failed to create the state encryption key"
            ) from error
        else:
            key = Fernet.generate_key()
            try:
                with os.fdopen(descriptor, "wb") as key_file:
                    key_file.write(key)
                    key_file.flush()
                    os.fsync(key_file.fileno())
            except OSError as error:
                raise StateStoreError(
                    "failed to persist the state encryption key"
                ) from error
        try:
            return Fernet(key)
        except (TypeError, ValueError) as error:
            raise StateStoreError("state encryption key is invalid") from error

    @staticmethod
    def _atomic_write(path: Path, contents: bytes, mode: int) -> None:
        descriptor, temporary_name = tempfile.mkstemp(
            dir=path.parent, prefix=f".{path.name}."
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "wb") as output:
                output.write(contents)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_path, path)
            directory_descriptor = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
        except OSError as error:
            try:
                os.close(descriptor)
            except OSError:
                pass
            temporary_path.unlink(missing_ok=True)
            raise StateStoreError(f"failed to persist {path.name}") from error
