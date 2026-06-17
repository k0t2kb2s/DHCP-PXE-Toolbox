from __future__ import annotations

from contextlib import contextmanager
import copy
import ipaddress
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, Optional, Union


MAC_PATTERNS = (
    re.compile(r"^[0-9a-fA-F]{12}$"),
    re.compile(r"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"),
    re.compile(r"^(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}$"),
)


class ConfigError(RuntimeError):
    pass


class DuplicateMACError(ConfigError):
    pass


class MACNotFoundError(ConfigError):
    pass


_CONFIG_LOCKS_GUARD = threading.Lock()
_CONFIG_LOCKS: Dict[Path, threading.RLock] = {}


def get_config_lock(path: Union[str, Path]) -> threading.RLock:
    resolved_path = Path(path).resolve(strict=False)
    with _CONFIG_LOCKS_GUARD:
        lock = _CONFIG_LOCKS.get(resolved_path)
        if lock is None:
            lock = threading.RLock()
            _CONFIG_LOCKS[resolved_path] = lock
        return lock


@contextmanager
def locked_config_file(path: Path):
    lock_path = path.with_name(f".{path.name}.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+b") as lock_file:
        if os.name == "nt":
            import msvcrt

            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                lock_file.seek(0)
                msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        else:
            import fcntl

            fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)


def normalize_mac(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("MAC-адрес должен быть строкой")

    value = value.strip()
    if not any(pattern.fullmatch(value) for pattern in MAC_PATTERNS):
        raise ValueError("Некорректный MAC-адрес")

    compact = re.sub(r"[:.\-]", "", value).lower()
    return ":".join(compact[index : index + 2] for index in range(0, 12, 2))


def validate_config(config: Any) -> Dict[str, Any]:
    if not isinstance(config, dict):
        raise ConfigError("Корень config.json должен быть JSON-объектом")

    settings = config.get("dhcp_settings")
    whitelist = config.get("whitelist")
    if not isinstance(settings, dict) or not isinstance(whitelist, list):
        raise ConfigError("config.json должен содержать dhcp_settings и whitelist")

    required = {
        "pool_start",
        "pool_end",
        "subnet_mask",
        "router",
        "pxe_next_server",
        "pxe_boot_file",
    }
    missing = required.difference(settings)
    if missing:
        raise ConfigError(f"В dhcp_settings отсутствуют поля: {', '.join(sorted(missing))}")

    try:
        pool_start = ipaddress.IPv4Address(settings["pool_start"])
        pool_end = ipaddress.IPv4Address(settings["pool_end"])
        ipaddress.IPv4Address(settings["router"])
        ipaddress.IPv4Address(settings["pxe_next_server"])
        network = ipaddress.IPv4Network(
            f"{settings['pool_start']}/{settings['subnet_mask']}", strict=False
        )
    except (ValueError, TypeError) as exc:
        raise ConfigError(f"Некорректные DHCP-настройки: {exc}") from exc

    if pool_start > pool_end:
        raise ConfigError("pool_start не может быть больше pool_end")
    if pool_end not in network:
        raise ConfigError("Начало и конец пула должны находиться в одной подсети")
    if not isinstance(settings["pxe_boot_file"], str) or not settings["pxe_boot_file"].strip():
        raise ConfigError("pxe_boot_file не может быть пустым")

    normalized_whitelist: list[str] = []
    for mac in whitelist:
        try:
            normalized = normalize_mac(mac)
        except ValueError as exc:
            raise ConfigError(f"Некорректный MAC-адрес в whitelist: {mac!r}") from exc
        if normalized not in normalized_whitelist:
            normalized_whitelist.append(normalized)

    validated = copy.deepcopy(config)
    validated["whitelist"] = normalized_whitelist
    return validated


class ConfigStore:
    def __init__(self, path: Union[str, Path]) -> None:
        self.path = Path(path)
        self._lock = get_config_lock(self.path)

    def load(self) -> Dict[str, Any]:
        with self._lock:
            with locked_config_file(self.path):
                return self._read_unlocked()

    def add_mac(self, value: str) -> str:
        normalized = normalize_mac(value)
        with self._lock:
            with locked_config_file(self.path):
                config = self._read_unlocked()
                if normalized in config["whitelist"]:
                    raise DuplicateMACError(f"{normalized} уже есть в вайтлисте")
                config["whitelist"].append(normalized)
                self._write_unlocked(config)
        return normalized

    def remove_mac(self, value: str) -> str:
        normalized = normalize_mac(value)
        with self._lock:
            with locked_config_file(self.path):
                config = self._read_unlocked()
                if normalized not in config["whitelist"]:
                    raise MACNotFoundError(f"{normalized} отсутствует в вайтлисте")
                config["whitelist"].remove(normalized)
                self._write_unlocked(config)
        return normalized

    def update_dhcp_settings(self, settings: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock:
            with locked_config_file(self.path):
                config = self._read_unlocked()
                config["dhcp_settings"].update(settings)
                self._write_unlocked(config)
                return copy.deepcopy(config["dhcp_settings"])

    def _read_unlocked(self) -> Dict[str, Any]:
        try:
            raw = self.path.read_text(encoding="utf-8")
        except FileNotFoundError as exc:
            raise ConfigError(f"Файл конфигурации не найден: {self.path}") from exc
        except OSError as exc:
            raise ConfigError(f"Не удалось прочитать config.json: {exc}") from exc

        if not raw.strip():
            raise ConfigError("config.json пуст")
        try:
            return validate_config(json.loads(raw))
        except json.JSONDecodeError as exc:
            raise ConfigError(f"Некорректный JSON в config.json: {exc}") from exc

    def _write_unlocked(self, config: Dict[str, Any]) -> None:
        validated = validate_config(config)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp_path: Optional[str] = None
        try:
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=self.path.parent,
                prefix=f".{self.path.name}.",
                delete=False,
            ) as temp_file:
                temp_path = temp_file.name
                json.dump(validated, temp_file, ensure_ascii=False, indent=2)
                temp_file.write("\n")
                temp_file.flush()
                os.fsync(temp_file.fileno())
            os.replace(temp_path, self.path)
        except OSError as exc:
            raise ConfigError(f"Не удалось записать config.json: {exc}") from exc
        finally:
            if temp_path and os.path.exists(temp_path):
                os.unlink(temp_path)
