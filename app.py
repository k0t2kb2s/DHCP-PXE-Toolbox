from __future__ import annotations

import ipaddress
import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel

from config_store import (
    ConfigError,
    ConfigStore,
    DuplicateMACError,
    MACNotFoundError,
)
from tftp_core import TFTPServer
from vendor_db import load_manuf, lookup_vendor


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", BASE_DIR / "config.json"))
MANUF_PATH = Path(os.getenv("MANUF_PATH", BASE_DIR / "manuf"))
TFTP_ROOT = Path(os.getenv("TFTP_ROOT", BASE_DIR / "tftpboot"))

LOGGER = logging.getLogger(__name__)
config_store = ConfigStore(CONFIG_PATH)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class MACRequest(BaseModel):
    mac: str
    pxe_enabled: bool = True


class WhitelistEntry(BaseModel):
    mac: str
    pxe_enabled: bool
    vendor: str


class DHCPSettings(BaseModel):
    pool_start: str
    pool_end: str
    subnet_mask: str
    router: str
    pxe_next_server: str
    pxe_boot_file: str


class DHCPStatus(BaseModel):
    enabled: bool
    running: bool
    interface: Optional[str]
    label: str
    leases_used: int
    pool_size: int
    pool_usage_percent: int


def _run_dhcp(app: FastAPI) -> None:
    try:
        from dhcp_server import DHCPServer

        server = DHCPServer(CONFIG_PATH, os.getenv("DHCP_INTERFACE") or None)
        app.state.dhcp_server = server
        app.state.dhcp_error = None
        server.serve_forever()
    except Exception as exc:
        app.state.dhcp_error = str(exc)
        LOGGER.exception("DHCP-поток остановлен из-за ошибки")


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        app.state.vendors = load_manuf(MANUF_PATH)
        LOGGER.info("Загружено %d MAC-префиксов из %s", len(app.state.vendors), MANUF_PATH)
    except OSError as exc:
        LOGGER.error("Не удалось прочитать базу вендоров %s: %s", MANUF_PATH, exc)
        app.state.vendors = {}

    app.state.dhcp_server = None
    app.state.dhcp_error = None
    app.state.tftp_server = None
    app.state.tftp_error = None

    dhcp_enabled = os.getenv("DHCP_ENABLED", "").lower() in {"1", "true", "yes", "on"}
    tftp_enabled = os.getenv("TFTP_ENABLED", "").lower() not in {"0", "false", "no", "off"}
    if tftp_enabled:
        tftp_server = TFTPServer(TFTP_ROOT)
        app.state.tftp_server = tftp_server
        tftp_server.start()
        LOGGER.info("Запущен TFTP-поток")

    if dhcp_enabled:
        thread = threading.Thread(target=_run_dhcp, args=(app,), daemon=True, name="dhcp-server")
        thread.start()
        app.state.dhcp_thread = thread
        LOGGER.info("Запущен DHCP-поток")

    yield

    if app.state.dhcp_server is not None:
        app.state.dhcp_server.stop()
    if app.state.tftp_server is not None:
        app.state.tftp_server.stop()


app = FastAPI(title="PXE DHCP Whitelist", lifespan=lifespan)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")


@app.get("/api/whitelist", response_model=list[WhitelistEntry])
async def get_whitelist(request: Request):
    try:
        config = config_store.load()
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    vendors = getattr(request.app.state, "vendors", {})
    return [
        WhitelistEntry(
            mac=entry["mac"],
            pxe_enabled=entry["pxe_enabled"],
            vendor=lookup_vendor(entry["mac"], vendors),
        )
        for entry in config["whitelist"]
    ]


@app.get("/api/settings", response_model=dict[str, str])
async def get_settings():
    try:
        return config_store.load()["dhcp_settings"]
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@app.put("/api/settings", response_model=dict[str, str])
@app.patch("/api/settings", response_model=dict[str, str])
async def update_settings(payload: DHCPSettings):
    settings = payload.model_dump()
    settings["pxe_boot_file"] = settings["pxe_boot_file"].strip()
    try:
        return config_store.update_dhcp_settings(settings)
    except ConfigError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@app.get("/api/status", response_model=DHCPStatus)
async def get_status(request: Request):
    try:
        settings = config_store.load()["dhcp_settings"]
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    server = getattr(request.app.state, "dhcp_server", None)
    thread = getattr(request.app.state, "dhcp_thread", None)
    enabled = os.getenv("DHCP_ENABLED", "").lower() in {"1", "true", "yes", "on"}
    running = bool(server is not None and thread is not None and thread.is_alive())
    interface = getattr(server, "interface", None) or os.getenv("DHCP_INTERFACE") or None
    leases_used = _count_active_leases(server, settings)
    pool_size = _pool_size(settings)
    usage = round((leases_used / pool_size) * 100) if pool_size else 0

    if running:
        label = f"Слушает {interface}" if interface else "Слушает интерфейс"
    elif getattr(request.app.state, "dhcp_error", None):
        label = "Остановлен после ошибки"
    else:
        label = "Остановлен"

    return DHCPStatus(
        enabled=enabled,
        running=running,
        interface=interface,
        label=label,
        leases_used=leases_used,
        pool_size=pool_size,
        pool_usage_percent=max(0, min(100, usage)),
    )


def _pool_size(settings: dict[str, Any]) -> int:
    try:
        start = ipaddress.IPv4Address(settings["pool_start"])
        end = ipaddress.IPv4Address(settings["pool_end"])
    except (KeyError, ValueError, TypeError):
        return 0
    if end < start:
        return 0
    return int(end) - int(start) + 1


def _count_active_leases(server: Any, settings: dict[str, Any]) -> int:
    if server is None or not hasattr(server, "allocator"):
        return 0
    try:
        start = ipaddress.IPv4Address(settings["pool_start"])
        end = ipaddress.IPv4Address(settings["pool_end"])
        leases = server.allocator.snapshot()
    except Exception:
        LOGGER.debug("Не удалось получить DHCP leases", exc_info=True)
        return 0

    count = 0
    for address in leases:
        try:
            ip = ipaddress.IPv4Address(address)
        except ValueError:
            continue
        if start <= ip <= end:
            count += 1
    return count


@app.post("/api/whitelist", response_model=WhitelistEntry, status_code=status.HTTP_201_CREATED)
async def add_to_whitelist(payload: MACRequest, request: Request):
    try:
        entry = config_store.add_mac(payload.mac, payload.pxe_enabled)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DuplicateMACError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    vendors = getattr(request.app.state, "vendors", {})
    return WhitelistEntry(
        mac=entry["mac"],
        pxe_enabled=entry["pxe_enabled"],
        vendor=lookup_vendor(entry["mac"], vendors),
    )


@app.put("/api/whitelist", response_model=WhitelistEntry)
@app.patch("/api/whitelist", response_model=WhitelistEntry)
async def update_whitelist_entry(payload: MACRequest, request: Request):
    try:
        entry = config_store.update_mac_pxe(payload.mac, payload.pxe_enabled)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MACNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    vendors = getattr(request.app.state, "vendors", {})
    return WhitelistEntry(
        mac=entry["mac"],
        pxe_enabled=entry["pxe_enabled"],
        vendor=lookup_vendor(entry["mac"], vendors),
    )


@app.delete("/api/whitelist", response_model=WhitelistEntry)
async def remove_from_whitelist(payload: MACRequest, request: Request):
    try:
        entry = config_store.remove_mac(payload.mac)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MACNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    vendors = getattr(request.app.state, "vendors", {})
    return WhitelistEntry(
        mac=entry["mac"],
        pxe_enabled=entry["pxe_enabled"],
        vendor=lookup_vendor(entry["mac"], vendors),
    )


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    uvicorn.run("app:app", host="0.0.0.0", port=8000)
