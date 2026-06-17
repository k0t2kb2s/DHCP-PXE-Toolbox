from __future__ import annotations

import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path

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
from vendor_db import load_manuf, lookup_vendor


BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = Path(os.getenv("CONFIG_PATH", BASE_DIR / "config.json"))
MANUF_PATH = Path(os.getenv("MANUF_PATH", BASE_DIR / "manuf"))

LOGGER = logging.getLogger(__name__)
config_store = ConfigStore(CONFIG_PATH)
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


class MACRequest(BaseModel):
    mac: str


class WhitelistEntry(BaseModel):
    mac: str
    vendor: str


def _run_dhcp(app: FastAPI) -> None:
    try:
        from dhcp_server import DHCPServer

        server = DHCPServer(CONFIG_PATH, os.getenv("DHCP_INTERFACE") or None)
        app.state.dhcp_server = server
        server.serve_forever()
    except Exception:
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
    if os.getenv("DHCP_ENABLED", "").lower() in {"1", "true", "yes", "on"}:
        thread = threading.Thread(target=_run_dhcp, args=(app,), daemon=True, name="dhcp-server")
        thread.start()
        app.state.dhcp_thread = thread
        LOGGER.info("Запущен DHCP-поток")

    yield

    if app.state.dhcp_server is not None:
        app.state.dhcp_server.stop()


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
        WhitelistEntry(mac=mac, vendor=lookup_vendor(mac, vendors))
        for mac in config["whitelist"]
    ]


@app.get("/api/settings", response_model=dict[str, str])
async def get_settings():
    try:
        return config_store.load()["dhcp_settings"]
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc


@app.post("/api/whitelist", response_model=WhitelistEntry, status_code=status.HTTP_201_CREATED)
async def add_to_whitelist(payload: MACRequest, request: Request):
    try:
        mac = config_store.add_mac(payload.mac)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except DuplicateMACError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    vendors = getattr(request.app.state, "vendors", {})
    return WhitelistEntry(mac=mac, vendor=lookup_vendor(mac, vendors))


@app.delete("/api/whitelist", response_model=WhitelistEntry)
async def remove_from_whitelist(payload: MACRequest, request: Request):
    try:
        mac = config_store.remove_mac(payload.mac)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except MACNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ConfigError as exc:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail=str(exc)) from exc

    vendors = getattr(request.app.state, "vendors", {})
    return WhitelistEntry(mac=mac, vendor=lookup_vendor(mac, vendors))


if __name__ == "__main__":
    import uvicorn

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    uvicorn.run("app:app", host="0.0.0.0", port=8000)
