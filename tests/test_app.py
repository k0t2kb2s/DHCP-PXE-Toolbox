import json

from fastapi.testclient import TestClient

import app as app_module
from config_store import ConfigStore


def make_config():
    return {
        "dhcp_settings": {
            "pool_start": "192.168.50.100",
            "pool_end": "192.168.50.102",
            "subnet_mask": "255.255.255.0",
            "router": "192.168.50.1",
            "pxe_next_server": "192.168.50.10",
            "pxe_boot_file": "pxelinux.0",
        },
        "whitelist": [],
    }


def test_whitelist_api(monkeypatch, tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(make_config()), encoding="utf-8")
    monkeypatch.setattr(app_module, "config_store", ConfigStore(path))

    with TestClient(app_module.app) as client:
        created = client.post("/api/whitelist", json={"mac": "00-00-0C-AA-BB-CC"})
        assert created.status_code == 201
        assert created.json() == {
            "mac": "00:00:0c:aa:bb:cc",
            "vendor": "Cisco Systems, Inc",
        }

        response = client.get("/api/whitelist")
        assert response.status_code == 200
        assert response.json() == [created.json()]

        settings = client.get("/api/settings")
        assert settings.status_code == 200
        assert settings.json()["pxe_next_server"] == "192.168.50.10"

        deleted = client.request(
            "DELETE", "/api/whitelist", json={"mac": "00:00:0c:aa:bb:cc"}
        )
        assert deleted.status_code == 200
        assert client.get("/api/whitelist").json() == []


def test_whitelist_api_rejects_invalid_mac(monkeypatch, tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(make_config()), encoding="utf-8")
    monkeypatch.setattr(app_module, "config_store", ConfigStore(path))

    with TestClient(app_module.app) as client:
        response = client.post("/api/whitelist", json={"mac": "invalid"})

    assert response.status_code == 422
    assert response.json()["detail"] == "Некорректный MAC-адрес"
