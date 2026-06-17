import json

import pytest

from config_store import ConfigError, ConfigStore, DuplicateMACError, normalize_mac


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


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
    ],
)
def test_normalize_mac(value, expected):
    assert normalize_mac(value) == expected


def test_add_and_remove_mac(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(make_config()), encoding="utf-8")
    store = ConfigStore(path)

    assert store.add_mac("AA-BB-CC-DD-EE-FF") == "aa:bb:cc:dd:ee:ff"
    assert store.load()["whitelist"] == ["aa:bb:cc:dd:ee:ff"]
    assert store.remove_mac("aabb.ccdd.eeff") == "aa:bb:cc:dd:ee:ff"
    assert store.load()["whitelist"] == []


def test_duplicate_mac_is_rejected(tmp_path):
    path = tmp_path / "config.json"
    config = make_config()
    config["whitelist"] = ["aa:bb:cc:dd:ee:ff"]
    path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(DuplicateMACError):
        ConfigStore(path).add_mac("AA:BB:CC:DD:EE:FF")


def test_update_dhcp_settings_preserves_whitelist_and_boot_file(tmp_path):
    path = tmp_path / "config.json"
    config = make_config()
    config["whitelist"] = ["aa:bb:cc:dd:ee:ff"]
    path.write_text(json.dumps(config), encoding="utf-8")

    settings = ConfigStore(path).update_dhcp_settings(
        {
            "pool_start": "10.20.30.100",
            "pool_end": "10.20.30.200",
            "subnet_mask": "255.255.255.0",
            "router": "10.20.30.1",
            "pxe_next_server": "10.20.30.50",
        }
    )
    saved = ConfigStore(path).load()

    assert settings["pxe_boot_file"] == "pxelinux.0"
    assert saved["whitelist"] == ["aa:bb:cc:dd:ee:ff"]
    assert saved["dhcp_settings"]["pxe_next_server"] == "10.20.30.50"


def test_empty_config_has_clear_error(tmp_path):
    path = tmp_path / "config.json"
    path.write_text("", encoding="utf-8")

    with pytest.raises(ConfigError, match="пуст"):
        ConfigStore(path).load()
