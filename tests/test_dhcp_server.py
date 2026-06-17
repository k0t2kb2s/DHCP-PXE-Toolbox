import json
from ipaddress import IPv4Address, IPv4Network

import pytest
try:
    from scapy.all import ARP, BOOTP, DHCP, Ether, IP, UDP
except PermissionError as exc:
    pytest.skip(f"Scapy недоступен в sandbox: {exc}", allow_module_level=True)

from dhcp_server import (
    DHCPServer,
    LeaseAllocator,
    NetworkDiscoveryError,
    build_assign_ip_command,
    build_dhcp_autoconfig_settings,
    choose_network,
    extract_client_mac,
    extract_source_ip,
    get_dhcp_message_type,
    is_network_discovery_runtime_error,
    run_cli,
    set_reuseaddr_on_socket,
    validate_interface_name,
)


SETTINGS = {
    "pool_start": "192.168.50.100",
    "pool_end": "192.168.50.101",
    "subnet_mask": "255.255.255.0",
    "router": "192.168.50.1",
    "pxe_next_server": "192.168.50.10",
    "pxe_boot_file": "pxelinux.0",
}


def discover():
    return (
        Ether(src="aa:bb:cc:dd:ee:ff", dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(
            op=1,
            htype=1,
            hlen=6,
            xid=1234,
            chaddr=bytes.fromhex("aabbccddeeff") + bytes(10),
        )
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def test_extract_discover_data():
    packet = discover()
    assert get_dhcp_message_type(packet) == "discover"
    assert extract_client_mac(packet) == "aa:bb:cc:dd:ee:ff"


def test_extract_source_ip_from_ip_and_arp():
    assert extract_source_ip(IP(src="192.168.1.15")) == IPv4Address("192.168.1.15")
    assert extract_source_ip(ARP(psrc="192.168.1.50")) == IPv4Address("192.168.1.50")
    assert extract_source_ip(IP(src="0.0.0.0")) is None


def test_choose_dominant_network_and_current_ip_tiebreaker():
    observed = {
        IPv4Address("192.168.1.15"),
        IPv4Address("192.168.1.50"),
        IPv4Address("10.0.0.2"),
    }
    assert choose_network(observed, None) == IPv4Network("192.168.1.0/24")

    tied = {IPv4Address("192.168.1.15"), IPv4Address("10.0.0.2")}
    assert choose_network(tied, IPv4Address("10.0.0.50")) == IPv4Network("10.0.0.0/24")


def test_choose_network_can_infer_wider_than_24():
    observed = {IPv4Address("192.168.0.15"), IPv4Address("192.168.1.50")}

    assert choose_network(observed, None) == IPv4Network("192.168.0.0/23")


def test_choose_network_prefers_known_interface_network():
    observed = {IPv4Address("10.20.30.15")}
    known_networks = {IPv4Network("10.20.30.0/23")}

    assert choose_network(observed, None, known_networks) == IPv4Network("10.20.30.0/23")


def test_choose_network_fails_without_traffic_or_interface_ip():
    with pytest.raises(NetworkDiscoveryError):
        choose_network(set(), None)


def test_allocator_keeps_stable_lease():
    allocator = LeaseAllocator()
    assert allocator.allocate("aa:bb:cc:dd:ee:ff", SETTINGS) == "192.168.50.100"
    assert allocator.allocate("11:22:33:44:55:66", SETTINGS) == "192.168.50.101"
    assert allocator.allocate("aa:bb:cc:dd:ee:ff", SETTINGS) == "192.168.50.100"


def test_allocator_tracks_ip_to_mac_timestamp_and_reserved_ips(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr("dhcp_server.time.time", lambda: now[0])
    allocator = LeaseAllocator()

    first = allocator.allocate(
        "aa:bb:cc:dd:ee:ff",
        SETTINGS,
        reserved_ips={IPv4Address("192.168.50.100")},
    )
    second = allocator.allocate("11:22:33:44:55:66", SETTINGS)
    leases = allocator.snapshot()

    assert first == "192.168.50.101"
    assert second == "192.168.50.100"
    assert leases["192.168.50.101"] == {
        "mac": "aa:bb:cc:dd:ee:ff",
        "timestamp": 1000.0,
    }
    assert leases["192.168.50.100"]["mac"] == "11:22:33:44:55:66"


def test_allocator_expires_old_leases(monkeypatch):
    settings = {**SETTINGS, "lease_time": 60}
    now = [1000.0]
    monkeypatch.setattr("dhcp_server.time.time", lambda: now[0])
    allocator = LeaseAllocator()

    assert allocator.allocate("aa:bb:cc:dd:ee:ff", settings) == "192.168.50.100"
    now[0] = 1061.0
    assert allocator.allocate("11:22:33:44:55:66", settings) == "192.168.50.100"
    assert allocator.snapshot()["192.168.50.100"]["mac"] == "11:22:33:44:55:66"


def test_offer_contains_pxe_options(monkeypatch, tmp_path):
    monkeypatch.setattr("dhcp_server.get_if_hwaddr", lambda _: "00:11:22:33:44:55")
    server = DHCPServer(tmp_path / "config.json", interface="eth0")

    offer = server.build_offer(discover(), "192.168.50.100", SETTINGS)
    options = dict(option for option in offer[DHCP].options if isinstance(option, tuple))

    assert offer[BOOTP].yiaddr == "192.168.50.100"
    assert offer[BOOTP].siaddr == "192.168.50.10"
    assert offer[IP].src == "192.168.50.10"
    assert offer[BOOTP].file == b"pxelinux.0"
    assert options["lease_time"] == 3600
    assert options["router"] == "192.168.50.1"
    assert options["subnet_mask"] == "255.255.255.0"
    assert options["tftp_server_name"] == "192.168.50.10"
    assert options["boot-file-name"] == "pxelinux.0"

    serialized_options = bytes(offer[DHCP])
    assert b"\x42\x0d192.168.50.10" in serialized_options
    assert b"\x43\x0apxelinux.0" in serialized_options


def test_network_discovery_updates_config_and_assigns_server_ip(monkeypatch, tmp_path):
    config = {"dhcp_settings": SETTINGS, "whitelist": ["aa:bb:cc:dd:ee:ff"]}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    sniff_options = {}
    assigned = []

    def fake_sniff_packets(**kwargs):
        sniff_options.update(kwargs)
        kwargs["prn"](IP(src="192.168.1.15"))
        kwargs["prn"](ARP(psrc="192.168.1.80"))

    monkeypatch.setattr("dhcp_server.sniff_packets", fake_sniff_packets)
    monkeypatch.setattr("dhcp_server.get_if_addr", lambda _: "0.0.0.0")
    monkeypatch.setattr("dhcp_server.get_interface_networks", lambda _: set())
    monkeypatch.setattr(
        "dhcp_server.subprocess.run",
        lambda command, **kwargs: assigned.append((command, kwargs)),
    )
    monkeypatch.setattr(
        "dhcp_server.conf.route.route",
        lambda *args, **kwargs: ("eth0", "0.0.0.0", "192.168.1.254"),
    )

    result = DHCPServer(path, interface="eth0").discover_and_configure_network()
    saved = json.loads(path.read_text(encoding="utf-8"))

    assert result.network == IPv4Network("192.168.1.0/24")
    assert result.router == IPv4Address("192.168.1.254")
    assert result.server_ip == IPv4Address("192.168.1.50")
    assert sniff_options["timeout"] == 10
    assert sniff_options["promisc"] is True
    assert sniff_options["bpf_filter"] == "ip or arp"
    assert assigned[0][0] == [
        "ip",
        "address",
        "replace",
        "192.168.1.50/24",
        "dev",
        "eth0",
    ]
    assert saved["dhcp_settings"] == {
        **SETTINGS,
        "pool_start": "192.168.1.100",
        "pool_end": "192.168.1.200",
        "router": "192.168.1.254",
        "pxe_next_server": "192.168.1.50",
    }
    assert saved["whitelist"] == ["aa:bb:cc:dd:ee:ff"]


def test_network_discovery_reuses_existing_interface_ip(monkeypatch, tmp_path):
    config = {"dhcp_settings": SETTINGS, "whitelist": []}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    def fake_sniff_packets(**kwargs):
        kwargs["prn"](IP(src="10.20.30.15"))

    monkeypatch.setattr("dhcp_server.sniff_packets", fake_sniff_packets)
    monkeypatch.setattr("dhcp_server.get_if_addr", lambda _: "10.20.30.9")
    monkeypatch.setattr("dhcp_server.get_interface_networks", lambda _: {IPv4Network("10.20.30.0/24")})
    monkeypatch.setattr(
        "dhcp_server.subprocess.run",
        lambda *args, **kwargs: pytest.fail("ip address add не должен вызываться"),
    )
    monkeypatch.setattr(
        "dhcp_server.conf.route.route",
        lambda *args, **kwargs: ("eth0", "10.20.30.9", "0.0.0.0"),
    )

    result = DHCPServer(path, interface="eth0").discover_and_configure_network()

    assert result.server_ip == IPv4Address("10.20.30.9")
    assert result.router == IPv4Address("10.20.30.1")
    assert json.loads(path.read_text(encoding="utf-8"))["dhcp_settings"][
        "pxe_next_server"
    ] == "10.20.30.9"


def test_build_assign_ip_command_linux(monkeypatch):
    monkeypatch.setattr("dhcp_server.platform.system", lambda: "Linux")

    command = build_assign_ip_command(
        "eth0",
        IPv4Address("192.168.56.50"),
        IPv4Network("192.168.56.0/24"),
    )

    assert command == [
        "ip",
        "address",
        "replace",
        "192.168.56.50/24",
        "dev",
        "eth0",
    ]


def test_build_assign_ip_command_windows(monkeypatch):
    monkeypatch.setattr("dhcp_server.platform.system", lambda: "Windows")

    command = build_assign_ip_command(
        "Ethernet",
        IPv4Address("192.168.56.50"),
        IPv4Network("192.168.56.0/24"),
    )

    assert command == [
        "netsh",
        "interface",
        "ip",
        "set",
        "address",
        "name=Ethernet",
        "static",
        "192.168.56.50",
        "255.255.255.0",
    ]


def test_build_assign_ip_command_macos(monkeypatch):
    monkeypatch.setattr("dhcp_server.platform.system", lambda: "Darwin")

    command = build_assign_ip_command(
        "en0",
        IPv4Address("192.168.56.50"),
        IPv4Network("192.168.56.0/24"),
    )

    assert command == ["ifconfig", "en0", "alias", "192.168.56.50", "255.255.255.0"]


def test_validate_interface_name_rejects_command_injection():
    assert validate_interface_name("VirtualBox Host-Only Network") == "VirtualBox Host-Only Network"
    with pytest.raises(ValueError):
        validate_interface_name("eth0; rm -rf /")
    with pytest.raises(ValueError):
        validate_interface_name("-bad")
    with pytest.raises(ValueError):
        validate_interface_name("eth0\nbad")


def test_build_assign_ip_command_rejects_unsafe_interface(monkeypatch):
    monkeypatch.setattr("dhcp_server.platform.system", lambda: "Linux")

    with pytest.raises(ValueError):
        build_assign_ip_command(
            "eth0;rm -rf /",
            IPv4Address("192.168.56.50"),
            IPv4Network("192.168.56.0/24"),
        )


def test_set_reuseaddr_on_socket():
    calls = []

    class RawSocket:
        def setsockopt(self, *args):
            calls.append(args)

    class SuperSocket:
        ins = RawSocket()

    set_reuseaddr_on_socket(SuperSocket())

    assert calls


def test_build_autoconfig_settings_caps_pool_to_network():
    settings = build_dhcp_autoconfig_settings(
        IPv4Network("192.168.56.0/25"),
        IPv4Address("192.168.56.1"),
        IPv4Address("192.168.56.50"),
    )

    assert settings["pool_start"] == "192.168.56.100"
    assert settings["pool_end"] == "192.168.56.126"


def test_network_discovery_runtime_error_detection():
    assert is_network_discovery_runtime_error(
        RuntimeError("Автоопределение сети завершилось ошибкой: нет трафика")
    )
    assert not is_network_discovery_runtime_error(RuntimeError("порт 67 занят"))


def test_run_cli_handles_network_discovery_error(monkeypatch, caplog):
    def fail(_config_path, _interface):
        raise NetworkDiscoveryError("нет IP/ARP-трафика")

    monkeypatch.setattr("dhcp_server.run_dhcp_server", fail)

    with caplog.at_level("ERROR"), pytest.raises(SystemExit) as exc_info:
        run_cli("config.json", "eth0")

    assert exc_info.value.code == 1
    assert "Не удалось определить сеть: нет IP/ARP-трафика" in caplog.text
    assert "Пожалуйста, назначьте IP-адрес" in caplog.text


def test_run_cli_handles_wrapped_network_discovery_runtime_error(monkeypatch, caplog):
    def fail(_config_path, _interface):
        raise RuntimeError("Автоопределение сети завершилось ошибкой: нет трафика")

    monkeypatch.setattr("dhcp_server.run_dhcp_server", fail)

    with caplog.at_level("ERROR"), pytest.raises(SystemExit) as exc_info:
        run_cli("config.json", "eth0")

    assert exc_info.value.code == 1
    assert "Не удалось определить сеть" in caplog.text
    assert "нет трафика" in caplog.text


def test_run_cli_reraises_unrelated_runtime_error(monkeypatch):
    def fail(_config_path, _interface):
        raise RuntimeError("порт 67 занят")

    monkeypatch.setattr("dhcp_server.run_dhcp_server", fail)

    with pytest.raises(RuntimeError, match="порт 67 занят"):
        run_cli("config.json", "eth0")


def test_non_whitelisted_discover_is_silently_dropped(monkeypatch, tmp_path):
    config = {"dhcp_settings": SETTINGS, "whitelist": []}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    sent = []
    monkeypatch.setattr("dhcp_server.sendp", lambda *args, **kwargs: sent.append(args))

    DHCPServer(path, interface="eth0").handle_packet(discover())

    assert sent == []


def test_whitelisted_discover_sends_offer(monkeypatch, tmp_path):
    config = {"dhcp_settings": SETTINGS, "whitelist": ["aa:bb:cc:dd:ee:ff"]}
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config), encoding="utf-8")
    sent = []
    server = DHCPServer(path, interface="eth0")
    server._reserved_ips = {IPv4Address("192.168.50.100")}
    monkeypatch.setattr("dhcp_server.get_if_hwaddr", lambda _: "00:11:22:33:44:55")
    monkeypatch.setattr(
        "dhcp_server.sendp", lambda packet, **kwargs: sent.append((packet, kwargs))
    )

    server.handle_packet(discover())

    assert len(sent) == 1
    assert sent[0][0][BOOTP].yiaddr == "192.168.50.101"
    assert sent[0][1]["iface"] == "eth0"
