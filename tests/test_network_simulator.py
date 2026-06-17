import ipaddress
from argparse import Namespace

import pytest
try:
    from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether
except PermissionError as exc:
    pytest.skip(f"Scapy недоступен в sandbox: {exc}", allow_module_level=True)

import network_simulator
from network_simulator import (
    SimulatedHost,
    build_arp_packet,
    build_dhcp_discover_packet,
    build_ip_packet,
    parse_hosts,
    should_send_arp,
)


def test_parse_default_hosts():
    network = ipaddress.IPv4Network("192.168.56.0/24")

    assert parse_hosts(network, None) == [
        ipaddress.IPv4Address("192.168.56.15"),
        ipaddress.IPv4Address("192.168.56.30"),
        ipaddress.IPv4Address("192.168.56.80"),
    ]


def test_parse_hosts_rejects_network_and_broadcast():
    network = ipaddress.IPv4Network("192.168.56.0/24")

    with pytest.raises(ValueError):
        parse_hosts(network, "0")
    with pytest.raises(ValueError):
        parse_hosts(network, "255")


def test_build_arp_packet():
    host = SimulatedHost(
        ip=ipaddress.IPv4Address("192.168.56.15"),
        mac="02:00:00:00:00:15",
    )

    packet = build_arp_packet(host, ipaddress.IPv4Address("192.168.56.1"))

    assert packet[Ether].src == "02:00:00:00:00:15"
    assert packet[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert packet[ARP].psrc == "192.168.56.15"
    assert packet[ARP].pdst == "192.168.56.1"


def test_build_ip_packet():
    host = SimulatedHost(
        ip=ipaddress.IPv4Address("192.168.56.30"),
        mac="02:00:00:00:00:30",
    )

    packet = build_ip_packet(host, ipaddress.IPv4Network("192.168.56.0/24"))

    assert packet[Ether].src == "02:00:00:00:00:30"
    assert packet[IP].src == "192.168.56.30"
    assert packet[IP].dst == "192.168.56.255"


def test_build_dhcp_discover_packet(monkeypatch):
    monkeypatch.setattr(network_simulator.random, "randint", lambda _start, _end: 1234)

    packet = build_dhcp_discover_packet("AA-BB-CC-DD-EE-FF")
    options = dict(option for option in packet[DHCP].options if isinstance(option, tuple))

    assert packet[Ether].src == "aa:bb:cc:dd:ee:ff"
    assert packet[Ether].dst == "ff:ff:ff:ff:ff:ff"
    assert packet[IP].src == "0.0.0.0"
    assert packet[IP].dst == "255.255.255.255"
    assert packet[UDP].sport == 68
    assert packet[UDP].dport == 67
    assert packet[BOOTP].op == 1
    assert packet[BOOTP].xid == 1234
    assert bytes(packet[BOOTP].chaddr)[:6] == bytes.fromhex("aabbccddeeff")
    assert options["message-type"] == "discover"


def test_should_send_arp_modes():
    assert should_send_arp("arp", 2)
    assert not should_send_arp("ip", 1)
    assert should_send_arp("mixed", 1)
    assert not should_send_arp("mixed", 2)


def test_run_simulator_respects_count(monkeypatch):
    sent = []
    slept = []
    args = Namespace(
        interface="vboxnet0",
        network="192.168.56.0/24",
        interval=1.0,
        count=3,
        mode="mixed",
        router=None,
        hosts="15,30",
        test_dhcp=None,
        verbose=False,
    )
    monkeypatch.setattr(network_simulator, "sendp", lambda packet, **kwargs: sent.append(packet))
    monkeypatch.setattr(network_simulator.time, "sleep", lambda seconds: slept.append(seconds))

    network_simulator.run_simulator(args)

    assert len(sent) == 3
    assert len(slept) == 3


def test_run_simulator_test_dhcp_sends_one_packet(monkeypatch):
    sent = []
    slept = []
    args = Namespace(
        interface="vboxnet0",
        network="192.168.56.0/24",
        interval=1.0,
        count=0,
        mode="mixed",
        router=None,
        hosts=None,
        test_dhcp="aa:bb:cc:dd:ee:ff",
        verbose=False,
    )
    monkeypatch.setattr(network_simulator, "sendp", lambda packet, **kwargs: sent.append((packet, kwargs)))
    monkeypatch.setattr(network_simulator.time, "sleep", lambda seconds: slept.append(seconds))

    network_simulator.run_simulator(args)

    assert len(sent) == 1
    assert sent[0][0][DHCP].options[0] == ("message-type", "discover")
    assert sent[0][1]["iface"] == "vboxnet0"
    assert slept == []
