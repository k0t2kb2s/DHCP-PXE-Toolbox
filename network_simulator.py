from __future__ import annotations

import argparse
import ipaddress
import logging
import random
import signal
import time
from dataclasses import dataclass
from itertools import cycle
from typing import List, Optional

try:
    from scapy.all import ARP, BOOTP, DHCP, IP, UDP, Ether, RandMAC, sendp
except ImportError as exc:  # pragma: no cover - depends on deployment environment
    raise RuntimeError("Для network_simulator.py установите зависимости из requirements.txt") from exc
except PermissionError as exc:  # pragma: no cover - depends on deployment environment
    raise RuntimeError("Scapy не удалось получить доступ к сетевым интерфейсам") from exc

from config_store import normalize_mac


LOGGER = logging.getLogger(__name__)
DEFAULT_HOSTS = (15, 30, 80)


@dataclass(frozen=True)
class SimulatedHost:
    ip: ipaddress.IPv4Address
    mac: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Генератор фейкового ARP/IP-трафика для проверки network sniffing"
    )
    parser.add_argument(
        "--interface",
        "-i",
        default="vboxnet0",
        help="Изолированный тестовый интерфейс, например vboxnet0",
    )
    parser.add_argument(
        "--network",
        "-n",
        default="192.168.56.0/24",
        help="Подсеть, которую должен увидеть dhcp_server.py",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=1.0,
        help="Интервал между пакетами в секундах",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=0,
        help="Количество пакетов. 0 означает бесконечно до Ctrl+C",
    )
    parser.add_argument(
        "--mode",
        choices=("arp", "ip", "mixed"),
        default="mixed",
        help="Тип генерируемого трафика",
    )
    parser.add_argument(
        "--router",
        help="IP роутера для ARP-запросов. По умолчанию .1 выбранной подсети",
    )
    parser.add_argument(
        "--hosts",
        help="Список host-частей через запятую, например 1,15,30,80",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Подробный вывод Scapy",
    )
    parser.add_argument(
        "--test-dhcp",
        metavar="MAC_ADDRESS",
        help="Отправить один DHCPDISCOVER от указанного MAC и завершиться",
    )
    return parser.parse_args()


def parse_hosts(
    network: ipaddress.IPv4Network, hosts: Optional[str]
) -> List[ipaddress.IPv4Address]:
    host_numbers = (
        [int(part.strip()) for part in hosts.split(",") if part.strip()]
        if hosts
        else list(DEFAULT_HOSTS)
    )
    addresses: List[ipaddress.IPv4Address] = []
    for host_number in host_numbers:
        address = network.network_address + host_number
        if address in {network.network_address, network.broadcast_address}:
            raise ValueError(f"{address} не является usable host-адресом")
        if address not in network:
            raise ValueError(f"{address} не входит в {network}")
        addresses.append(address)
    if not addresses:
        raise ValueError("Список hosts пуст")
    return addresses


def build_hosts(
    network: ipaddress.IPv4Network, hosts_arg: Optional[str]
) -> List[SimulatedHost]:
    return [
        SimulatedHost(ip=address, mac=str(RandMAC()))
        for address in parse_hosts(network, hosts_arg)
    ]


def build_arp_packet(host: SimulatedHost, router_ip: ipaddress.IPv4Address) -> Ether:
    return (
        Ether(src=host.mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(
            op="who-has",
            hwsrc=host.mac,
            psrc=str(host.ip),
            hwdst="00:00:00:00:00:00",
            pdst=str(router_ip),
        )
    )


def build_ip_packet(
    host: SimulatedHost,
    network: ipaddress.IPv4Network,
) -> Ether:
    payload = f"network-simulator {host.ip} {time.time():.3f}".encode("ascii")
    return (
        Ether(src=host.mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src=str(host.ip), dst=str(network.broadcast_address))
        / UDP(sport=random.randint(20000, 60000), dport=9)
        / payload
    )


def build_dhcp_discover_packet(mac_address: str) -> Ether:
    normalized_mac = normalize_mac(mac_address)
    raw_mac = bytes.fromhex(normalized_mac.replace(":", ""))
    xid = random.randint(1, 0xFFFFFFFF)
    return (
        Ether(src=normalized_mac, dst="ff:ff:ff:ff:ff:ff")
        / IP(src="0.0.0.0", dst="255.255.255.255")
        / UDP(sport=68, dport=67)
        / BOOTP(
            op=1,
            htype=1,
            hlen=6,
            xid=xid,
            flags=0x8000,
            chaddr=raw_mac + bytes(10),
        )
        / DHCP(options=[("message-type", "discover"), "end"])
    )


def should_send_arp(mode: str, packet_number: int) -> bool:
    return mode == "arp" or (mode == "mixed" and packet_number % 2 == 1)


def send_dhcp_discover(interface: str, mac_address: str, verbose: bool = False) -> None:
    packet = build_dhcp_discover_packet(mac_address)
    sendp(packet, iface=interface, verbose=verbose)
    LOGGER.info("DHCPDISCOVER отправлен от %s через %s", normalize_mac(mac_address), interface)


def run_simulator(args: argparse.Namespace) -> None:
    if args.test_dhcp:
        send_dhcp_discover(args.interface, args.test_dhcp, args.verbose)
        return

    network = ipaddress.IPv4Network(args.network, strict=False)
    router_ip = ipaddress.IPv4Address(args.router) if args.router else network.network_address + 1
    if router_ip not in network:
        raise ValueError(f"router {router_ip} не входит в {network}")

    hosts = build_hosts(network, args.hosts)
    packet_limit = args.count if args.count > 0 else None
    stop = False

    def stop_handler(signum: int, _frame: object) -> None:
        nonlocal stop
        LOGGER.info("Получен сигнал %s, завершаю симулятор", signum)
        stop = True

    signal.signal(signal.SIGINT, stop_handler)
    signal.signal(signal.SIGTERM, stop_handler)

    LOGGER.info(
        "Симулятор отправляет %s-трафик в %s для подсети %s, router=%s",
        args.mode,
        args.interface,
        network,
        router_ip,
    )
    LOGGER.info("Фейковые источники: %s", ", ".join(f"{host.ip}/{host.mac}" for host in hosts))

    for packet_number, host in enumerate(cycle(hosts), start=1):
        if stop or (packet_limit is not None and packet_number > packet_limit):
            break

        if should_send_arp(args.mode, packet_number):
            packet = build_arp_packet(host, router_ip)
            sendp(packet, iface=args.interface, verbose=args.verbose)
            LOGGER.info("ARP who-has %s says %s (%s)", router_ip, host.ip, host.mac)
        else:
            packet = build_ip_packet(host, network)
            sendp(packet, iface=args.interface, verbose=args.verbose)
            LOGGER.info("IP/UDP %s -> %s", host.ip, network.broadcast_address)

        time.sleep(args.interval)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
    args = parse_args()
    try:
        run_simulator(args)
    except KeyboardInterrupt:
        pass
    except PermissionError as exc:
        raise SystemExit(f"Недостаточно прав для отправки raw-пакетов: {exc}") from exc
    except OSError as exc:
        raise SystemExit(f"Ошибка сетевого интерфейса: {exc}") from exc
    except ValueError as exc:
        raise SystemExit(f"Некорректные параметры: {exc}") from exc


if __name__ == "__main__":
    main()
