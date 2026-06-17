from __future__ import annotations

import ipaddress
import logging
import platform
import re
import socket
import subprocess
import sys
import threading
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, FrozenSet, Optional, Set, Tuple, Union

from config_store import ConfigError, ConfigStore, normalize_mac

try:
    from scapy.all import (
        ARP,
        BOOTP,
        DHCP,
        IP,
        UDP,
        Ether,
        conf,
        get_if_addr,
        get_if_hwaddr,
        sendp,
        sniff,
    )
except ImportError as exc:  # pragma: no cover - depends on deployment environment
    raise RuntimeError("Для DHCP-сервера установите зависимости из requirements.txt") from exc
except PermissionError as exc:  # pragma: no cover - depends on deployment environment
    raise RuntimeError("Scapy не удалось получить доступ к сетевым интерфейсам") from exc


LOGGER = logging.getLogger(__name__)
DEFAULT_LEASE_TIME = 3600
INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9_.:@#() \-]{1,128}$")


class LeasePoolExhausted(RuntimeError):
    pass


class NetworkDiscoveryError(RuntimeError):
    pass


@dataclass(frozen=True)
class NetworkDiscoveryResult:
    network: ipaddress.IPv4Network
    router: ipaddress.IPv4Address
    server_ip: ipaddress.IPv4Address
    observed_ips: FrozenSet[ipaddress.IPv4Address]


@dataclass
class LeaseRecord:
    ip: str
    mac: str
    timestamp: float


def get_lease_time(settings: Dict[str, Any]) -> int:
    try:
        lease_time = int(settings.get("lease_time", DEFAULT_LEASE_TIME))
    except (TypeError, ValueError):
        return DEFAULT_LEASE_TIME
    return max(60, lease_time)


def build_reserved_ips(
    settings: Dict[str, Any],
    network: ipaddress.IPv4Network,
    extra_reserved: Set[ipaddress.IPv4Address],
) -> Set[ipaddress.IPv4Address]:
    reserved = {
        network.network_address,
        network.broadcast_address,
    } | set(extra_reserved)
    for key in ("router", "pxe_next_server"):
        address = parse_usable_ipv4(settings.get(key))
        if address:
            reserved.add(address)
    return reserved


class LeaseAllocator:
    def __init__(self) -> None:
        self._leases_by_ip: Dict[str, LeaseRecord] = {}
        self._lock = threading.Lock()

    def allocate(
        self,
        mac: str,
        settings: Dict[str, Any],
        reserved_ips: Optional[Set[ipaddress.IPv4Address]] = None,
    ) -> str:
        normalized_mac = normalize_mac(mac)
        start = ipaddress.IPv4Address(settings["pool_start"])
        end = ipaddress.IPv4Address(settings["pool_end"])
        network = ipaddress.IPv4Network(
            f"{settings['pool_start']}/{settings['subnet_mask']}", strict=False
        )
        lease_time = get_lease_time(settings)
        reserved = build_reserved_ips(settings, network, reserved_ips or set())
        now = time.time()

        with self._lock:
            self._purge_expired(now, lease_time)

            for ip, lease in list(self._leases_by_ip.items()):
                if lease.mac != normalized_mac:
                    continue
                address = ipaddress.IPv4Address(ip)
                if start <= address <= end and address not in reserved:
                    lease.timestamp = now
                    return ip
                del self._leases_by_ip[ip]

            used = {
                ipaddress.IPv4Address(ip) for ip in self._leases_by_ip
            }
            candidate = start
            while candidate <= end:
                if candidate not in used and candidate not in reserved:
                    self._leases_by_ip[str(candidate)] = LeaseRecord(
                        ip=str(candidate),
                        mac=normalized_mac,
                        timestamp=now,
                    )
                    return str(candidate)
                candidate += 1

        raise LeasePoolExhausted("В DHCP-пуле не осталось свободных адресов")

    def snapshot(self) -> Dict[str, Dict[str, Union[str, float]]]:
        with self._lock:
            return {
                ip: {"mac": lease.mac, "timestamp": lease.timestamp}
                for ip, lease in self._leases_by_ip.items()
            }

    def _purge_expired(self, now: float, lease_time: int) -> None:
        expired = [
            ip
            for ip, lease in self._leases_by_ip.items()
            if now - lease.timestamp >= lease_time
        ]
        for ip in expired:
            del self._leases_by_ip[ip]


def get_dhcp_message_type(packet: Any) -> Optional[str]:
    if not packet.haslayer(DHCP):
        return None
    for option in packet[DHCP].options:
        if isinstance(option, tuple) and option[0] == "message-type":
            value = option[1]
            if value in (1, "discover", b"discover"):
                return "discover"
            return str(value)
    return None


def extract_client_mac(packet: Any) -> str:
    bootp = packet[BOOTP]
    raw = bytes(bootp.chaddr)[: int(bootp.hlen or 6)]
    return normalize_mac(raw.hex())


def parse_usable_ipv4(value: Any) -> Optional[ipaddress.IPv4Address]:
    try:
        address = ipaddress.IPv4Address(str(value))
    except ipaddress.AddressValueError:
        return None
    if address.is_unspecified or address.is_multicast or address.is_loopback:
        return None
    if address.is_link_local or address == ipaddress.IPv4Address("255.255.255.255"):
        return None
    return address


def validate_interface_name(interface: str) -> str:
    if not isinstance(interface, str):
        raise ValueError("Имя интерфейса должно быть строкой")
    normalized = interface.strip()
    if not normalized:
        raise ValueError("Имя интерфейса не может быть пустым")
    if normalized.startswith("-"):
        raise ValueError("Имя интерфейса не может начинаться с '-'")
    if not INTERFACE_NAME_RE.fullmatch(normalized):
        raise ValueError(
            "Имя интерфейса содержит недопустимые символы. Разрешены буквы, "
            "цифры, пробелы, '.', '_', '-', ':', '@', '#', '(' и ')'."
        )
    return normalized


def extract_source_ip(packet: Any) -> Optional[ipaddress.IPv4Address]:
    if packet.haslayer(IP):
        return parse_usable_ipv4(packet[IP].src)
    if packet.haslayer(ARP):
        return parse_usable_ipv4(packet[ARP].psrc)
    return None


def route_to_interface_network(route: Any, interface: str) -> Optional[ipaddress.IPv4Network]:
    if len(route) < 5 or str(route[3]) != interface:
        return None
    address = parse_usable_ipv4(route[4])
    if not address:
        return None
    try:
        mask = int(route[1])
        if mask == 0:
            return None
        netmask = ipaddress.IPv4Address(mask)
        return ipaddress.IPv4Network(f"{address}/{netmask}", strict=False)
    except (ValueError, TypeError):
        return None


def get_interface_ipv4s(
    interface: str,
) -> Tuple[Optional[ipaddress.IPv4Address], Set[ipaddress.IPv4Address]]:
    preferred = parse_usable_ipv4(get_if_addr(interface))
    addresses = {preferred} if preferred else set()
    for route in conf.route.routes:
        if len(route) >= 5 and str(route[3]) == interface:
            address = parse_usable_ipv4(route[4])
            if address:
                addresses.add(address)
    return preferred, addresses


def get_interface_networks(interface: str) -> Set[ipaddress.IPv4Network]:
    networks: Set[ipaddress.IPv4Network] = set()
    for route in conf.route.routes:
        network = route_to_interface_network(route, interface)
        if network:
            networks.add(network)
    return networks


def infer_network_from_observed_ips(
    observed_ips: Set[ipaddress.IPv4Address],
    current_ip: Optional[ipaddress.IPv4Address],
) -> ipaddress.IPv4Network:
    if not observed_ips:
        if current_ip:
            return ipaddress.IPv4Network(f"{current_ip}/24", strict=False)
        raise NetworkDiscoveryError(
            "За время прослушивания не найдено IP/ARP-трафика и интерфейс не имеет IPv4"
        )

    octet8_groups = Counter(
        ipaddress.IPv4Network((int(address), 8), strict=False)
        for address in observed_ips
    )
    if current_ip:
        current_octet8 = ipaddress.IPv4Network((int(current_ip), 8), strict=False)
        if current_octet8 in octet8_groups:
            candidate_ips = {
                address for address in observed_ips if address in current_octet8
            }
        else:
            candidate_ips = set(observed_ips)
    else:
        dominant_octet8 = max(
            octet8_groups,
            key=lambda network: (octet8_groups[network], -int(network.network_address)),
        )
        candidate_ips = {address for address in observed_ips if address in dominant_octet8}

    low = min(int(address) for address in candidate_ips)
    high = max(int(address) for address in candidate_ips)
    common_prefix = 32 - (low ^ high).bit_length()
    prefix = min(24, common_prefix)
    return ipaddress.IPv4Network((low, prefix), strict=False)


def choose_network(
    observed_ips: Set[ipaddress.IPv4Address],
    current_ip: Optional[ipaddress.IPv4Address],
    known_networks: Optional[Set[ipaddress.IPv4Network]] = None,
) -> ipaddress.IPv4Network:
    known_networks = known_networks or set()
    if known_networks:
        if observed_ips:
            candidates = [
                (
                    sum(1 for address in observed_ips if address in network),
                    bool(current_ip and current_ip in network),
                    network.prefixlen,
                    -int(network.network_address),
                    network,
                )
                for network in known_networks
            ]
            candidates = [candidate for candidate in candidates if candidate[0] > 0]
            if candidates:
                return max(candidates, key=lambda candidate: candidate[:4])[4]
        if current_ip:
            containing_current = [
                network for network in known_networks if current_ip in network
            ]
            if containing_current:
                return max(containing_current, key=lambda network: network.prefixlen)

    return infer_network_from_observed_ips(observed_ips, current_ip)


def choose_server_ip(
    network: ipaddress.IPv4Network,
    current_ip: Optional[ipaddress.IPv4Address],
    router: ipaddress.IPv4Address,
    observed_ips: Set[ipaddress.IPv4Address],
) -> ipaddress.IPv4Address:
    if current_ip and current_ip in network and current_ip not in {
        network.network_address,
        network.broadcast_address,
        router,
    }:
        return current_ip

    excluded = observed_ips | {
        network.network_address,
        network.broadcast_address,
        router,
    }
    preferred_hosts = [50, *range(51, 100), *range(2, 50), *range(201, 255)]
    for host_number in preferred_hosts:
        candidate = network.network_address + host_number
        if candidate in network and candidate not in excluded:
            return candidate
    raise NetworkDiscoveryError("Не удалось подобрать свободный адрес для PXE-сервера")


def set_reuseaddr_on_socket(super_socket: Any) -> None:
    for attr in ("ins", "outs", "socket"):
        raw_socket = getattr(super_socket, attr, None)
        if raw_socket and hasattr(raw_socket, "setsockopt"):
            try:
                raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            except OSError:
                LOGGER.debug("Не удалось выставить SO_REUSEADDR для %s", attr, exc_info=True)


def open_reusable_l2_socket(interface: str, bpf_filter: str, promisc: bool = False) -> Any:
    safe_interface = validate_interface_name(interface)
    listen_socket = conf.L2listen(
        iface=safe_interface,
        filter=bpf_filter,
        promisc=promisc,
    )
    set_reuseaddr_on_socket(listen_socket)
    return listen_socket


def sniff_packets(
    interface: str,
    bpf_filter: str,
    prn: Any,
    timeout: Optional[int] = None,
    promisc: bool = False,
    stop_filter: Optional[Any] = None,
) -> None:
    listen_socket = open_reusable_l2_socket(interface, bpf_filter, promisc)
    try:
        sniff(
            opened_socket=listen_socket,
            prn=prn,
            store=False,
            timeout=timeout,
            stop_filter=stop_filter,
        )
    finally:
        try:
            listen_socket.close()
        except Exception:
            LOGGER.debug("Не удалось закрыть L2 listen socket", exc_info=True)


def build_dhcp_autoconfig_settings(
    network: ipaddress.IPv4Network,
    router: ipaddress.IPv4Address,
    server_ip: ipaddress.IPv4Address,
) -> Dict[str, str]:
    first_usable = network.network_address + 1
    last_usable = network.broadcast_address - 1
    desired_start = network.network_address + 100
    desired_end = network.network_address + 200
    pool_start = desired_start if desired_start <= last_usable else first_usable
    pool_end = min(desired_end, last_usable)
    if pool_start > pool_end:
        raise NetworkDiscoveryError(f"Сеть {network} слишком мала для DHCP-пула")

    return {
        "pool_start": str(pool_start),
        "pool_end": str(pool_end),
        "subnet_mask": str(network.netmask),
        "router": str(router),
        "pxe_next_server": str(server_ip),
    }


class DHCPServer:
    def __init__(
        self,
        config_path: Union[str, Path],
        interface: Optional[str] = None,
        discovery_timeout: int = 10,
    ) -> None:
        self.config_store = ConfigStore(config_path)
        self.interface = validate_interface_name(interface or str(conf.iface))
        self.discovery_timeout = discovery_timeout
        self.allocator = LeaseAllocator()
        self._stop_event = threading.Event()
        self._reserved_ips_lock = threading.Lock()
        self._reserved_ips: Set[ipaddress.IPv4Address] = set()

    def serve_forever(self) -> None:
        try:
            self.config_store.load()
        except ConfigError as exc:
            raise RuntimeError(f"DHCP-сервер не может прочитать конфигурацию: {exc}") from exc

        try:
            get_if_hwaddr(self.interface)
        except Exception as exc:
            raise RuntimeError(f"Недоступен сетевой интерфейс {self.interface}: {exc}") from exc

        try:
            result = self.discover_and_configure_network()
        except (NetworkDiscoveryError, ConfigError) as exc:
            raise RuntimeError(f"Автоопределение сети завершилось ошибкой: {exc}") from exc

        LOGGER.info(
            "Определена сеть %s, router=%s, PXE/TFTP=%s",
            result.network,
            result.router,
            result.server_ip,
        )
        LOGGER.info("DHCP-сервер слушает интерфейс %s, UDP-порт 67", self.interface)
        try:
            sniff_packets(
                interface=self.interface,
                bpf_filter="udp and dst port 67",
                prn=self.handle_packet,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError as exc:
            raise RuntimeError(
                "Недостаточно прав для DHCP-сервера; запустите процесс с CAP_NET_RAW/root"
            ) from exc
        except OSError as exc:
            raise RuntimeError(f"Не удалось прослушивать UDP-порт 67: {exc}") from exc
        except Exception as exc:
            raise RuntimeError(
                f"Не удалось запустить захват DHCP-пакетов на {self.interface}: {exc}"
            ) from exc

    def discover_and_configure_network(self) -> NetworkDiscoveryResult:
        observed_ips: Set[ipaddress.IPv4Address] = set()

        def collect_source_ip(packet: Any) -> None:
            address = extract_source_ip(packet)
            if address:
                observed_ips.add(address)

        LOGGER.info(
            "Пассивное определение сети на %s: прослушивание IP/ARP в течение %d секунд",
            self.interface,
            self.discovery_timeout,
        )
        try:
            sniff_packets(
                interface=self.interface,
                bpf_filter="ip or arp",
                prn=collect_source_ip,
                timeout=self.discovery_timeout,
                promisc=True,
            )
        except PermissionError as exc:
            raise NetworkDiscoveryError(
                "Недостаточно прав для promiscuous-сниффинга; нужны CAP_NET_RAW/root"
            ) from exc
        except Exception as exc:
            raise NetworkDiscoveryError(f"Не удалось выполнить сниффинг: {exc}") from exc

        try:
            preferred_ip, interface_ips = get_interface_ipv4s(self.interface)
            interface_networks = get_interface_networks(self.interface)
        except Exception as exc:
            raise NetworkDiscoveryError(
                f"Не удалось прочитать IPv4 интерфейса {self.interface}: {exc}"
            ) from exc
        current_hint = preferred_ip or min(interface_ips, default=None)
        network = choose_network(observed_ips, current_hint, interface_networks)
        current_ip = (
            preferred_ip
            if preferred_ip and preferred_ip in network
            else min(
                (address for address in interface_ips if address in network),
                default=None,
            )
        )
        router = self.detect_router(network, observed_ips)
        server_ip = choose_server_ip(network, current_ip, router, observed_ips)
        self.assign_interface_ip(network, current_ip, server_ip)
        with self._reserved_ips_lock:
            self._reserved_ips = set(observed_ips) | {
                network.network_address,
                network.broadcast_address,
                router,
                server_ip,
            }

        settings = build_dhcp_autoconfig_settings(network, router, server_ip)
        self.config_store.update_dhcp_settings(settings)
        return NetworkDiscoveryResult(network, router, server_ip, frozenset(observed_ips))

    def detect_router(
        self,
        network: ipaddress.IPv4Network,
        observed_ips: Set[ipaddress.IPv4Address],
    ) -> ipaddress.IPv4Address:
        try:
            gateway = parse_usable_ipv4(
                conf.route.route("0.0.0.0", dev=self.interface, verbose=0)[2]
            )
        except Exception:
            gateway = None

        if gateway and gateway in network:
            return gateway

        conventional_gateway = network.network_address + 1
        if conventional_gateway in observed_ips:
            return conventional_gateway
        return conventional_gateway

    def assign_interface_ip(
        self,
        network: ipaddress.IPv4Network,
        current_ip: Optional[ipaddress.IPv4Address],
        server_ip: ipaddress.IPv4Address,
    ) -> None:
        if current_ip == server_ip:
            return

        command = build_assign_ip_command(self.interface, server_ip, network)
        try:
            subprocess.run(
                command,
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError as exc:
            raise NetworkDiscoveryError(
                "Не найдена системная утилита для назначения адреса интерфейсу"
            ) from exc
        except subprocess.CalledProcessError as exc:
            message = exc.stderr.strip() or exc.stdout.strip() or str(exc)
            raise NetworkDiscoveryError(
                f"Не удалось назначить {server_ip}/{network.prefixlen} интерфейсу "
                f"{self.interface}: {message}"
            ) from exc

    def stop(self) -> None:
        self._stop_event.set()

    def handle_packet(self, packet: Any) -> None:
        if not packet.haslayer(BOOTP) or get_dhcp_message_type(packet) != "discover":
            return

        try:
            mac = extract_client_mac(packet)
            config = self.config_store.load()
            if mac not in config["whitelist"]:
                LOGGER.info("Silent Drop DHCPDISCOVER от %s", mac)
                return

            with self._reserved_ips_lock:
                reserved_ips = set(self._reserved_ips)
            offered_ip = self.allocator.allocate(
                mac, config["dhcp_settings"], reserved_ips=reserved_ips
            )
            offer = self.build_offer(packet, offered_ip, config["dhcp_settings"])
            sendp(offer, iface=self.interface, verbose=False)
            LOGGER.info("Отправлен DHCPOFFER: %s -> %s", mac, offered_ip)
        except (ConfigError, LeasePoolExhausted, ValueError, OSError) as exc:
            LOGGER.error("Ошибка обработки DHCPDISCOVER: %s", exc)
        except Exception:
            LOGGER.exception("Непредвиденная ошибка обработки DHCPDISCOVER")

    def build_offer(
        self, discover: Any, offered_ip: str, settings: dict[str, Any]
    ) -> Any:
        server_ip = settings["pxe_next_server"]
        server_mac = get_if_hwaddr(self.interface)
        next_server = settings["pxe_next_server"]

        return (
            Ether(src=server_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src=server_ip, dst="255.255.255.255")
            / UDP(sport=67, dport=68)
            / BOOTP(
                op=2,
                htype=discover[BOOTP].htype,
                hlen=discover[BOOTP].hlen,
                xid=discover[BOOTP].xid,
                flags=discover[BOOTP].flags,
                yiaddr=offered_ip,
                siaddr=next_server,
                giaddr=discover[BOOTP].giaddr,
                chaddr=discover[BOOTP].chaddr,
                file=settings["pxe_boot_file"],
            )
            / DHCP(
                options=[
                    ("message-type", "offer"),
                    ("server_id", server_ip),
                    ("lease_time", 3600),
                    ("subnet_mask", settings["subnet_mask"]),
                    ("router", settings["router"]),
                    ("tftp_server_name", next_server),
                    ("boot-file-name", settings["pxe_boot_file"]),
                    "end",
                ]
            )
        )


def build_assign_ip_command(
    interface: str, server_ip: ipaddress.IPv4Address, network: ipaddress.IPv4Network
) -> list[str]:
    safe_interface = validate_interface_name(interface)
    system = platform.system().lower()
    if system == "windows":
        return [
            "netsh",
            "interface",
            "ip",
            "set",
            "address",
            f"name={safe_interface}",
            "static",
            str(server_ip),
            str(network.netmask),
        ]
    if system == "darwin":
        return ["ifconfig", safe_interface, "alias", str(server_ip), str(network.netmask)]
    return [
        "ip",
        "address",
        "replace",
        f"{server_ip}/{network.prefixlen}",
        "dev",
        safe_interface,
    ]


def run_dhcp_server(config_path: Union[str, Path], interface: Optional[str] = None) -> None:
    DHCPServer(config_path, interface).serve_forever()


def is_network_discovery_runtime_error(exc: RuntimeError) -> bool:
    return "Автоопределение сети" in str(exc)


def run_cli(config_path: Union[str, Path], interface: Optional[str] = None) -> None:
    try:
        run_dhcp_server(config_path, interface)
    except NetworkDiscoveryError as exc:
        LOGGER.error(
            "Не удалось определить сеть: %s. Пожалуйста, назначьте IP-адрес "
            "на интерфейс вручную или убедитесь, что в сети есть трафик.",
            exc,
        )
        sys.exit(1)
    except RuntimeError as exc:
        if not is_network_discovery_runtime_error(exc):
            raise
        LOGGER.error(
            "Не удалось определить сеть: %s. Пожалуйста, назначьте IP-адрес "
            "на интерфейс вручную или убедитесь, что в сети есть трафик.",
            exc,
        )
        sys.exit(1)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Whitelist PXE DHCP server")
    parser.add_argument("--config", default="config.json", help="Путь к config.json")
    parser.add_argument("--interface", help="Сетевой интерфейс для DHCP")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    run_cli(args.config, args.interface)
