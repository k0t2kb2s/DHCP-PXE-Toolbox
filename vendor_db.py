from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, Union


OCTET_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


def load_manuf(path: Union[str, Path]) -> Dict[str, str]:
    vendors: Dict[str, str] = {}
    manuf_path = Path(path)

    with manuf_path.open(encoding="utf-8", errors="replace") as manuf_file:
        for raw_line in manuf_file:
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            columns = line.split()
            if len(columns) < 2:
                continue

            address = columns[0].split("/", 1)[0].replace("-", ":")
            octets = address.split(":")
            if len(octets) < 3 or not all(OCTET_RE.fullmatch(octet) for octet in octets[:3]):
                continue

            prefix = ":".join(octets[:3]).upper()
            vendor = " ".join(columns[2:]) if len(columns) > 2 else columns[1]
            vendors.setdefault(prefix, vendor)

    return vendors


def lookup_vendor(mac: str, vendors: Dict[str, str]) -> str:
    prefix = ":".join(mac.split(":")[:3]).upper()
    return vendors.get(prefix, "Неизвестный вендор")
