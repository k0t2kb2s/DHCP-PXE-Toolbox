from vendor_db import load_manuf, lookup_vendor


def test_load_manuf_and_lookup(tmp_path):
    path = tmp_path / "manuf"
    path.write_text(
        "# comment\n"
        "00:00:0C\tCisco\tCisco Systems, Inc\n"
        "AA:BB:CC\tExample\n",
        encoding="utf-8",
    )

    vendors = load_manuf(path)

    assert lookup_vendor("00:00:0c:11:22:33", vendors) == "Cisco Systems, Inc"
    assert lookup_vendor("aa:bb:cc:11:22:33", vendors) == "Example"
    assert lookup_vendor("11:22:33:44:55:66", vendors) == "Неизвестный вендор"
