# PXE DHCP Whitelist Server

## Описание

PXE DHCP Whitelist Server — автономный DHCP/PXE-сервер с Web GUI, автоопределением подсети через network sniffing и фильтрацией клиентов по JSON whitelist.

Проект умеет:

- слушать IP/ARP-трафик на выбранном интерфейсе и автоматически определять рабочую `/24` подсеть;
- атомарно обновлять `config.json` после автоопределения сети;
- принимать DHCPDISCOVER от PXE-устройств;
- выдавать DHCPOFFER только MAC-адресам из whitelist;
- молча игнорировать чужие MAC-адреса через Silent Drop;
- передавать PXE-параметры: TFTP/next-server и boot file;
- управлять whitelist и смотреть текущие DHCP/PXE-настройки через Web GUI.

Основные файлы:

- `app.py` — FastAPI Web GUI и API.
- `dhcp_server.py` — DHCP/PXE-ядро на Scapy.
- `network_simulator.py` — генератор фейкового ARP/IP-трафика для тестирования sniffing-фазы.
- `config_store.py` — чтение, валидация и атомарная запись `config.json`.
- `vendor_db.py` — парсер Wireshark `manuf` для определения производителя по MAC-префиксу.
- `templates/index.html` — Bootstrap-интерфейс.
- `config.json` — DHCP-настройки и whitelist.
- `manuf` — база MAC-вендоров.

## Требования

- Python 3.9+
- `pip`
- сетевой интерфейс, на котором будут видны PXE-клиенты
- файл `manuf` в корне проекта
- файл `config.json` в корне проекта

**Для запуска DHCP-ядра и `network_simulator.py` требуются права Администратора / root, потому что Scapy использует raw sockets для sniff/send сетевых пакетов.**

Платформенные замечания:

- Linux: обычно достаточно запускать DHCP-ядро и симулятор через `sudo`.
- Windows: запускайте терминал от имени Администратора. Для Scapy обычно нужен установленный Npcap.
- macOS: запускайте DHCP-ядро и симулятор через `sudo`.

Если интерфейс уже имеет IPv4-адрес в найденной сети, сервер использует его как `pxe_next_server`. Если адреса нет, сервер попробует назначить выбранный IP сам:

- Linux: через `ip address replace`.
- Windows: через `netsh interface ip set address`.
- macOS: через `ifconfig alias`.

## Установка

Создайте виртуальное окружение:

```bash
python3 -m venv .venv
```

Активация на Linux/macOS:

```bash
source .venv/bin/activate
```

Активация на Windows PowerShell:

```powershell
.\.venv\Scripts\activate
```

Установите зависимости:

```bash
pip install -r requirements.txt
```

Для запуска тестов установите dev-зависимости:

```bash
pip install -r requirements-dev.txt
```

## Запуск проекта

### Web GUI без root-прав

Web GUI можно запускать без прав Администратора/root, если вы не включаете DHCP-поток внутри веб-приложения:

```bash
uvicorn app:app --host 127.0.0.1 --port 8000
```

Откройте:

```text
http://127.0.0.1:8000
```

Web GUI позволяет:

- смотреть whitelist;
- добавлять MAC-адреса;
- удалять MAC-адреса;
- видеть производителя по базе `manuf`;
- видеть текущие DHCP/PXE-настройки из `config.json`.

### DHCP-сервер на Linux

Посмотрите имя сетевого интерфейса:

```bash
ip link
```

Запустите DHCP-сервер:

```bash
sudo .venv/bin/python dhcp_server.py --interface eth0
```

Пример для VirtualBox host-only интерфейса:

```bash
sudo .venv/bin/python dhcp_server.py --interface vboxnet0
```

### DHCP-сервер на Windows

Откройте PowerShell или Command Prompt от имени Администратора.

Посмотрите список интерфейсов:

```powershell
netsh interface show interface
```

Запустите DHCP-сервер, указав имя интерфейса:

```powershell
.\.venv\Scripts\python.exe dhcp_server.py --interface "Ethernet"
```

Если интерфейс называется иначе, используйте его точное имя, например:

```powershell
.\.venv\Scripts\python.exe dhcp_server.py --interface "VirtualBox Host-Only Network"
```

### DHCP-сервер на macOS

Посмотрите интерфейсы:

```bash
ifconfig
```

Запустите DHCP-сервер:

```bash
sudo .venv/bin/python dhcp_server.py --interface en0
```

Для проводного адаптера имя может быть `en0`, `en1`, `en5` или другое — зависит от устройства.

### Web GUI вместе с DHCP-потоком

Можно запустить Web GUI и DHCP-ядро в одном процессе. Для DHCP-ядра всё равно нужны права Администратора/root.

Linux/macOS:

```bash
sudo DHCP_ENABLED=true DHCP_INTERFACE=eth0 .venv/bin/uvicorn app:app --host 0.0.0.0 --port 8000
```

Windows PowerShell от имени Администратора:

```powershell
$env:DHCP_ENABLED="true"
$env:DHCP_INTERFACE="Ethernet"
.\.venv\Scripts\uvicorn.exe app:app --host 0.0.0.0 --port 8000
```

### Симулятор сети

`network_simulator.py` нужен для проверки автоопределения подсети. Он раз в секунду отправляет фейковые ARP или IP/UDP broadcast-пакеты в выбранный интерфейс.

Linux/macOS:

```bash
sudo .venv/bin/python network_simulator.py --interface vboxnet0 --network 192.168.56.0/24 --mode mixed
```

Windows PowerShell от имени Администратора:

```powershell
.\.venv\Scripts\python.exe network_simulator.py --interface "VirtualBox Host-Only Network" --network 192.168.56.0/24 --mode mixed
```

Одноразовый запуск на 15 пакетов:

```bash
sudo .venv/bin/python network_simulator.py --interface vboxnet0 --network 192.168.56.0/24 --mode mixed --count 15
```

Проверка DHCP-ядра одним DHCPDISCOVER от конкретного MAC:

```bash
sudo .venv/bin/python network_simulator.py --interface vboxnet0 --test-dhcp aa:bb:cc:dd:ee:ff
```

Windows PowerShell от имени Администратора:

```powershell
.\.venv\Scripts\python.exe network_simulator.py --interface "VirtualBox Host-Only Network" --test-dhcp aa:bb:cc:dd:ee:ff
```

В этом режиме симулятор не отправляет фоновый ARP/IP-трафик. Он формирует ровно один broadcast DHCPDISCOVER на UDP port 67 с указанным MAC в BOOTP `chaddr`. Это удобно для проверки Silent Drop и DHCPOFFER.

Для проверки DHCPOFFER добавьте MAC в `whitelist`. Для проверки Silent Drop используйте MAC, которого нет в `whitelist`.

Режимы симулятора:

- `--mode arp` — отправлять только ARP.
- `--mode ip` — отправлять только IP/UDP broadcast.
- `--mode mixed` — чередовать ARP и IP/UDP.

Полезные параметры:

- `--interface` — интерфейс отправки пакетов.
- `--network` — подсеть, которую должен увидеть DHCP-сервер.
- `--router` — IP роутера для ARP-запросов, по умолчанию `.1`.
- `--hosts` — список host-частей через запятую, например `15,30,80`.
- `--interval` — интервал между пакетами.
- `--count` — количество пакетов, `0` означает бесконечно.
- `--test-dhcp` — отправить один DHCPDISCOVER от указанного MAC и завершиться.

## Логика работы

Короткий пайплайн DHCP-ядра:

1. Сниффинг сети 10 секунд.
2. Автоконфигурация `config.json`.
3. Прослушивание DHCPDISCOVER.
4. Выдача DHCPOFFER только устройствам из whitelist.

Подробно:

1. При старте `dhcp_server.py` слушает выбранный интерфейс в promiscuous-режиме.
2. Сервер перехватывает IP и ARP пакеты от уже активных устройств.
3. Из пакетов извлекаются IP-адреса источников.
4. По найденным адресам выбирается рабочая `/24` подсеть.
5. Сервер определяет шлюз: сначала системный gateway, затем адрес `.1` выбранной подсети.
6. Сервер выбирает IP для себя: текущий IPv4 интерфейса или свободный адрес начиная с `.50`.
7. В `config.json` атомарно обновляются:
   - `pool_start`;
   - `pool_end`;
   - `subnet_mask`;
   - `router`;
   - `pxe_next_server`.
8. После этого DHCP-ядро начинает слушать UDP port 67.
9. Когда приходит DHCPDISCOVER, сервер извлекает MAC-адрес клиента.
10. MAC проверяется по `whitelist` из `config.json`.
11. Если MAC отсутствует, пакет игнорируется без ответа: Silent Drop.
12. Если MAC есть в whitelist, сервер отправляет DHCPOFFER.

DHCPOFFER содержит:

- IP из DHCP-пула;
- subnet mask;
- router;
- lease time;
- option 66, TFTP Server Name / Next Server;
- option 67, Bootfile Name;
- BOOTP `siaddr`;
- BOOTP `file`.

Если в сети нет активных устройств, интерфейс не имеет IPv4-адреса и никто не отправляет IP/ARP-трафик, автоопределить подсеть невозможно. В таком случае задайте IP интерфейса вручную или используйте `network_simulator.py` для тестовой сети.
