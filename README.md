# PXE DHCP Whitelist Server

> Тактический автономный DHCP/PXE-сервер. Не домашняя игрушка "а давайте всем раздадим IP", а аккуратный вышибала: своих пускает, чужих молча шлет нахуй.

---

## Описание

`PXE DHCP Whitelist Server` - это автономный DHCP/PXE-сервер с Web GUI, автоопределением подсети через network sniffing и фильтрацией клиентов по JSON whitelist.

Говоря по-человечески: ты поднимаешь сервер на своем ноуте/хосте, цепляешь его в нужный сетевой сегмент, он 10 секунд нюхает провод, понимает где живет сеть, обновляет `config.json`, потом слушает DHCPDISCOVER на 67 порту и отвечает только тем железкам, которые ты заранее внес в whitelist.

**Логика "Вышибалы":**

| Кто пришел | Что делает сервер |
| --- | --- |
| MAC есть в `whitelist` | Выдает DHCPOFFER, IP из пула, router, subnet mask, PXE next-server и boot file. Все красиво, проходи, брат. |
| MAC нет в `whitelist` | **Silent Drop**. Никаких ответов, никаких "пошел отсюда", просто тишина. Левый чужак орет DHCPDISCOVER в пустоту, а сервер делает вид, что его не существует. |

Это важно: Silent Drop не палит сервер лишними ответами и не устраивает пизду в чужой сети. Если клиент не твой - он не получает вообще ничего.

Проект умеет:

- слушать IP/ARP-трафик на выбранном интерфейсе и автоматически определять рабочую IPv4-подсеть;
- считать сеть нормально через `ipaddress`, без ебанатского `ip.split('.')[:3]`;
- атомарно обновлять `config.json` после автоопределения сети;
- принимать DHCPDISCOVER от PXE-устройств;
- выдавать DHCPOFFER только MAC-адресам из whitelist;
- вести in-memory таблицу DHCP leases, чтобы не выдать один IP двум разным MAC;
- молча игнорировать чужие MAC через Silent Drop;
- передавать PXE-параметры: TFTP/next-server и boot file;
- управлять whitelist и смотреть текущие DHCP/PXE-настройки через Web GUI.

Основные файлы:

| Файл | Нахуя он нужен |
| --- | --- |
| `app.py` | FastAPI Web GUI и API. Тут веб-морда, добавление/удаление MAC, отображение конфига. |
| `dhcp_server.py` | DHCP/PXE-ядро на Scapy. Тут вся настоящая сетевая магия и ответственность. |
| `network_simulator.py` | Симулятор живой сети и точечный генератор DHCPDISCOVER для проверки вышибалы. |
| `config_store.py` | Чтение, валидация и атомарная запись `config.json`, чтобы файл не превращался в фарш. |
| `vendor_db.py` | Парсер Wireshark `manuf`, определяет производителя по MAC-префиксу. |
| `templates/index.html` | Bootstrap-интерфейс. Кнопки, таблицы, вся вебовая косметика. |
| `config.json` | DHCP-настройки и whitelist. Главная записная книжка проекта. |
| `manuf` | База MAC-вендоров. Уже лежит в корне проекта. |

---

## Требования

- Python 3.9+
- `pip`
- сетевой интерфейс, на котором реально видны PXE-клиенты
- файл `manuf` в корне проекта
- файл `config.json` в корне проекта

**ВНИМАНИЕ, БЛЯТЬ: для запуска DHCP-ядра и `network_simulator.py` нужны права Администратора / root.**

Почему так? Потому что Scapy использует raw sockets: он сам собирает и отправляет низкоуровневые сетевые пакеты. Обычному пользователю ОС такое не даст, и правильно сделает, иначе любой еблан мог бы крутить сеть как хотел.

Платформенные заметки:

| ОС | Что помнить |
| --- | --- |
| Linux | DHCP-ядро и симулятор обычно запускать через `sudo`. |
| Windows | Терминал запускать от имени Администратора. Для Scapy обычно нужен Npcap. |
| macOS | DHCP-ядро и симулятор запускать через `sudo`. |

Если интерфейс уже имеет IPv4-адрес в найденной сети, сервер использует его как `pxe_next_server`. Если адреса нет, сервер попробует назначить выбранный IP сам.

---

## Установка

Создай виртуальное окружение:

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

Поставь зависимости:

```bash
pip install -r requirements.txt
```

Для тестов поставь dev-зависимости:

```bash
pip install -r requirements-dev.txt
```

> Если `pip` начинает ныть - сначала проверь, что venv активирован. Половина "мистических" проблем Python - это просто ты ставишь пакеты не туда, котакбас.

---

## Кроссплатформенность

Проект умеет работать на Linux, Windows и macOS. Но сеть - штука системная, поэтому команды назначения IP отличаются.

| ОС | Как назначается IP серверу, если интерфейс пустой |
| --- | --- |
| Linux | `ip address replace` |
| Windows | `netsh interface ip set address` |
| macOS | `ifconfig alias` |

Что происходит на практике:

- сервер нюхает сеть;
- понимает подсеть;
- выбирает себе IP, например `.50`;
- если на интерфейсе уже есть подходящий IP - использует его;
- если IP нет - пытается назначить его системной командой;
- после этого пишет свой IP в `pxe_next_server`, потому что именно этот хост будет TFTP/PXE next-server.

И еще раз жирно, потому что это не декоративная надпись:

**Без Администратора / root DHCP-ядро и симулятор не заведутся. ОС не даст обычному юзеру лезть в raw sockets, слушать DHCP и слать низкоуровневые пакеты.**

---

## Запуск проекта

### Web GUI без root-прав

Веб-морду можно запускать без root, если DHCP-поток внутри нее не включаешь:

```bash
uvicorn app:app --host 127.0.0.1 --port 8000
```

Открывай:

```text
http://127.0.0.1:8000
```

Web GUI умеет:

- показывать whitelist;
- добавлять MAC-адреса;
- удалять MAC-адреса;
- показывать производителя по базе `manuf`;
- показывать текущие DHCP/PXE-настройки из `config.json`.

### DHCP-сервер на Linux

Сначала посмотри имя интерфейса:

```bash
ip link
```

Запусти DHCP-сервер:

```bash
sudo .venv/bin/python dhcp_server.py --interface eth0
```

Пример для VirtualBox host-only интерфейса:

```bash
sudo .venv/bin/python dhcp_server.py --interface vboxnet0
```

### DHCP-сервер на Windows

Открой PowerShell или Command Prompt от имени Администратора. Не "ну я вроде админ", а реально **Run as Administrator**, иначе будет пизда с правами.

Посмотри список интерфейсов:

```powershell
netsh interface show interface
```

Запусти DHCP-сервер:

```powershell
.\.venv\Scripts\python.exe dhcp_server.py --interface "Ethernet"
```

Если интерфейс называется иначе, используй точное имя:

```powershell
.\.venv\Scripts\python.exe dhcp_server.py --interface "VirtualBox Host-Only Network"
```

### DHCP-сервер на macOS

Посмотри интерфейсы:

```bash
ifconfig
```

Запусти DHCP-сервер:

```bash
sudo .venv/bin/python dhcp_server.py --interface en0
```

Для проводного адаптера имя может быть `en0`, `en1`, `en5` или другое. macOS любит свои приколы, так что смотри `ifconfig`, а не гадай на кофейной гуще.

### Web GUI вместе с DHCP-потоком

Можно запустить Web GUI и DHCP-ядро в одном процессе. Удобно, но помни: раз внутри стартует DHCP-ядро, права Администратора/root все равно нужны.

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

---

## Симулятор сети

`network_simulator.py` нужен, чтобы проверить автоопределение подсети без настоящего роутера, коммутатора и плясок с железом. Он раз в секунду отправляет фейковые ARP или IP/UDP broadcast-пакеты в выбранный интерфейс, имитируя живую сеть.

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

Режимы:

| Режим | Что шлет |
| --- | --- |
| `--mode arp` | Только ARP. |
| `--mode ip` | Только IP/UDP broadcast. |
| `--mode mixed` | Чередует ARP и IP/UDP. |

Полезные параметры:

| Параметр | Что делает |
| --- | --- |
| `--interface` | Интерфейс отправки пакетов. |
| `--network` | Подсеть, которую должен увидеть DHCP-сервер. |
| `--router` | IP роутера для ARP-запросов, по умолчанию `.1`. |
| `--hosts` | Список host-частей через запятую, например `15,30,80`. |
| `--interval` | Интервал между пакетами. |
| `--count` | Количество пакетов, `0` значит бесконечно. |
| `--test-dhcp` | Отправить один DHCPDISCOVER от указанного MAC и завершиться. |

### Проверка "Вышибалы" через `--test-dhcp`

Это точечный режим: симулятор **не** шлет фоновый ARP/IP-трафик. Он формирует ровно один broadcast DHCPDISCOVER на UDP port 67 с указанным MAC в BOOTP `chaddr`.

Linux/macOS:

```bash
sudo .venv/bin/python network_simulator.py --interface vboxnet0 --test-dhcp aa:bb:cc:dd:ee:ff
```

Windows PowerShell от имени Администратора:

```powershell
.\.venv\Scripts\python.exe network_simulator.py --interface "VirtualBox Host-Only Network" --test-dhcp aa:bb:cc:dd:ee:ff
```

Как проверить:

1. Добавь MAC в `whitelist`.
2. Запусти `dhcp_server.py`.
3. Запусти `network_simulator.py --test-dhcp aa:bb:cc:dd:ee:ff`.
4. Если MAC свой - сервер должен ответить DHCPOFFER.
5. Если MAC левый - сервер молчит. Вот это и есть Silent Drop: чужака не бьют, не ругают, не учат жизни, просто отправляют в пизду тишиной.

---

## Логика и Магия

### Как эта хуйня работает

Короткий пайплайн DHCP-ядра:

1. **Сниффинг сети** - 10 секунд шпионажа за ARP/IP пакетами.
2. **Автонастройка подсети** - расчет сети на лету через `ipaddress`.
3. **Перезапись `config.json`** - атомарно, чтобы файл не умер между чтением и записью.
4. **DHCP-петля на порту 67** - слушаем DHCPDISCOVER и обслуживаем только whitelist.

Почему это охуенно: сеть в проводе не пахнет. Кабель не говорит "привет, я 192.168.1.0/24, шлюз у меня 192.168.1.1". В Ethernet летят кадры, в них ARP/IP, и по этим пакетам уже можно понять, кто тут живет и какая подсеть рядом. Поэтому сервер сначала смотрит, что происходит вокруг, а потом уже лезет раздавать адреса.

Подробно:

1. При старте `dhcp_server.py` слушает выбранный интерфейс в promiscuous-режиме.
2. В течение 10 секунд он перехватывает IP и ARP пакеты от активных устройств.
3. Из пакетов достаются IP-адреса источников.
4. Рабочая IPv4-подсеть выбирается через стандартную библиотеку `ipaddress`. Если ОС знает маску интерфейса - используется она. Если нет - сеть выводится по наблюдаемым адресам с безопасным fallback не уже `/24`.
5. Шлюз определяется так: сначала системный gateway, если он понятен; иначе берется адрес `.1` выбранной подсети.
6. IP сервера выбирается так: текущий IPv4 интерфейса или свободный адрес начиная с `.50`.
7. В `config.json` атомарно обновляются:
   - `pool_start`;
   - `pool_end`;
   - `subnet_mask`;
   - `router`;
   - `pxe_next_server`.
8. После этого DHCP-ядро начинает слушать UDP port 67.
9. Когда приходит DHCPDISCOVER, сервер извлекает MAC-адрес клиента.
10. MAC проверяется по `whitelist` из `config.json`.
11. Если MAC отсутствует - пакет игнорируется без ответа: **Silent Drop**.
12. Если MAC есть в whitelist - сервер отправляет DHCPOFFER.

Перед отправкой DHCPOFFER сервер проверяет in-memory leases и резервирует адрес за MAC-адресом с timestamp. Адреса роутера, PXE-сервера, network/broadcast и IP, замеченные во время sniffing, клиентам не выдаются. Это нужно, чтобы не устроить IP conflict и не получить сетевую кашу, где два устройства думают, что они один и тот же адрес.

DHCPOFFER содержит:

- IP из DHCP-пула;
- subnet mask;
- router;
- lease time;
- option 66, TFTP Server Name / Next Server;
- option 67, Bootfile Name;
- BOOTP `siaddr`;
- BOOTP `file`.

Если в сети нет активных устройств, интерфейс не имеет IPv4-адреса и никто не отправляет IP/ARP-трафик, автоопределить подсеть невозможно. Это не баг, это физика: сервер не телепат. В таком случае назначь IP интерфейса вручную или используй `network_simulator.py`, чтобы подкинуть тестовый трафик.

---

## Быстрая памятка

| Хочешь | Делай |
| --- | --- |
| Открыть веб-морду | `uvicorn app:app --host 127.0.0.1 --port 8000` |
| Запустить DHCP на Linux | `sudo .venv/bin/python dhcp_server.py --interface eth0` |
| Запустить DHCP на Windows | `.\.venv\Scripts\python.exe dhcp_server.py --interface "Ethernet"` |
| Сымитировать сеть | `sudo .venv/bin/python network_simulator.py --interface vboxnet0 --network 192.168.56.0/24 --mode mixed` |
| Проверить MAC через DHCPDISCOVER | `sudo .venv/bin/python network_simulator.py --interface vboxnet0 --test-dhcp aa:bb:cc:dd:ee:ff` |

> Главное правило: сначала whitelist, потом DHCP. Иначе будешь удивляться, почему сервер "не отвечает", хотя он просто делает ровно то, что ты ему сказал - молча отшивает всех левых.
