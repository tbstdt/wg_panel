# wg_panel

Простая веб-панель для управления клиентами WireGuard-сервера (интерфейс `wg0`).
Один Python-файл без внешних зависимостей; HTML/JS встроены в скрипт.

> Сейчас сервер работает на `amneziawg-go`, поэтому панель вызывает утилиту
> `amneziawg` и хранит данные в `/userdata/wg-panel`. Конфиги клиентов при этом —
> обычный WireGuard, без параметров обфускации. Переход на чистый `wg` запланирован.

## Платформа

Панель сделана и проверена на **Ubuntu Touch** (база Ubuntu 24.04), сервер —
смартфон. Отсюда особенности:

- **Корневая ФС только для чтения.** `/etc`, `/usr/local`, `/var/spool/cron`
  нельзя менять без `sudo mount -o remount,rw /`, поэтому все данные панели
  лежат на `/userdata`, а после перезагрузки ничего не перемонтируется.
- **Userspace-реализация** — интерфейс поднимает `amneziawg-go`, а не модуль
  ядра.
- **Интернет через Wi-Fi** — NAT настроен на `wlan0`.
- **Батарея и датчики телефона** — в системном мониторе выводятся заряд и
  температура батареи (`/sys/class/power_supply/battery`) и температура CPU
  (`/sys/class/thermal`).
- **Минимум зависимостей** — только стандартная библиотека Python; `curl` нет,
  поэтому используется `wget`.

На обычном Linux панель тоже заработает, но пути (`/userdata`), интерфейс
`wlan0` и датчики придётся поправить под свою систему.

## Возможности

- Добавление клиента: генерация ключей и PSK, выдача IP из `10.66.66.0/24`,
  добавление пира в `wg0`, готовый `client.conf`
- Просмотр конфига, QR-код, копирование и скачивание `.conf`
- Включение/отключение клиента без удаления
- Удаление клиента
- Трафик по клиентам за текущий месяц (снимок раз в минуту в фоне, сбросы
  счётчиков при перезапуске `wg0` учитываются)
- Индикатор «подключён/отключён»: handshake не старше 3 минут
- Системный монитор: CPU, load average, память, скорость `wg0`, uptime,
  заряд и температура батареи, температура CPU
- Настройка Endpoint (обновляет его во всех клиентских конфигах)
- Кнопка обновления IP в DuckDNS

## Требования

- Linux, Python 3.7+ (только стандартная библиотека)
- Поднятый интерфейс `wg0` и утилита `amneziawg` (совместима с `wg`)
- `qrencode` — для QR-кодов (без него показывается текст конфига)
- `wget` — для определения внешнего IP
- Запуск от root (управление интерфейсом и запись в `/userdata/wg-panel`)
- Опционально: `/usr/local/bin/duckdns-update.sh` — скрипт обновления DuckDNS
  (в репозитории — шаблон `duckdns/duckdns-update.sh.example`)

## Что и как запускается

| Компонент | Чем запускается |
|---|---|
| Интерфейс `wg0` + NAT | crontab root, `@reboot` |
| DuckDNS | crontab root, каждые 10 минут |
| Панель | systemd, `awg-panel.service` (автоперезапуск при падении) |

crontab root:

```
@reboot /usr/local/bin/start-awg-full.sh >> /tmp/awg-boot.log 2>&1
*/10 * * * * /usr/local/bin/duckdns-update.sh
```

`start-awg-full.sh` запускает `amneziawg-go`, загружает
`/userdata/wg-panel/wg0-native.conf`, назначает адрес, включает `ip_forward` и
добавляет правила NAT/FORWARD (без дублей).

Корневая ФС смонтирована только для чтения, crontab тоже лежит на ней. Чтобы
его изменить:

```bash
sudo mount -o remount,rw /
sudo crontab -e
sudo mount -o remount,ro /
```

## DuckDNS

`duckdns/duckdns-update.sh.example` — скрипт обновления IP. Скопируйте его в
`/usr/local/bin/duckdns-update.sh` и впишите `DOMAIN` и `TOKEN`. IP DuckDNS
берёт из самого запроса, при ошибке скрипт завершается с кодом 1. Скрипт
запускает cron (см. выше) и кнопка «Update IP» в панели.

## Установка панели

```bash
sudo cp awg_panel.py /userdata/awg_panel.py
sudo cp awg-panel.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now awg-panel
```

Панель доступна на `http://<адрес-сервера>:8080`. Перед добавлением первого
клиента укажите Endpoint (`host:port` сервера) в разделе Settings — без него
клиенты не создаются.

Логи и статус:

```bash
systemctl status awg-panel
journalctl -u awg-panel -f
```

## Настройки

Константы в начале `awg_panel.py`:

| Константа | Значение по умолчанию | Назначение |
|---|---|---|
| `CONFIG_DIR` | `/userdata/wg-panel` | Каталог сервера |
| `CLIENTS_DIR` | `/userdata/wg-panel/clients` | Каталоги клиентов |
| `SETTINGS_FILE` | `/userdata/wg-panel/panel_settings.json` | Настройки панели (Endpoint) |
| `STATS_FILE` | `/userdata/wg-panel/traffic_stats.json` | Месячная статистика трафика |
| `WEB_PORT` | `8080` | Порт панели |
| `SERVER_CONF` | `/userdata/wg-panel/wg0-native.conf` | Конфиг, из которого поднимается `wg0`; панель записывает в него пиров |
| `DUCKDNS_SCRIPT` | `/usr/local/bin/duckdns-update.sh` | Скрипт DuckDNS |

## Хранение данных

Данные лежат на `/userdata`: корневая ФС смонтирована только для чтения.

Пиры сохраняются в `SERVER_CONF`, поэтому переживают перезапуск `wg0`. Каждый
блок помечается комментарием `# client: <имя>`. Отключённый клиент убирается и
из интерфейса, и из конфига; при включении он возвращается в оба места.

```
/userdata/wg-panel/
├── server_public.key         # публичный ключ сервера (для клиентских конфигов)
├── panel_settings.json       # {"endpoint": "host:port"}
├── traffic_stats.json        # трафик за месяц
└── clients/
    └── <имя>/
        ├── private.key
        ├── public.key
        ├── preshared.key
        ├── client.conf
        └── disabled          # есть, если клиент отключён
```

## HTTP API

| Метод | Путь | Описание |
|---|---|---|
| GET | `/` | Главная страница |
| GET | `/api/add?name=` | Добавить клиента (`[a-zA-Z0-9_-]+`) |
| GET | `/api/remove?name=` | Удалить клиента |
| GET | `/api/toggle?name=` | Включить/отключить клиента |
| GET | `/api/config?name=` | Конфиг и QR (JSON) |
| GET | `/api/download?name=` | Скачать `.conf` |
| GET | `/api/traffic` | Трафик клиентов за месяц |
| GET | `/api/system` | Системные метрики |
| GET | `/api/duckdns` | Обновить DuckDNS, вернуть внешний IP |
| POST | `/api/settings` | `{"endpoint": "host:port"}` |

## Безопасность

Авторизации нет. Панель рассчитана только на локальную сеть: не открывайте
порт 8080 в интернет.

## Известные проблемы

Нет.
