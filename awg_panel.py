#!/usr/bin/env python3
"""AmneziaWG Web Management Panel v3"""

import http.server
import json
import os
import subprocess
import re
import hashlib
import time
import urllib.parse
import shutil
import threading

# kept on /userdata: the root filesystem is mounted read-only
CONFIG_DIR = "/userdata/wg-panel"
CLIENTS_DIR = os.path.join(CONFIG_DIR, "clients")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "panel_settings.json")
STATS_FILE = os.path.join(CONFIG_DIR, "traffic_stats.json")
STATS_INTERVAL = 60  # seconds between background traffic snapshots
ONLINE_TIMEOUT = 180  # a peer with a handshake newer than this is "connected"
# Config wg0 is loaded from; peers added/removed by the panel are persisted here
SERVER_CONF = os.path.join(CONFIG_DIR, "wg0-native.conf")
WEB_PORT = 8080
DUCKDNS_SCRIPT = "/usr/local/bin/duckdns-update.sh"


def run_cmd(cmd, timeout=20):
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout)
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def run_cmd_status(cmd, timeout=20):
    """Run a command and return (returncode, stdout). Errors are not hidden."""
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True,
                                text=True, timeout=timeout)
        return result.returncode, result.stdout.strip()
    except subprocess.TimeoutExpired:
        return -1, ""
    except Exception:
        return -2, ""


def load_settings():
    if os.path.exists(SETTINGS_FILE):
        with open(SETTINGS_FILE) as f:
            return json.load(f)
    return {"endpoint": ""}


def save_settings(data):
    os.makedirs(os.path.dirname(SETTINGS_FILE), exist_ok=True)
    with open(SETTINGS_FILE, "w") as f:
        json.dump(data, f)


def generate_qr_svg(text):
    try:
        tmp = "/tmp/qr_" + hashlib.md5(text.encode()).hexdigest() + ".png"
        result = subprocess.run(
            ["qrencode", "-o", tmp, "-s", "6", "-m", "2", text],
            capture_output=True, timeout=10
        )
        if result.returncode == 0 and os.path.exists(tmp):
            with open(tmp, "rb") as f:
                import base64
                b64 = base64.b64encode(f.read()).decode()
            os.unlink(tmp)
            return f'<img src="data:image/png;base64,{b64}" style="max-width:300px;border-radius:8px" />'
    except:
        pass
    return f'<pre style="font-size:8px;background:#fff;color:#000;padding:10px;display:inline-block;word-break:break-all;border-radius:8px">{text}</pre>'


def get_server_pubkey():
    path = os.path.join(CONFIG_DIR, "server_public.key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return run_cmd("amneziawg show wg0 | grep 'public key' | awk '{print $3}'")


def get_clients():
    if not os.path.exists(CLIENTS_DIR):
        return []
    return [d for d in os.listdir(CLIENTS_DIR)
            if os.path.isdir(os.path.join(CLIENTS_DIR, d))]


def valid_name(name):
    return bool(name) and re.fullmatch(r'[a-zA-Z0-9_-]+', name) is not None


def write_server_conf(content):
    tmp = SERVER_CONF + ".tmp"
    with open(tmp, "w") as f:
        f.write(content)
    os.chmod(tmp, 0o600)
    os.replace(tmp, SERVER_CONF)


def split_conf_sections(content):
    """Split a wg config into sections; comment lines right above a
    [Section] header belong to that section."""
    sections, cur = [], []
    for line in content.splitlines(keepends=True):
        if line.strip().startswith("[") and any(
                l.strip() and not l.strip().startswith("#") for l in cur):
            tail = []
            while cur and cur[-1].strip().startswith("#"):
                tail.insert(0, cur.pop())
            sections.append("".join(cur))
            cur = tail
        cur.append(line)
    if cur:
        sections.append("".join(cur))
    return sections


def server_conf_remove_peer(pubkey):
    with open(SERVER_CONF) as f:
        sections = split_conf_sections(f.read())
    key_re = re.compile(r'^\s*PublicKey\s*=\s*' + re.escape(pubkey) + r'\s*$', re.M)
    kept = [sec for sec in sections
            if not (re.search(r'^\s*\[Peer\]', sec, re.M) and key_re.search(sec))]
    write_server_conf("".join(kept).rstrip("\n") + "\n")


def server_conf_add_peer(name, pubkey, psk, allowed_ip):
    # drop a stale block for the same key first so it is never duplicated
    server_conf_remove_peer(pubkey)
    with open(SERVER_CONF) as f:
        content = f.read().rstrip("\n")
    content += (f"\n\n# client: {name}\n[Peer]\nPublicKey = {pubkey}\n"
                f"PresharedKey = {psk}\nAllowedIPs = {allowed_ip}\n")
    write_server_conf(content)


def read_client_psk(name):
    path = os.path.join(CLIENTS_DIR, name, "preshared.key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return ""


def is_client_disabled(name):
    return os.path.exists(os.path.join(CLIENTS_DIR, name, "disabled"))


def get_client_config_raw(name):
    path = os.path.join(CLIENTS_DIR, name, "client.conf")
    if os.path.exists(path):
        with open(path) as f:
            return f.read()
    return ""


def get_client_pubkey(name):
    path = os.path.join(CLIENTS_DIR, name, "public.key")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return ""


def get_client_allowed_ip(name):
    conf = get_client_config_raw(name)
    m = re.search(r'Address\s*=\s*10\.66\.66\.(\d+)', conf)
    return f"10.66.66.{m.group(1)}/32" if m else None


def get_client_info(name):
    conf = get_client_config_raw(name)
    m = re.search(r'Address\s*=\s*([\d.]+)', conf)
    ip = m.group(1) if m else "unknown"
    # Configs are plain WireGuard (no Jc/S/H obfuscation) so the Amnezia app
    # detects them as "WireGuard", which is what the wg0 server accepts.
    proto = "AmneziaWG" if re.search(r'^\s*Jc\s*=', conf, re.M) else "WireGuard"
    disabled = is_client_disabled(name)
    return {"name": name, "ip": ip, "proto": proto, "disabled": disabled}


def get_peer_transfer():
    """Read per-peer rx/tx counters from `amneziawg show wg0 dump`.

    Returns {pubkey: {"rx": int, "tx": int}}. Transfer columns are per-peer
    and cumulative since the interface started, so unlike sysfs interface
    totals they are correct per client.
    """
    stats = {}
    try:
        output = run_cmd("amneziawg show wg0 dump", timeout=10)
        lines = output.strip().split("\n")
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) < 8:
                continue
            try:
                handshake = int(parts[4])
                rx = int(parts[5])
                tx = int(parts[6])
            except ValueError:
                continue
            stats[parts[0]] = {"rx": rx, "tx": tx, "handshake": handshake}
    except Exception:
        pass
    return stats


def get_online_clients():
    """Names of clients whose latest handshake is recent enough."""
    transfer = get_peer_transfer()
    now = time.time()
    online = set()
    for name in get_clients():
        peer = transfer.get(get_client_pubkey(name))
        if peer and peer["handshake"] and now - peer["handshake"] < ONLINE_TIMEOUT:
            online.add(name)
    return online


def format_bytes(b):
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b / 1024:.1f} KB"
    elif b < 1024 * 1024 * 1024:
        return f"{b / (1024 * 1024):.1f} MB"
    else:
        return f"{b / (1024 * 1024 * 1024):.2f} GB"


_last_cpu = None


def get_cpu_usage():
    global _last_cpu
    try:
        with open("/proc/stat") as f:
            line = f.readline()
        parts = line.split()
        idle = int(parts[4])
        total = sum(int(x) for x in parts[1:])
        if _last_cpu is None:
            _last_cpu = (idle, total)
            return 0.0
        d_idle = idle - _last_cpu[0]
        d_total = total - _last_cpu[1]
        _last_cpu = (idle, total)
        if d_total == 0:
            return 0.0
        return round((1 - d_idle / d_total) * 100, 1)
    except:
        return 0.0


def get_load_average():
    try:
        load = os.getloadavg()
        return [round(x, 2) for x in load]
    except:
        return [0.0, 0.0, 0.0]


def get_memory_info():
    try:
        info = {}
        with open("/proc/meminfo") as f:
            for line in f:
                parts = line.split()
                if parts[0] == "MemTotal:":
                    info["total_kb"] = int(parts[1])
                elif parts[0] == "MemAvailable:":
                    info["avail_kb"] = int(parts[1])
        total = info.get("total_kb", 1)
        avail = info.get("avail_kb", total)
        used = total - avail
        return {
            "total_mb": round(total / 1024),
            "used_mb": round(used / 1024),
            "percent": round(used / total * 100, 1)
        }
    except:
        return {"total_mb": 0, "used_mb": 0, "percent": 0.0}


_net_last = None


def get_network_throughput():
    global _net_last
    try:
        rx = int(open("/sys/class/net/wg0/statistics/rx_bytes").read().strip())
        tx = int(open("/sys/class/net/wg0/statistics/tx_bytes").read().strip())
        now = time.time()
        if _net_last is None:
            _net_last = (rx, tx, now)
            return {"rx_speed": 0, "tx_speed": 0}
        prev_rx, prev_tx, prev_t = _net_last
        dt = now - prev_t
        _net_last = (rx, tx, now)
        if dt <= 0:
            return {"rx_speed": 0, "tx_speed": 0}
        rx_speed = max(0, int((rx - prev_rx) / dt))
        tx_speed = max(0, int((tx - prev_tx) / dt))
        return {"rx_speed": rx_speed, "tx_speed": tx_speed}
    except:
        return {"rx_speed": 0, "tx_speed": 0}


def read_sysfs(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return None


def get_battery():
    base = "/sys/class/power_supply/battery"
    cap = read_sysfs(f"{base}/capacity")
    temp = read_sysfs(f"{base}/temp")  # tenths of a degree
    status = read_sysfs(f"{base}/status")
    return {
        "percent": int(cap) if cap and cap.isdigit() else None,
        "status": status or "?",
        "temp": round(int(temp) / 10, 1) if temp and temp.lstrip("-").isdigit() else None,
    }


def get_cpu_temp():
    """Hottest CPU thermal zone, in degrees C."""
    temps = []
    base = "/sys/class/thermal"
    try:
        zones = os.listdir(base)
    except OSError:
        return None
    for z in zones:
        if not z.startswith("thermal_zone"):
            continue
        ztype = read_sysfs(f"{base}/{z}/type") or ""
        if ztype.startswith("cpu"):
            t = read_sysfs(f"{base}/{z}/temp")
            if t and t.lstrip("-").isdigit():
                temps.append(int(t) / 1000)
    return round(max(temps), 1) if temps else None


def get_uptime():
    try:
        with open("/proc/uptime") as f:
            seconds = float(f.read().split()[0])
        days = int(seconds // 86400)
        hours = int((seconds % 86400) // 3600)
        mins = int((seconds % 3600) // 60)
        parts = []
        if days > 0:
            parts.append(f"{days}d")
        if hours > 0:
            parts.append(f"{hours}h")
        parts.append(f"{mins}m")
        return " ".join(parts)
    except:
        return "?"


def load_monthly_stats():
    now = time.localtime()
    month_key = f"{now.tm_year}-{now.tm_mon:02d}"
    if os.path.exists(STATS_FILE):
        with open(STATS_FILE) as f:
            data = json.load(f)
        if data.get("month") == month_key:
            return data
        # new month: keep the snapshot so traffic since the last update
        # is counted in the new month instead of being lost
        return {"month": month_key, "clients": {},
                "last_snapshot": data.get("last_snapshot", {})}
    return {"month": month_key, "clients": {}, "last_snapshot": {}}


def save_monthly_stats(data):
    os.makedirs(os.path.dirname(STATS_FILE), exist_ok=True)
    with open(STATS_FILE, "w") as f:
        json.dump(data, f)


_stats_lock = threading.Lock()


def counter_delta(cur, prev):
    """Traffic since the previous snapshot. A counter lower than before means
    wg0 was restarted and counters started from zero, so all of it is new."""
    if prev is None:
        return cur
    return cur - prev if cur >= prev else cur


def update_monthly_stats():
    """Add current transfer delta to monthly totals."""
    with _stats_lock:
        return _update_monthly_stats()


def _update_monthly_stats():
    monthly = load_monthly_stats()
    current = get_peer_transfer()
    old_snapshot = monthly.get("last_snapshot", {})

    for name in get_clients():
        pubkey = get_client_pubkey(name)
        if not pubkey or pubkey not in current:
            continue
        cur = current[pubkey]
        prev = old_snapshot.get(pubkey) or {}
        delta_rx = counter_delta(cur["rx"], prev.get("rx"))
        delta_tx = counter_delta(cur["tx"], prev.get("tx"))
        if name not in monthly["clients"]:
            monthly["clients"][name] = {"rx": 0, "tx": 0}
        monthly["clients"][name]["rx"] += delta_rx
        monthly["clients"][name]["tx"] += delta_tx

    monthly["last_snapshot"] = {k: {"rx": v["rx"], "tx": v["tx"]} for k, v in current.items()}
    save_monthly_stats(monthly)
    return monthly


def refresh_monthly_stats():
    return update_monthly_stats()


def stats_loop():
    while True:
        try:
            update_monthly_stats()
        except Exception as e:
            print(f"traffic stats update failed: {e}", flush=True)
        time.sleep(STATS_INTERVAL)


def used_client_ips():
    """Last octets of 10.66.66.x addresses taken by panel clients (disabled
    ones included), peers in the server config and peers on the live
    interface. .1 is the server itself."""
    used = {1}
    octet = re.compile(r'\b10\.66\.66\.(\d+)\b')
    for c in get_clients():
        m = re.search(r'Address\s*=\s*10\.66\.66\.(\d+)', get_client_config_raw(c))
        if m:
            used.add(int(m.group(1)))
    try:
        with open(SERVER_CONF) as f:
            for line in f:
                if re.match(r'\s*AllowedIPs\s*=', line):
                    used.update(int(x) for x in octet.findall(line))
    except OSError:
        pass
    for line in run_cmd("amneziawg show wg0 allowed-ips").splitlines():
        used.update(int(x) for x in octet.findall(line))
    return used


def gen_keys():
    """Return (privkey, pubkey, psk) or raise RuntimeError."""
    def awg(*args, input=None):
        r = subprocess.run(["amneziawg", *args], capture_output=True,
                           text=True, input=input, timeout=20)
        out = r.stdout.strip()
        if r.returncode != 0 or not out:
            raise RuntimeError(f"amneziawg {args[0]} failed: {r.stderr.strip()}")
        return out
    privkey = awg("genkey")
    return privkey, awg("pubkey", input=privkey), awg("genpsk")


def add_client(name):
    endpoint = load_settings().get("endpoint", "").strip()
    if not endpoint:
        return {"error": "Сначала укажите Endpoint в настройках"}

    free = [i for i in range(2, 255) if i not in used_client_ips()]
    if not free:
        return {"error": "Нет свободных адресов в 10.66.66.0/24"}
    next_ip = free[0]

    try:
        privkey, pubkey, psk = gen_keys()
    except (RuntimeError, OSError, subprocess.TimeoutExpired) as e:
        return {"error": str(e)}

    os.makedirs(CLIENTS_DIR, exist_ok=True)
    client_dir = os.path.join(CLIENTS_DIR, name)
    os.makedirs(client_dir, exist_ok=True)

    with open(os.path.join(client_dir, "private.key"), "w") as f:
        f.write(privkey)
    with open(os.path.join(client_dir, "public.key"), "w") as f:
        f.write(pubkey)
    with open(os.path.join(client_dir, "preshared.key"), "w") as f:
        f.write(psk)

    psk_path = os.path.join(client_dir, "preshared.key")
    code, err = run_cmd_status(
        f"amneziawg set wg0 peer {pubkey} preshared-key {psk_path} allowed-ips 10.66.66.{next_ip}/32")
    if code != 0:
        shutil.rmtree(client_dir)
        return {"error": f"Failed to add peer to wg0 (code {code}): {err}"}
    try:
        server_conf_add_peer(name, pubkey, psk, f"10.66.66.{next_ip}/32")
    except OSError as e:
        run_cmd(f"amneziawg set wg0 peer {pubkey} remove")
        shutil.rmtree(client_dir)
        return {"error": f"Failed to save peer to {SERVER_CONF}: {e}"}

    server_pubkey = get_server_pubkey()
    config = f"""[Interface]
PrivateKey = {privkey}
Address = 10.66.66.{next_ip}/24
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = {server_pubkey}
PresharedKey = {psk}
Endpoint = {endpoint}
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
"""
    with open(os.path.join(client_dir, "client.conf"), "w") as f:
        f.write(config)

    return {"name": name, "ip": f"10.66.66.{next_ip}", "pubkey": pubkey}


def remove_client(name):
    if not valid_name(name):
        return {"error": "Invalid name"}
    client_dir = os.path.join(CLIENTS_DIR, name)
    if not os.path.isdir(client_dir):
        return {"error": "Not found"}
    pubkey = get_client_pubkey(name)
    if pubkey:
        if not is_client_disabled(name):
            code, err = run_cmd_status(f"amneziawg set wg0 peer {pubkey} remove")
            if code != 0:
                return {"error": f"Failed to remove peer from wg0 (code {code}): {err}"}
        try:
            server_conf_remove_peer(pubkey)
        except OSError as e:
            return {"error": f"Failed to update {SERVER_CONF}: {e}"}
    shutil.rmtree(client_dir)
    return {"ok": True}


def toggle_client(name):
    """Toggle client enabled/disabled."""
    if not valid_name(name):
        return {"error": "Invalid name"}
    client_dir = os.path.join(CLIENTS_DIR, name)
    if not os.path.exists(client_dir):
        return None

    disabled_path = os.path.join(client_dir, "disabled")
    pubkey = get_client_pubkey(name)

    if os.path.exists(disabled_path):
        # Enable: re-add peer
        if pubkey:
            psk_path = os.path.join(client_dir, "preshared.key")
            allowed_ip = get_client_allowed_ip(name)
            if allowed_ip:
                code, err = run_cmd_status(
                    f"amneziawg set wg0 peer {pubkey} preshared-key {psk_path} allowed-ips {allowed_ip}")
                if code != 0:
                    return {"error": f"Failed to re-add peer (code {code}): {err}"}
                try:
                    server_conf_add_peer(name, pubkey, read_client_psk(name), allowed_ip)
                except OSError as e:
                    return {"error": f"Failed to save peer to {SERVER_CONF}: {e}"}
        os.unlink(disabled_path)
        return {"disabled": False}
    else:
        # Disable: remove peer
        if pubkey:
            code, err = run_cmd_status(f"amneziawg set wg0 peer {pubkey} remove")
            if code != 0:
                return {"error": f"Failed to remove peer (code {code}): {err}"}
            try:
                server_conf_remove_peer(pubkey)
            except OSError as e:
                return {"error": f"Failed to update {SERVER_CONF}: {e}"}
        with open(disabled_path, "w") as f:
            f.write("disabled")
        return {"disabled": True}


def update_endpoint_all(endpoint):
    for name in get_clients():
        path = os.path.join(CLIENTS_DIR, name, "client.conf")
        if os.path.exists(path):
            with open(path) as f:
                content = f.read()
            content = re.sub(r'Endpoint\s*=\s*\S+', f'Endpoint = {endpoint}', content)
            with open(path, "w") as f:
                f.write(content)


def get_public_ip():
    try:
        r = subprocess.run(["wget", "-q", "-O", "-", "http://ifconfig.me/ip"],
                           capture_output=True, text=True, timeout=10)
        if r.stdout.strip():
            return r.stdout.strip()
    except:
        pass
    return None


def update_duckdns():
    ip = get_public_ip()
    if not ip:
        return {"ok": False, "error": "Cannot get public IP"}
    run_cmd(f"sudo {DUCKDNS_SCRIPT}")
    return {"ok": True, "ip": ip}


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="ru">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AmneziaWG Panel</title>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:linear-gradient(135deg,#1e293b 0%,#0f172a 100%);border-bottom:1px solid #334155;padding:20px 30px;display:flex;align-items:center;gap:15px}
.header h1{font-size:24px;font-weight:600}
.header .badge{background:#22c55e;color:#000;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:600}
.container{max-width:900px;margin:30px auto;padding:0 20px}
.card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;margin-bottom:20px}
.card h2{font-size:18px;margin-bottom:16px;color:#94a3b8}
.status-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.status-item{background:#0f172a;padding:12px;border-radius:8px}
.status-item .label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.status-item .value{font-size:16px;font-weight:600;margin-top:4px;font-family:monospace}
.btn{padding:10px 20px;border:none;border-radius:8px;cursor:pointer;font-size:14px;font-weight:500;transition:all .2s}
.btn-primary{background:#3b82f6;color:#fff}.btn-primary:hover{background:#2563eb}
.btn-danger{background:#ef4444;color:#fff}.btn-danger:hover{background:#dc2626}
.btn-success{background:#22c55e;color:#000}.btn-success:hover{background:#16a34a}
.btn-warning{background:#f59e0b;color:#000}.btn-warning:hover{background:#d97706}
.btn-sm{padding:6px 12px;font-size:12px}
.client-list{list-style:none}
.client-item{background:#0f172a;border:1px solid #334155;border-radius:8px;padding:16px;margin-bottom:10px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.client-item.disabled{opacity:.5;border-color:#ef4444}
.client-info{flex:1;min-width:150px}
.client-name{font-weight:600;font-size:16px;display:flex;align-items:center;gap:8px}
.status-dot{font-size:11px;font-weight:500;padding:2px 8px;border-radius:10px;background:#334155;color:#94a3b8}
.status-dot.online{background:#14532d;color:#4ade80}
.client-ip{color:#64748b;font-family:monospace;font-size:13px;margin-top:2px}
.client-obf{color:#3b82f6;font-family:monospace;font-size:11px;margin-top:2px}
.client-traffic{color:#22c55e;font-family:monospace;font-size:11px;margin-top:2px}
.client-actions{display:flex;gap:6px;flex-wrap:wrap}
.input-group{display:flex;gap:10px;margin-bottom:16px;flex-wrap:wrap}
.input-group input{flex:1;min-width:150px;padding:10px 14px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px}
.input-group input:focus{outline:none;border-color:#3b82f6}
.config-modal{display:none;position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.85);z-index:100;align-items:center;justify-content:center}
.config-modal.active{display:flex}
.config-content{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:24px;max-width:600px;width:90%;max-height:85vh;overflow-y:auto}
.config-content pre{background:#0f172a;padding:16px;border-radius:8px;font-size:12px;overflow-x:auto;white-space:pre-wrap;word-break:break-all;color:#e2e8f0}
.config-content h3{margin-bottom:12px}
.qr-box{background:#fff;padding:16px;border-radius:12px;display:inline-block;margin:16px 0}
.copy-btn{background:#475569;color:#fff;padding:6px 12px;border:none;border-radius:6px;cursor:pointer;font-size:12px}
.copy-btn:hover{background:#64748b}
.toast{position:fixed;bottom:20px;right:20px;background:#22c55e;color:#000;padding:12px 20px;border-radius:8px;font-weight:500;display:none;z-index:200}
.empty-state{text-align:center;padding:40px;color:#64748b}
.settings-row{display:flex;gap:10px;align-items:center;margin-bottom:10px}
.settings-row label{min-width:100px;color:#94a3b8;font-size:14px}
.settings-row input{flex:1;padding:8px 12px;background:#0f172a;border:1px solid #334155;border-radius:8px;color:#e2e8f0;font-size:14px}
.modal-btns{display:flex;gap:10px;margin-top:12px;flex-wrap:wrap}
.progress-bar{height:6px;background:#334155;border-radius:3px;margin-top:6px;overflow:hidden}
.progress-bar .fill{height:100%;border-radius:3px;transition:width .5s ease}
.progress-bar .fill.green{background:#22c55e}
.progress-bar .fill.yellow{background:#f59e0b}
.progress-bar .fill.red{background:#ef4444}
.sys-label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
.sys-value{font-size:15px;font-weight:600;margin-top:3px;font-family:monospace}
.sys-sub{font-size:11px;color:#64748b;font-family:monospace;margin-top:1px}
</style>
</head>
<body>

<div class="header">
  <h1>AmneziaWG</h1>
  <span class="badge">ACTIVE</span>
</div>

<div class="container">
  <div class="card">
    <h2>Server Status</h2>
    <div class="status-grid">
      <div class="status-item">
        <div class="label">Interface</div>
        <div class="value">wg0</div>
      </div>
      <div class="status-item">
        <div class="label">Endpoint</div>
        <div class="value">ENDPOINT_DISPLAY</div>
      </div>
      <div class="status-item">
        <div class="label">Peers</div>
        <div class="value">PEER_COUNT</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>System Monitor</h2>
    <div class="status-grid">
      <div class="status-item">
        <div class="sys-label">CPU</div>
        <div class="sys-value" id="sysCpu">--%</div>
        <div class="progress-bar"><div class="fill green" id="cpuBar" style="width:0%"></div></div>
      </div>
      <div class="status-item">
        <div class="sys-label">Load Avg</div>
        <div class="sys-value" id="sysLoad">--</div>
        <div class="sys-sub">1 / 5 / 15 min</div>
      </div>
      <div class="status-item">
        <div class="sys-label">Memory</div>
        <div class="sys-value" id="sysMem">--</div>
        <div class="progress-bar"><div class="fill green" id="memBar" style="width:0%"></div></div>
        <div class="sys-sub" id="sysMemDetail">--</div>
      </div>
      <div class="status-item">
        <div class="sys-label">Net ↓ wg0</div>
        <div class="sys-value" id="sysNetRx">0 B/s</div>
      </div>
      <div class="status-item">
        <div class="sys-label">Net ↑ wg0</div>
        <div class="sys-value" id="sysNetTx">0 B/s</div>
      </div>
      <div class="status-item">
        <div class="sys-label">Battery</div>
        <div class="sys-value" id="sysBat">--</div>
        <div class="progress-bar"><div class="fill green" id="batBar" style="width:0%"></div></div>
        <div class="sys-sub" id="sysBatDetail">--</div>
      </div>
      <div class="status-item">
        <div class="sys-label">CPU Temp</div>
        <div class="sys-value" id="sysCpuTemp">--</div>
      </div>
      <div class="status-item">
        <div class="sys-label">Uptime</div>
        <div class="sys-value" id="sysUptime">--</div>
      </div>
    </div>
  </div>

  <div class="card">
    <h2>Settings</h2>
    <div class="settings-row">
      <label>Endpoint:</label>
      <input type="text" id="endpointInput" placeholder="domain:port or ip:port" value="ENDPOINT_VAL">
      <button class="btn btn-primary btn-sm" onclick="saveEndpoint()">Save</button>
    </div>
    <div class="settings-row" style="margin-top:12px;border-top:1px solid #334155;padding-top:12px">
      <label>DuckDNS:</label>
      <div style="flex:1;font-family:monospace;font-size:13px;color:#64748b" id="duckStatus">IP: loading...</div>
      <button class="btn btn-success btn-sm" onclick="updateDuckDNS()" id="duckBtn">Update IP</button>
    </div>
  </div>

  <div class="card">
    <h2>Clients</h2>
    <div class="input-group">
      <input type="text" id="clientName" placeholder="Client name...">
      <button class="btn btn-primary" onclick="addClient()">Add Client</button>
    </div>
    <ul class="client-list" id="clientList">
      CLIENT_LIST_HTML
    </ul>
  </div>
</div>

<div class="config-modal" id="configModal">
  <div class="config-content">
    <h3 id="modalTitle">Client Config</h3>
    <div class="qr-box" id="modalQR"></div>
    <pre id="modalConfig"></pre>
    <div class="modal-btns">
      <button class="btn btn-primary" onclick="copyConfig()">Copy</button>
      <button class="copy-btn" onclick="downloadConfig()">Download .conf</button>
      <button class="copy-btn" onclick="closeModal()">Close</button>
    </div>
  </div>
</div>

<div class="toast" id="toast"></div>

<script>
function addClient() {
  const name = document.getElementById('clientName').value.trim();
  if (!name) { alert('Enter a name'); return; }
  fetch('/api/add?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(data => {
      if (data.error) { alert(data.error); return; }
      window.location.href = window.location.href;
    });
}

function removeClient(name) {
  if (!confirm('Delete ' + name + '?')) return;
  fetch('/api/remove?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(data => {
      if (data.error) { alert(data.error); return; }
      window.location.href = window.location.href;
    });
}

function toggleClient(name) {
  const btn = event.target;
  btn.disabled = true;
  btn.textContent = '...';
  fetch('/api/toggle?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(data => {
      if (data.error) { alert(data.error); btn.disabled = false; return; }
      window.location.href = window.location.href;
    })
    .catch(() => { btn.disabled = false; btn.textContent = 'Toggle'; });
}

function showConfig(name) {
  fetch('/api/config?name=' + encodeURIComponent(name))
    .then(r => r.json())
    .then(data => {
      document.getElementById('modalTitle').textContent = name;
      document.getElementById('modalConfig').textContent = data.config;
      document.getElementById('modalQR').innerHTML = data.qr;
      document.getElementById('configModal').classList.add('active');
    });
}

function copyConfig() {
  navigator.clipboard.writeText(document.getElementById('modalConfig').textContent)
    .then(() => showToast('Copied!'));
}

function downloadConfig() {
  const text = document.getElementById('modalConfig').textContent;
  const name = document.getElementById('modalTitle').textContent;
  const blob = new Blob([text], {type:'text/plain'});
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = name + '.conf';
  a.click();
}

function closeModal() {
  document.getElementById('configModal').classList.remove('active');
}

function saveEndpoint() {
  const val = document.getElementById('endpointInput').value.trim();
  if (!val) { alert('Enter endpoint'); return; }
  fetch('/api/settings', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({endpoint: val})
  }).then(r => r.json()).then(d => {
    showToast('Endpoint saved: ' + val);
  });
}

function updateDuckDNS() {
  const btn = document.getElementById('duckBtn');
  const status = document.getElementById('duckStatus');
  btn.disabled = true;
  btn.textContent = 'Updating...';
  status.textContent = 'Updating...';
  fetch('/api/duckdns')
    .then(r => r.json())
    .then(data => {
      btn.disabled = false;
      btn.textContent = 'Update IP';
      if (data.ok) {
        status.textContent = 'IP: ' + data.ip;
        showToast('DuckDNS updated: ' + data.ip);
      } else {
        status.textContent = 'Error';
        showToast('DuckDNS error');
      }
    })
    .catch(() => { btn.disabled = false; btn.textContent = 'Update IP'; });
}

function loadDuckStatus() {
  fetch('/api/duckdns').then(r => r.json()).then(data => {
    if (data.ok) document.getElementById('duckStatus').textContent = 'IP: ' + data.ip;
  });
}

function pollTraffic() {
  fetch('/api/traffic').then(r => r.json()).then(data => {
    for (const [name, t] of Object.entries(data)) {
      const st = document.querySelector(`.status-dot[data-status="${name}"]`);
      if (st) {
        st.classList.toggle('online', t.online);
        st.textContent = t.online ? 'подключён' : 'отключён';
      }
      const el = document.querySelector(`.client-traffic[data-client="${name}"]`);
      if (!el) continue;
      el.innerHTML = '&darr; ' + formatBytesJS(t.tx) + ' &nbsp;&nbsp; &uarr; ' + formatBytesJS(t.rx);
    }
  }).catch(() => {});
}

function formatBytesJS(b) {
  if (b < 1024) return b + ' B';
  if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1073741824) return (b / 1048576).toFixed(1) + ' MB';
  return (b / 1073741824).toFixed(2) + ' GB';
}

function formatSpeedJS(bps) {
  if (bps < 1024) return bps + ' B/s';
  if (bps < 1048576) return (bps / 1024).toFixed(1) + ' KB/s';
  return (bps / 1048576).toFixed(1) + ' MB/s';
}

function setBarColor(el, pct) {
  el.className = 'fill ' + (pct >= 85 ? 'red' : pct >= 60 ? 'yellow' : 'green');
}

function pollSystem() {
  fetch('/api/system').then(r => r.json()).then(d => {
    document.getElementById('sysCpu').textContent = d.cpu_percent + '%';
    const cpuBar = document.getElementById('cpuBar');
    cpuBar.style.width = d.cpu_percent + '%';
    setBarColor(cpuBar, d.cpu_percent);

    document.getElementById('sysLoad').textContent = d.load[0] + ' / ' + d.load[1] + ' / ' + d.load[2];

    document.getElementById('sysMem').textContent = d.mem_percent + '%';
    const memBar = document.getElementById('memBar');
    memBar.style.width = d.mem_percent + '%';
    setBarColor(memBar, d.mem_percent);
    document.getElementById('sysMemDetail').textContent = d.mem_used_mb + ' / ' + d.mem_total_mb + ' MB';

    document.getElementById('sysNetRx').textContent = formatSpeedJS(d.net_rx_speed);
    document.getElementById('sysNetTx').textContent = formatSpeedJS(d.net_tx_speed);
    document.getElementById('sysUptime').textContent = d.uptime;

    const bat = d.battery;
    document.getElementById('sysBat').textContent = bat.percent == null ? '--' : bat.percent + '%';
    const batBar = document.getElementById('batBar');
    batBar.style.width = (bat.percent || 0) + '%';
    batBar.className = 'fill ' + (bat.percent <= 15 ? 'red' : bat.percent <= 40 ? 'yellow' : 'green');
    document.getElementById('sysBatDetail').textContent =
      bat.status + (bat.temp == null ? '' : ' · ' + bat.temp + ' °C');

    const ct = document.getElementById('sysCpuTemp');
    ct.textContent = d.cpu_temp == null ? '--' : d.cpu_temp + ' °C';
    ct.style.color = d.cpu_temp >= 70 ? '#ef4444' : d.cpu_temp >= 55 ? '#f59e0b' : '';
  }).catch(() => {});
}

window.addEventListener('load', () => {
  loadDuckStatus();
  pollSystem();
  pollTraffic();
  setInterval(pollTraffic, 10000);
  setInterval(pollSystem, 3000);
});
</script>
</body>
</html>"""


class PanelHandler(http.server.BaseHTTPRequestHandler):
    timeout = 300

    def log_message(self, format, *args):
        pass

    def _query_param(self, name, default=""):
        return urllib.parse.parse_qs(
            urllib.parse.urlsplit(self.path).query).get(name, [default])[0]

    def do_GET(self):
        if self.path == '/' or self.path == '/index.html':
            self.serve_main()
        elif self.path.startswith('/api/add'):
            self.handle_add()
        elif self.path.startswith('/api/remove'):
            self.handle_remove()
        elif self.path.startswith('/api/config'):
            self.handle_config()
        elif self.path.startswith('/api/download'):
            self.handle_download()
        elif self.path.startswith('/api/duckdns'):
            self.handle_duckdns()
        elif self.path.startswith('/api/toggle'):
            self.handle_toggle()
        elif self.path.startswith('/api/traffic'):
            self.handle_traffic()
        elif self.path.startswith('/api/system'):
            self.handle_system()
        else:
            self.send_error(404)

    def do_POST(self):
        if self.path.startswith('/api/settings'):
            self.handle_settings()
        else:
            self.send_error(404)

    def serve_main(self):
        settings = load_settings()
        clients = get_clients()
        monthly = refresh_monthly_stats()
        monthly_clients = monthly.get("clients", {})
        online = get_online_clients()
        client_html = ""
        for c in sorted(clients):
            info = get_client_info(c)
            traffic = monthly_clients.get(c, {"rx": 0, "tx": 0})
            rx_str = format_bytes(traffic["rx"])
            tx_str = format_bytes(traffic["tx"])
            disabled_class = ' disabled' if info['disabled'] else ''
            toggle_label = 'Enable' if info['disabled'] else 'Disable'
            toggle_btn_class = 'btn-success' if info['disabled'] else 'btn-warning'
            client_html += f"""
            <li class="client-item{disabled_class}">
              <div class="client-info">
                <div class="client-name">{c}<span class="status-dot{' online' if c in online else ''}" data-status="{c}">{'подключён' if c in online else 'отключён'}</span></div>
                <div class="client-ip">{info['ip']}</div>
                <div class="client-obf">{info['proto']}</div>
                <div class="client-traffic" data-client="{c}">&darr; {tx_str} &nbsp;&nbsp; &uarr; {rx_str}</div>
              </div>
              <div class="client-actions">
                <button class="btn btn-success btn-sm" onclick="showConfig('{c}')">Config</button>
                <button class="btn {toggle_btn_class} btn-sm" onclick="toggleClient('{c}')">{toggle_label}</button>
                <button class="btn btn-danger btn-sm" onclick="removeClient('{c}')">Delete</button>
              </div>
            </li>"""
        if not clients:
            client_html = '<div class="empty-state">No clients yet</div>'

        html = HTML_TEMPLATE
        html = html.replace("ENDPOINT_DISPLAY", settings.get("endpoint") or "не задан")
        html = html.replace("ENDPOINT_VAL", settings.get("endpoint", ""))
        html = html.replace("CLIENT_LIST_HTML", client_html)
        html = html.replace("PEER_COUNT", str(len(clients)))

        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(html.encode())
        self.close_connection = True

    def handle_add(self):
        name = self._query_param("name")
        if not name or not re.match(r'^[a-zA-Z0-9_-]+$', name):
            self.json_response({"error": "Invalid name"})
            return
        if name in get_clients():
            self.json_response({"error": "Client already exists"})
            return
        result = add_client(name)
        self.json_response(result)

    def handle_remove(self):
        self.json_response(remove_client(self._query_param("name")))

    def handle_toggle(self):
        name = self._query_param("name")
        result = toggle_client(name)
        if result is None:
            self.json_response({"error": "Client not found"})
        else:
            self.json_response(result)

    def handle_traffic(self):
        monthly = refresh_monthly_stats()
        online = get_online_clients()
        result = {}
        for c in get_clients():
            raw = monthly.get("clients", {}).get(c)
            result[c] = {"rx": raw["rx"], "tx": raw["tx"]} if raw else {"rx": 0, "tx": 0}
            result[c]["online"] = c in online
        self.json_response(result)

    def handle_system(self):
        net = get_network_throughput()
        mem = get_memory_info()
        self.json_response({
            "cpu_percent": get_cpu_usage(),
            "load": get_load_average(),
            "mem_total_mb": mem["total_mb"],
            "mem_used_mb": mem["used_mb"],
            "mem_percent": mem["percent"],
            "net_rx_speed": net["rx_speed"],
            "net_tx_speed": net["tx_speed"],
            "uptime": get_uptime(),
            "battery": get_battery(),
            "cpu_temp": get_cpu_temp()
        })

    def handle_config(self):
        name = self._query_param("name")
        config = get_client_config_raw(name)
        qr = generate_qr_svg(config) if config else ""
        self.json_response({"config": config, "qr": qr})

    def handle_download(self):
        name = self._query_param("name")
        config = get_client_config_raw(name)
        if config:
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Disposition", f'attachment; filename="{name}.conf"')
            self.end_headers()
            self.wfile.write(config.encode())
        else:
            self.send_error(404)

    def handle_duckdns(self):
        result = update_duckdns()
        self.json_response(result)

    def handle_settings(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length)
        try:
            data = json.loads(body)
        except:
            self.json_response({"error": "Invalid JSON"})
            return
        settings = load_settings()
        if "endpoint" in data:
            settings["endpoint"] = data["endpoint"]
            update_endpoint_all(data["endpoint"])
        save_settings(settings)
        self.json_response({"ok": True, "settings": settings})

    def json_response(self, data):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())
        self.close_connection = True


if __name__ == "__main__":
    os.makedirs(CLIENTS_DIR, exist_ok=True)
    threading.Thread(target=stats_loop, daemon=True).start()
    server = http.server.ThreadingHTTPServer(("0.0.0.0", WEB_PORT), PanelHandler)
    print(f"AmneziaWG Panel running on http://0.0.0.0:{WEB_PORT}")
    server.serve_forever()
