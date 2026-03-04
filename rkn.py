#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
╔════════════════════════════════════════════════════════════════════════════════════╗
║                    DB CLEANER PRO - Распределенная система проверки прокси         ║
║                           Версия: 3.2.0 (Автовосстановление)                       ║
╚════════════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import socket
import urllib.parse
import urllib.request
import subprocess
import hashlib
import signal
import re
import threading
import queue
import random
import html
import ipaddress
import ssl
import struct
import tempfile
import shutil
import platform
import stat
import logging
import math
import argparse
import asyncio
import aiosqlite
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager, asynccontextmanager
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse
from typing import Dict, List, Optional, Tuple, Any, Set, Union
from pathlib import Path
import traceback

# ПОДАВЛЕНИЕ ПРЕДУПРЕЖДЕНИЙ URLLIB3
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except:
    pass

try:
    import requests
    REQUESTS_AVAILABLE = True
    from requests.packages.urllib3.exceptions import InsecureRequestWarning
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    REQUESTS_AVAILABLE = False
    print("⚠️  Для полной функциональности установите requests: pip install requests")

# =============================================================================
# ЧАСТЬ 1: КОНСТАНТЫ И НАСТРОЙКИ
# =============================================================================

# Файлы баз данных
MAIN_DB_FILE = "proxies.db"
CHECK_DB_FILE = "check_results.db"
WHITELIST_FILE = "whitelist.txt"
VPN_JSON_DIR = "vpn/json"

# Настройки координатора
COORDINATOR_HOST = '0.0.0.0'
COORDINATOR_PORT = 8080
COORDINATOR_BIND_HOST = '0.0.0.0'
COORDINATOR_CONNECT_HOST = '127.0.0.1'

# Настройки блокировок
LOCK_TIMEOUT = 300
CLEANUP_INTERVAL = 60

# Настройки черного ящика
POLL_INTERVAL = 5
MAX_CONSECUTIVE_ERRORS = 5
RECONNECT_DELAY = 2
MAX_RECONNECT_ATTEMPTS = 10

# Настройки Xray
XRAY_PORT = 10808
XRAY_CONFIG_DIR = ".tmp_runtime"

# Константы из test.py
TCP_FREEZE_THRESHOLD = 20 * 1024
TEST_FILE_32KB = "https://speed.cloudflare.com/__down?bytes=32768"
TEST_FILE_64KB = "https://speed.cloudflare.com/__down?bytes=65536"
PACKET_SIZE_THRESHOLD = 411
MSS_TEST_RANGE = range(1300, 1450, 10)

# Тестовые ресурсы для проверки
DEFAULT_BLOCKED_RESOURCES = [
    "https://www.google.com/generate_204",
    "https://rutracker.org",
    "https://telegram.org/",
    "https://gemini.google.com/",
    "https://2ip.ru/",
    "https://www.youtube.com/",
    "https://speedtest.rt.ru/",
    "https://rutor.info",
    "https://kinozal.tv",
    "https://nnmclub.to",
    "https://t.me",
    "https://telegram.org"
]

# Контрольные URL для проверки базового соединения
CONTROL_URLS = [
    "https://www.google.com/generate_204",
    "https://connectivitycheck.gstatic.com/generate_204",
    "https://captive.apple.com",
    "https://detectportal.firefox.com/success.txt",
]

# Порог успешного обхода блокировок
THRESHOLD_PERCENT = 70

# Профили мобильных операторов
MOBILE_OPERATORS = {
    'MTS': {
        'latency': (55, 75),
        'jitter': 12,
        'packet_loss': 0.5,
        'burst_loss': 25,
        'bandwidth_down': 15000,
        'bandwidth_up': 5500,
        'mtu': 1420,
        'description': 'МТС - агрессивное DPI, проблемы с Vision, MTU 1420'
    },
    'MEGAFON': {
        'latency': (35, 55),
        'jitter': 10,
        'packet_loss': 0.1,
        'burst_loss': 20,
        'bandwidth_down': 20000,
        'bandwidth_up': 7100,
        'mtu': 1440,
        'description': 'МегаФон - высокие скорости, жесткий NAT, MTU 1440'
    },
    'TELE2': {
        'latency': (45, 65),
        'jitter': 15,
        'packet_loss': 0.2,
        'burst_loss': 30,
        'bandwidth_down': 12000,
        'bandwidth_up': 5800,
        'mtu': 1400,
        'description': 'Tele2 - ограниченный MTU 1400, проблемы с фрагментацией'
    },
    'BEELINE': {
        'latency': (50, 70),
        'jitter': 18,
        'packet_loss': 0.4,
        'burst_loss': 28,
        'bandwidth_down': 13000,
        'bandwidth_up': 7200,
        'mtu': 1410,
        'description': 'Билайн - нестабильный пинг, частые реконнекты'
    },
    'LTE_GENERIC': {
        'latency': (50, 100),
        'jitter': 25,
        'packet_loss': 1.0,
        'burst_loss': 40,
        'bandwidth_down': 10000,
        'bandwidth_up': 5000,
        'mtu': 1350,
        'description': 'Generic LTE - худший сценарий'
    }
}

# Эмодзи стран
COUNTRY_FLAGS = {
    'RU': '🇷🇺', 'US': '🇺🇸', 'GB': '🇬🇧', 'DE': '🇩🇪', 'FR': '🇫🇷',
    'NL': '🇳🇱', 'CA': '🇨🇦', 'AU': '🇦🇺', 'JP': '🇯🇵', 'SG': '🇸🇬',
    'KR': '🇰🇷', 'CN': '🇨🇳', 'IN': '🇮🇳', 'BR': '🇧🇷', 'ZA': '🇿🇦',
    'IT': '🇮🇹', 'ES': '🇪🇸', 'CH': '🇨🇭', 'SE': '🇸🇪', 'NO': '🇳🇴',
    'FI': '🇫🇮', 'DK': '🇩🇰', 'PL': '🇵🇱', 'CZ': '🇨🇿', 'HU': '🇭🇺',
    'AT': '🇦🇹', 'BE': '🇧🇪', 'IE': '🇮🇪', 'PT': '🇵🇹', 'GR': '🇬🇷',
    'TR': '🇹🇷', 'IL': '🇮🇱', 'AE': '🇦🇪', 'SA': '🇸🇦', 'EG': '🇪🇬',
    'NG': '🇳🇬', 'KE': '🇰🇪', 'AR': '🇦🇷', 'CL': '🇨🇱', 'CO': '🇨🇴',
    'MX': '🇲🇽', 'NZ': '🇳🇿', 'ID': '🇮🇩', 'MY': '🇲🇾', 'TH': '🇹🇭',
    'VN': '🇻🇳', 'PH': '🇵🇭', 'PK': '🇵🇰', 'BD': '🇧🇩', 'LK': '🇱🇰',
    'UA': '🇺🇦', 'BY': '🇧🇾', 'KZ': '🇰🇿', 'GE': '🇬🇪', 'AM': '🇦🇲',
    'AZ': '🇦🇿', 'MD': '🇲🇩', 'LT': '🇱🇹', 'LV': '🇱🇻', 'EE': '🇪🇪',
    'IS': '🇮🇸', 'LU': '🇱🇺', 'MT': '🇲🇹', 'CY': '🇨🇾', 'BG': '🇧🇬',
    'RO': '🇷🇴', 'SK': '🇸🇰', 'SI': '🇸🇮', 'HR': '🇭🇷', 'BA': '🇧🇦',
    'RS': '🇷🇸', 'ME': '🇲🇪', 'AL': '🇦🇱', 'MK': '🇲🇰', 'XK': '🇽🇰',
    'LI': '🇱🇮', 'MC': '🇲🇨', 'SM': '🇸🇲', 'VA': '🇻🇦', 'AD': '🇦🇩'
}

# =============================================================================
# ЧАСТЬ 2: ЦВЕТА ДЛЯ ВЫВОДА
# =============================================================================

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'

GREEN = Colors.GREEN
RED = Colors.RED
YELLOW = Colors.YELLOW
BLUE = Colors.BLUE
CYAN = Colors.CYAN
MAGENTA = Colors.MAGENTA
WHITE = Colors.WHITE
RESET = Colors.RESET
BOLD = Colors.BOLD
DIM = Colors.DIM

# =============================================================================
# ЧАСТЬ 3: УТИЛИТЫ И ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def detect_encoding(file_path):
    encodings = ['utf-8', 'cp1251', 'latin-1', 'cp866', 'windows-1251', 'koi8-r']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding=enc) as f:
                f.read()
            return enc
        except UnicodeDecodeError:
            continue
    return 'utf-8'

def safe_open_file(file_path, mode='r'):
    if os.path.isdir(file_path):
        raise IsADirectoryError(f"Указан путь к директории, а не к файлу: {file_path}")
    
    if mode.startswith('r'):
        encoding = detect_encoding(file_path)
        return open(file_path, mode, encoding=encoding)
    else:
        return open(file_path, mode, encoding='utf-8')

def clean_url(url):
    url = url.strip()
    url = url.replace('\ufeff', '').replace('\u200b', '')
    url = url.replace('\n', '').replace('\r', '')
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    url = html.unescape(url)
    url = urllib.parse.unquote(url)
    return url

def is_port_in_use(port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.1)
            return s.connect_ex(('127.0.0.1', port)) == 0
    except:
        return False

def is_valid_uuid(uuid_str):
    if not uuid_str:
        return False
    pattern = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
    return bool(pattern.match(str(uuid_str)))

def is_valid_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except:
        return False

def init_temp_dir():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    preferred = os.path.join(script_dir, ".tmp_runtime")

    for candidate in (preferred, tempfile.mkdtemp(prefix="mkxray_")):
        try:
            os.makedirs(candidate, exist_ok=True)
            probe = os.path.join(candidate, ".write_probe")
            with open(probe, "w", encoding="utf-8") as f:
                f.write("ok")
            os.remove(probe)
            return candidate
        except Exception:
            continue

    return script_dir

TEMP_DIR = init_temp_dir()
OS_SYSTEM = platform.system().lower()

def kill_all_cores_manual():
    killed_count = 0
    target_names = ["xray.exe", "v2ray.exe", "xray", "v2ray"]
    
    print(f"{YELLOW}>> Принудительный сброс всех ядер Xray...{RESET}")
    
    if OS_SYSTEM == "windows":
        for name in target_names:
            try:
                subprocess.run(["taskkill", "/F", "/IM", name, "/T"],
                              capture_output=True, timeout=5)
            except:
                pass
    else:
        for name in target_names:
            try:
                subprocess.run(["pkill", "-f", name], capture_output=True, timeout=5)
            except:
                pass
    
    time.sleep(1.0)
    print(f"{GREEN}✓ СБРОС ЗАВЕРШЕН{RESET}")

# =============================================================================
# ЧАСТЬ 4: ПАРСЕРЫ ПРОТОКОЛОВ
# =============================================================================

def parse_vless(url):
    try:
        url = clean_url(url)
        if not url.startswith("vless://"):
            return None

        main_part = url
        tag = "vless"
        if '#' in url:
            parts = url.split('#', 1)
            main_part = parts[0]
            tag = urllib.parse.unquote(parts[1]).strip()
        else:
            match_host = re.search(r'vless://[^@]+@([^:]+):\d+', main_part)
            if match_host:
                tag = f"vless_{match_host.group(1)}"
            else:
                tag = "vless_unknown"

        match = re.search(r'vless://([^@]+)@([^:]+):(\d+)', main_part)
        if not match:
            return None

        uuid = match.group(1).strip()
        address = match.group(2).strip()
        port = int(match.group(3))

        params = {}
        if '?' in main_part:
            query = main_part.split('?', 1)[1]
            params = urllib.parse.parse_qs(query)

        def get_p(key, default=""):
            val = params.get(key, [default])
            return val[0].strip() if val else default

        net_type = get_p("type", "tcp").lower()
        flow = get_p("flow", "").lower()
        security = get_p("security", "none").lower()
        pbk = get_p("pbk", "")
        sid = get_p("sid", "")

        return {
            "protocol": "vless",
            "uuid": uuid,
            "host": address,
            "port": port,
            "encryption": get_p("encryption", "none"),
            "type": net_type,
            "security": security,
            "path": urllib.parse.unquote(get_p("path", "")),
            "host_header": get_p("host", ""),
            "sni": get_p("sni", ""),
            "fp": get_p("fp", ""),
            "alpn": get_p("alpn", ""),
            "serviceName": get_p("serviceName", ""),
            "mode": get_p("mode", ""),
            "pbk": pbk,
            "sid": sid,
            "flow": flow,
            "tag": tag,
            "name": tag,
            "raw": url
        }
    except Exception as e:
        return None

def parse_vmess(url):
    try:
        url = clean_url(url)
        if not url.startswith("vmess://"):
            return None

        if '@' in url:
            if '#' in url:
                main_part, tag = url.split('#', 1)
                tag = urllib.parse.unquote(tag).strip()
            else:
                main_part = url
                tag = "vmess"

            match = re.search(r'vmess://([^@]+)@([^:]+):(\d+)', main_part)
            if match:
                uuid = match.group(1).strip()
                address = match.group(2).strip()
                port = int(match.group(3))

                params = {}
                if '?' in main_part:
                    query = main_part.split('?', 1)[1]
                    params = urllib.parse.parse_qs(query)

                def get_p(key, default=""):
                    val = params.get(key, [default])
                    return val[0] if val else default

                try:
                    aid = int(get_p("aid", "0"))
                except:
                    aid = 0

                raw_path = get_p("path", "")
                final_path = urllib.parse.unquote(raw_path)

                net_type = get_p("type", "tcp").lower()

                return {
                    "protocol": "vmess",
                    "uuid": uuid,
                    "host": address,
                    "port": int(port),
                    "type": net_type,
                    "security": get_p("security", "none"),
                    "path": final_path,
                    "host_header": get_p("host", ""),
                    "sni": get_p("sni", ""),
                    "fp": get_p("fp", ""),
                    "alpn": get_p("alpn", ""),
                    "serviceName": get_p("serviceName", ""),
                    "aid": aid,
                    "scy": get_p("encryption", "auto"),
                    "tag": tag,
                    "name": tag,
                    "raw": url
                }

        content = url[8:]
        if '#' in content:
            b64, tag = content.rsplit('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            b64 = content
            tag = "vmess"

        missing_padding = len(b64) % 4
        if missing_padding:
            b64 += '=' * (4 - missing_padding)

        try:
            import base64
            decoded = base64.b64decode(b64).decode('utf-8', errors='ignore')
            data = json.loads(decoded)

            net_type = str(data.get("net", "tcp")).lower()
            name = data.get("ps", tag)

            return {
                "protocol": "vmess",
                "uuid": data.get("id"),
                "host": data.get("add"),
                "port": int(data.get("port", 0)),
                "aid": int(data.get("aid", 0)),
                "type": net_type,
                "security": data.get("tls", "") if data.get("tls") else "none",
                "path": data.get("path", ""),
                "host_header": data.get("host", ""),
                "sni": data.get("sni", ""),
                "fp": data.get("fp", ""),
                "alpn": data.get("alpn", ""),
                "scy": data.get("scy", "auto"),
                "tag": name,
                "name": name,
                "raw": url
            }
        except:
            pass

        return None
    except Exception as e:
        return None

def parse_trojan(url):
    try:
        if '#' in url:
            url_clean, tag = url.split('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            url_clean = url
            tag = "trojan"

        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            return None

        return {
            "protocol": "trojan",
            "uuid": parsed.username,
            "host": parsed.hostname,
            "port": int(parsed.port),
            "security": params.get("security", ["tls"])[0],
            "sni": params.get("sni", [""])[0] or params.get("peer", [""])[0],
            "type": params.get("type", ["tcp"])[0],
            "path": params.get("path", [""])[0],
            "host_header": params.get("host", [""])[0],
            "tag": tag,
            "name": tag,
            "raw": url
        }
    except:
        return None

def parse_ss(url):
    try:
        import base64
        if '#' in url:
            url_clean, tag = url.split('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            url_clean = url
            tag = "ss"

        parsed = urllib.parse.urlparse(url_clean)

        if '@' in url_clean:
            userinfo = parsed.username
            try:
                if userinfo and ':' not in userinfo:
                    missing_padding = len(userinfo) % 4
                    if missing_padding:
                        userinfo += '=' * (4 - missing_padding)
                    decoded_info = base64.b64decode(userinfo).decode('utf-8')
                else:
                    decoded_info = userinfo
            except:
                decoded_info = userinfo

            if not decoded_info or ':' not in decoded_info:
                return None
            method, password = decoded_info.split(':', 1)
            address = parsed.hostname
            port = parsed.port
        else:
            b64 = url_clean.replace("ss://", "")
            missing_padding = len(b64) % 4
            if missing_padding:
                b64 += '=' * (4 - missing_padding)
            decoded = base64.b64decode(b64).decode('utf-8')
            if '@' not in decoded:
                return None
            method_pass, addr_port = decoded.rsplit('@', 1)
            method, password = method_pass.split(':', 1)
            address, port = addr_port.rsplit(':', 1)

        if not address or not port:
            return None

        method_lower = method.lower().strip()

        return {
            "protocol": "shadowsocks",
            "host": address,
            "port": int(port),
            "method": method_lower,
            "password": password,
            "tag": tag,
            "name": tag,
            "raw": url
        }
    except:
        return None

def parse_hysteria2(url):
    try:
        url = url.replace("hy2://", "hysteria2://")
        if '#' in url:
            url_clean, tag = url.split('#', 1)
            tag = urllib.parse.unquote(tag).strip()
        else:
            url_clean = url
            tag = "hy2"

        parsed = urllib.parse.urlparse(url_clean)
        params = urllib.parse.parse_qs(parsed.query)

        if not parsed.hostname or not parsed.port:
            return None

        return {
            "protocol": "hysteria2",
            "uuid": parsed.username,
            "host": parsed.hostname,
            "port": int(parsed.port),
            "sni": params.get("sni", [""])[0],
            "insecure": params.get("insecure", ["0"])[0] == "1",
            "obfs": params.get("obfs", ["none"])[0],
            "obfs_password": params.get("obfs-password", [""])[0],
            "tag": tag,
            "name": tag,
            "raw": url
        }
    except:
        return None

def parse_proxy_url(proxy_url):
    try:
        proxy_url = clean_url(proxy_url)
        if proxy_url.startswith("vless://"):
            return parse_vless(proxy_url)
        if proxy_url.startswith("vmess://"):
            return parse_vmess(proxy_url)
        if proxy_url.startswith("trojan://"):
            return parse_trojan(proxy_url)
        if proxy_url.startswith("ss://"):
            return parse_ss(proxy_url)
        if proxy_url.startswith("hy"):
            return parse_hysteria2(proxy_url)
    except Exception:
        return None
    return None

def get_proxy_tag(url):
    tag = "proxy"
    try:
        url = clean_url(url)
        if '#' in url:
            _, raw_tag = url.rsplit('#', 1)
            tag = urllib.parse.unquote(raw_tag).strip()
    except:
        pass
    return tag if tag else "proxy"

def extract_proxy_info(proxy_url: str) -> Dict:
    parsed = parse_proxy_url(proxy_url)
    if not parsed:
        return {
            'full_config': proxy_url,
            'protocol': 'unknown',
            'host': 'unknown',
            'port': 0,
            'protocol_data': '{}'
        }
    
    return {
        'full_config': proxy_url,
        'protocol': parsed.get('protocol', 'unknown'),
        'host': parsed.get('host', 'unknown'),
        'port': parsed.get('port', 0),
        'protocol_data': json.dumps(parsed, ensure_ascii=False)
    }

# =============================================================================
# ЧАСТЬ 5: LocationDetector (ИСПРАВЛЕННЫЙ - с резервными методами)
# =============================================================================

class LocationDetector:
    """Определение местоположения по IP через различные бесплатные API"""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.cache = {}
        self.cache_file = "location_cache.json"
        self._lock = threading.RLock()
        self.last_request_time = 0
        self.request_delay = 0.5
        self.load_cache()
    
    def load_cache(self):
        try:
            if os.path.exists(self.cache_file):
                with open(self.cache_file, 'r', encoding='utf-8') as f:
                    self.cache = json.load(f)
                if self.verbose:
                    print(f"{GREEN}✅ Загружено {len(self.cache)} записей из кэша локаций{RESET}")
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}⚠ Не удалось загрузить кэш локаций: {e}{RESET}")
            self.cache = {}
    
    def save_cache(self):
        try:
            with open(self.cache_file, 'w', encoding='utf-8') as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}⚠ Не удалось сохранить кэш локаций: {e}{RESET}")
    
    def _code_to_country(self, code: str) -> str:
        countries = {
            'RU': 'Russia', 'US': 'United States', 'GB': 'United Kingdom',
            'DE': 'Germany', 'FR': 'France', 'NL': 'Netherlands',
            'CA': 'Canada', 'AU': 'Australia', 'JP': 'Japan',
            'SG': 'Singapore', 'KR': 'South Korea', 'CN': 'China',
            'IN': 'India', 'BR': 'Brazil', 'ZA': 'South Africa',
            'IT': 'Italy', 'ES': 'Spain', 'CH': 'Switzerland',
            'SE': 'Sweden', 'NO': 'Norway', 'FI': 'Finland',
            'DK': 'Denmark', 'PL': 'Poland', 'CZ': 'Czech Republic',
            'HU': 'Hungary', 'AT': 'Austria', 'BE': 'Belgium',
            'IE': 'Ireland', 'PT': 'Portugal', 'GR': 'Greece',
            'TR': 'Turkey', 'IL': 'Israel', 'AE': 'UAE',
            'SA': 'Saudi Arabia', 'EG': 'Egypt', 'UA': 'Ukraine',
            'BY': 'Belarus', 'KZ': 'Kazakhstan', 'GE': 'Georgia',
            'AM': 'Armenia', 'AZ': 'Azerbaijan', 'MD': 'Moldova',
            'LT': 'Lithuania', 'LV': 'Latvia', 'EE': 'Estonia',
        }
        return countries.get(code.upper(), code)
    
    def get_location_via_ipapi(self, ip: str) -> Optional[Dict]:
        """Получение локации через ip-api.com (бесплатно, без ключа)"""
        try:
            # ip-api.com - 45 запросов в минуту с бесплатного IP
            url = f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,city,region,isp,query"
            
            if REQUESTS_AVAILABLE:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('status') == 'success':
                        country_code = data.get('countryCode', 'XX').upper()
                        country = data.get('country', 'Unknown')
                        city = data.get('city', '')
                        region = data.get('region', '')
                        isp = data.get('isp', '')
                        
                        return {
                            'country': country,
                            'country_code': country_code,
                            'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳'),
                            'city': city,
                            'region': region,
                            'isp': isp,
                            'ip': ip,
                            'source': 'ip-api.com'
                        }
            else:
                # Используем curl если requests не доступен
                cmd = ['curl', '-s', '--max-time', '5', url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    if data.get('status') == 'success':
                        country_code = data.get('countryCode', 'XX').upper()
                        country = data.get('country', 'Unknown')
                        city = data.get('city', '')
                        region = data.get('region', '')
                        isp = data.get('isp', '')
                        
                        return {
                            'country': country,
                            'country_code': country_code,
                            'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳'),
                            'city': city,
                            'region': region,
                            'isp': isp,
                            'ip': ip,
                            'source': 'ip-api.com'
                        }
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}  ⚠ Ошибка ip-api.com для {ip}: {e}{RESET}")
        
        return None
    
    def get_location_via_ipinfo(self, ip: str) -> Optional[Dict]:
        """Получение локации через ipinfo.io (бесплатно, 50k запросов/месяц без ключа)"""
        try:
            url = f"https://ipinfo.io/{ip}/json"
            
            if REQUESTS_AVAILABLE:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    country_code = data.get('country', 'XX').upper()
                    country = self._code_to_country(country_code)
                    city = data.get('city', '')
                    region = data.get('region', '')
                    org = data.get('org', '')
                    
                    # Из org можно извлечь ISP
                    isp = org
                    
                    return {
                        'country': country,
                        'country_code': country_code,
                        'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳'),
                        'city': city,
                        'region': region,
                        'isp': isp,
                        'ip': ip,
                        'source': 'ipinfo.io'
                    }
            else:
                cmd = ['curl', '-s', '--max-time', '5', url]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                if result.returncode == 0 and result.stdout:
                    data = json.loads(result.stdout)
                    country_code = data.get('country', 'XX').upper()
                    country = self._code_to_country(country_code)
                    city = data.get('city', '')
                    region = data.get('region', '')
                    org = data.get('org', '')
                    isp = org
                    
                    return {
                        'country': country,
                        'country_code': country_code,
                        'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳'),
                        'city': city,
                        'region': region,
                        'isp': isp,
                        'ip': ip,
                        'source': 'ipinfo.io'
                    }
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}  ⚠ Ошибка ipinfo.io для {ip}: {e}{RESET}")
        
        return None
    
    def get_location_via_freegeoip(self, ip: str) -> Optional[Dict]:
        """Получение локации через freegeoip.app (бесплатно, 15000 запросов/час)"""
        try:
            url = f"https://freegeoip.app/json/{ip}"
            headers = {'Accept': 'application/json'}
            
            if REQUESTS_AVAILABLE:
                response = requests.get(url, headers=headers, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    country_code = data.get('country_code', 'XX').upper()
                    country = data.get('country_name', 'Unknown')
                    city = data.get('city', '')
                    region = data.get('region_name', '')
                    
                    return {
                        'country': country,
                        'country_code': country_code,
                        'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳'),
                        'city': city,
                        'region': region,
                        'isp': '',
                        'ip': ip,
                        'source': 'freegeoip.app'
                    }
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}  ⚠ Ошибка freegeoip.app для {ip}: {e}{RESET}")
        
        return None
    
    def get_location_via_ip2location(self, ip: str) -> Optional[Dict]:
        """Получение локации через ip2location.com (резервный API)"""
        try:
            url = f"https://api.ip2location.io/?key=demo&ip={ip}&format=json"
            
            if REQUESTS_AVAILABLE:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    data = response.json()
                    country_code = data.get('country_code', 'XX').upper()
                    country = data.get('country_name', 'Unknown')
                    city = data.get('city_name', '')
                    region = data.get('region_name', '')
                    
                    return {
                        'country': country,
                        'country_code': country_code,
                        'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳'),
                        'city': city,
                        'region': region,
                        'isp': '',
                        'ip': ip,
                        'source': 'ip2location.com'
                    }
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}  ⚠ Ошибка ip2location.com для {ip}: {e}{RESET}")
        
        return None
    
    def get_location_via_whois(self, ip: str) -> Optional[Dict]:
        """Получение локации через WHOIS (резервный метод)"""
        try:
            # Проверяем наличие whois
            result = subprocess.run(['which', 'whois'], capture_output=True, text=True, timeout=2)
            whois_available = result.returncode == 0 and result.stdout.strip()
            
            if not whois_available:
                return None
            
            cmd = ['whois', ip]
            whois_result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if whois_result.returncode == 0 and whois_result.stdout:
                output = whois_result.stdout
                
                result = {
                    'country': 'Unknown',
                    'country_code': 'XX',
                    'country_flag': '🇺🇳',
                    'city': '',
                    'region': '',
                    'isp': '',
                    'ip': ip,
                    'source': 'whois'
                }
                
                # Поиск страны
                country_patterns = [
                    (r'country:\s*([A-Z]{2})', 1),
                    (r'Country:\s*([A-Z]{2})', 1),
                    (r'country-code:\s*([A-Z]{2})', 1),
                ]
                
                for pattern, group in country_patterns:
                    match = re.search(pattern, output, re.IGNORECASE | re.MULTILINE)
                    if match:
                        country_code = match.group(group).upper()
                        if len(country_code) == 2:
                            result['country_code'] = country_code
                            result['country'] = self._code_to_country(country_code)
                            result['country_flag'] = COUNTRY_FLAGS.get(country_code, '🇺🇳')
                            break
                
                # Поиск города
                city_patterns = [
                    r'city:\s*(.+)',
                    r'City:\s*(.+)',
                ]
                
                for pattern in city_patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        city = match.group(1).strip()
                        city = re.sub(r'\s+', ' ', city)
                        if city and len(city) < 50:
                            result['city'] = city
                            break
                
                # Поиск провайдера
                isp_patterns = [
                    r'org-name:\s*(.+)',
                    r'OrgName:\s*(.+)',
                    r'organisation:\s*(.+)',
                ]
                
                for pattern in isp_patterns:
                    match = re.search(pattern, output, re.IGNORECASE)
                    if match:
                        isp = match.group(1).strip()
                        isp = re.sub(r'\s+', ' ', isp)
                        if isp and len(isp) < 100:
                            result['isp'] = isp
                            break
                
                return result
        except Exception as e:
            if self.verbose:
                print(f"{YELLOW}  ⚠ WHOIS ошибка для {ip}: {e}{RESET}")
        
        return None
    
    def get_location(self, ip: str) -> Dict:
        with self._lock:
            if ip in self.cache:
                if self.verbose:
                    print(f"{CYAN}  📍 Использую кэш для {ip}{RESET}")
                return self.cache[ip]
        
        result = {
            'country': 'Unknown',
            'country_code': 'XX',
            'country_flag': '🇺🇳',
            'city': '',
            'region': '',
            'isp': '',
            'ip': ip
        }
        
        if ip in ['127.0.0.1', 'localhost', 'unknown', '']:
            with self._lock:
                self.cache[ip] = result
            return result
        
        try:
            socket.inet_aton(ip)
        except socket.error:
            with self._lock:
                self.cache[ip] = result
            return result
        
        current_time = time.time()
        if current_time - self.last_request_time < self.request_delay:
            time.sleep(self.request_delay - (current_time - self.last_request_time))
        
        if self.verbose:
            print(f"{CYAN}  🌐 Определение локации для {ip}...{RESET}")
        
        # Пробуем разные API по очереди
        location = None
        
        # 1. ip-api.com (самый надежный, без ключа)
        location = self.get_location_via_ipapi(ip)
        
        # 2. ipinfo.io (запасной вариант)
        if not location:
            if self.verbose:
                print(f"{YELLOW}  ⚠ ip-api.com не ответил, пробуем ipinfo.io...{RESET}")
            location = self.get_location_via_ipinfo(ip)
        
        # 3. freegeoip.app (еще один запасной)
        if not location:
            if self.verbose:
                print(f"{YELLOW}  ⚠ ipinfo.io не ответил, пробуем freegeoip.app...{RESET}")
            location = self.get_location_via_freegeoip(ip)
        
        # 4. ip2location.com (демо-ключ)
        if not location:
            if self.verbose:
                print(f"{YELLOW}  ⚠ freegeoip.app не ответил, пробуем ip2location.com...{RESET}")
            location = self.get_location_via_ip2location(ip)
        
        # 5. WHOIS (последний шанс)
        if not location:
            if self.verbose:
                print(f"{YELLOW}  ⚠ API не ответили, пробуем WHOIS...{RESET}")
            location = self.get_location_via_whois(ip)
        
        if location:
            result.update(location)
            if self.verbose and result['country_code'] != 'XX':
                source = location.get('source', 'unknown')
                print(f"{GREEN}  ✅ {source}: {result['country_flag']} {result['country']}, {result['city']}{RESET}")
        else:
            if self.verbose:
                print(f"{YELLOW}  ⚠ Не удалось определить локацию для {ip}{RESET}")
        
        self.last_request_time = time.time()
        
        with self._lock:
            self.cache[ip] = result
            if len(self.cache) % 10 == 0:
                self.save_cache()
        
        return result
    
    def get_location_from_host(self, host: str) -> Dict:
        result = {
            'country': 'Unknown',
            'country_code': 'XX',
            'country_flag': '🇺🇳',
            'city': '',
            'region': '',
            'isp': '',
            'ip': host
        }
        
        with self._lock:
            if host in self.cache:
                return self.cache[host]
        
        # Пытаемся определить страну по домену
        tld_map = {
            '.ru': 'RU', '.su': 'RU', '.рф': 'RU',
            '.com': 'US', '.net': 'US', '.org': 'US',
            '.uk': 'GB', '.co.uk': 'GB', '.org.uk': 'GB',
            '.de': 'DE', '.fr': 'FR', '.nl': 'NL',
            '.ca': 'CA', '.au': 'AU', '.jp': 'JP',
            '.cn': 'CN', '.in': 'IN', '.br': 'BR',
            '.ua': 'UA', '.by': 'BY', '.kz': 'KZ',
        }
        
        host_lower = host.lower()
        for tld, country_code in tld_map.items():
            if host_lower.endswith(tld):
                result['country_code'] = country_code
                result['country'] = self._code_to_country(country_code)
                result['country_flag'] = COUNTRY_FLAGS.get(country_code, '🇺🇳')
                break
        
        with self._lock:
            self.cache[host] = result
        
        return result
    
    def rename_proxy(self, proxy_url: str, location: Dict) -> str:
        country = location.get('country', 'Unknown')
        flag = location.get('country_flag', '🇺🇳')
        city = location.get('city', '')
        
        if city and city != 'Unknown' and city.strip():
            new_tag = f"{flag} {city}, {country} X RAY"
        else:
            new_tag = f"{flag} {country} X RAY"
        
        new_tag = new_tag.replace('"', '').replace("'", "").replace('\n', '').replace('\r', '')
        
        if '#' in proxy_url:
            base_url = proxy_url.split('#')[0]
        else:
            base_url = proxy_url
        
        new_url = f"{base_url}#{new_tag}"
        
        if self.verbose:
            print(f"{GREEN}  ✏️ Переименовано: {new_tag}{RESET}")
        
        return new_url
    
    def get_country_flag(self, country_code: str) -> str:
        return COUNTRY_FLAGS.get(country_code.upper(), '🇺🇳')

# =============================================================================
# ЧАСТЬ 6: КЛАССЫ ДЛЯ МОБИЛЬНОЙ ОПТИМИЗАЦИИ
# =============================================================================

class TCPFreezeDetector:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def test_freeze(self, socks5_proxy: str, test_file: str = TEST_FILE_32KB, timeout: int = 15) -> Dict:
        result = {
            'freeze_detected': False,
            'bytes_received': 0,
            'freeze_threshold': TCP_FREEZE_THRESHOLD,
            'complete': False,
            'partial_data': False
        }
        
        try:
            proxy_host, proxy_port = socks5_proxy.replace('socks5://', '').split(':')
            
            cmd = [
                'curl', '-s', '-o', '/dev/null', '-w', '%{size_download}',
                '--socks5-hostname', f'{proxy_host}:{proxy_port}',
                '--connect-timeout', str(timeout),
                '--max-time', str(timeout * 2),
                '--verbose',
                test_file
            ]
            
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                if process.returncode == 0 and stdout.strip():
                    bytes_received = int(stdout.strip())
                    result['bytes_received'] = bytes_received
                    
                    if bytes_received < 32000:
                        result['partial_data'] = True
                        
                        if TCP_FREEZE_THRESHOLD - 5000 <= bytes_received <= TCP_FREEZE_THRESHOLD + 5000:
                            result['freeze_detected'] = True
                            result['freeze_confidence'] = 'high'
                        else:
                            result['freeze_confidence'] = 'medium'
                    else:
                        result['complete'] = True
                        
                elif '18' in stderr or 'transfer closed' in stderr:
                    result['freeze_detected'] = True
                    result['freeze_confidence'] = 'high'
                    result['error'] = stderr[-200:]
                    
            except subprocess.TimeoutExpired:
                process.kill()
                result['freeze_detected'] = True
                result['freeze_confidence'] = 'medium'
                result['error'] = 'Timeout - possible freeze'
                
        except Exception as e:
            result['error'] = str(e)
        
        if self.verbose and result['freeze_detected']:
            print(f"{YELLOW}  ⚠ Обнаружено замораживание TCP! Получено {result['bytes_received']} байт{RESET}")
        
        return result

class MSSOptimizer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.test_url = "https://www.google.com/generate_204"
    
    def test_mss_value(self, mss: int, proxy_info: Dict, xray_binary: str, temp_dir: str) -> Dict:
        result = {
            'mss': mss,
            'success': False,
            'time': 0,
            'error': None
        }
        
        config = self._create_mss_config(proxy_info, mss)
        config_hash = hashlib.md5(f"{proxy_info.get('raw', '')}_{mss}".encode()).hexdigest()[:8]
        config_path = os.path.join(temp_dir, f"mss_test_{config_hash}.json")
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        process = None
        try:
            process = subprocess.Popen(
                [xray_binary, '-c', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(1)
            
            if process.poll() is not None:
                result['error'] = "Xray не запустился"
                return result
            
            start_time = time.time()
            proxy_host, proxy_port = '127.0.0.1', '10808'
            
            cmd = [
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--socks5-hostname', f'{proxy_host}:{proxy_port}',
                '--connect-timeout', '5',
                '--max-time', '10',
                self.test_url
            ]
            
            curl_result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if curl_result.stdout.strip() in ['204', '200']:
                result['success'] = True
                result['time'] = time.time() - start_time
                
        except Exception as e:
            result['error'] = str(e)
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            
            try:
                os.remove(config_path)
            except:
                pass
        
        return result
    
    def _create_mss_config(self, proxy_info: Dict, mss: int) -> Dict:
        config = {
            "log": {"loglevel": "error"},
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}
            ],
            "outbounds": [
                {
                    "protocol": proxy_info.get('protocol', 'vless'),
                    "settings": {
                        "vnext": [{
                            "address": proxy_info.get('host', ''),
                            "port": proxy_info.get('port', 0),
                            "users": [{
                                "id": proxy_info.get('uuid', ''),
                                "encryption": proxy_info.get('encryption', 'none'),
                                "flow": proxy_info.get('flow', '')
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": proxy_info.get('type', 'tcp'),
                        "security": proxy_info.get('security', 'none'),
                        "sockopt": {
                            "tcpMaxSeg": mss,
                            "tcpNoDelay": True
                        }
                    }
                }
            ]
        }
        
        if proxy_info.get('security') == 'reality':
            config['outbounds'][0]['streamSettings']['realitySettings'] = {
                "serverName": proxy_info.get('sni', proxy_info.get('host', '')),
                "fingerprint": proxy_info.get('fp', 'chrome'),
                "publicKey": proxy_info.get('pbk', ''),
                "shortId": proxy_info.get('sid', '')
            }
        elif proxy_info.get('security') == 'tls':
            config['outbounds'][0]['streamSettings']['tlsSettings'] = {
                "serverName": proxy_info.get('sni', proxy_info.get('host', '')),
                "fingerprint": proxy_info.get('fp', 'chrome'),
                "allowInsecure": True
            }
        
        if proxy_info.get('type') == 'ws':
            ws_settings = {}
            if proxy_info.get('path'):
                ws_settings['path'] = proxy_info['path']
            if proxy_info.get('host'):
                ws_settings['headers'] = {"Host": proxy_info['host']}
            config['outbounds'][0]['streamSettings']['wsSettings'] = ws_settings
        
        return config
    
    def find_optimal_mss(self, proxy_info: Dict, xray_binary: str, temp_dir: str) -> Dict:
        print(f"\n{CYAN}🔍 Автоматический подбор MSS...{RESET}")
        
        results = []
        
        for mss in MSS_TEST_RANGE:
            if self.verbose:
                print(f"  Тестирование MSS = {mss}... ", end='', flush=True)
            
            test_result = self.test_mss_value(mss, proxy_info, xray_binary, temp_dir)
            results.append(test_result)
            
            if self.verbose:
                if test_result['success']:
                    print(f"{GREEN}✓ {test_result['time']*1000:.0f}ms{RESET}")
                else:
                    print(f"{RED}✗{RESET}")
            
            time.sleep(0.5)
        
        successful = [r for r in results if r['success']]
        
        if successful:
            optimal = min(successful, key=lambda x: x['mss'])
            fastest = min(successful, key=lambda x: x['time'])
            
            print(f"\n{GREEN}✅ Оптимальный MSS найден:{RESET}")
            print(f"  • Наименьший работающий: {optimal['mss']} (лучшая совместимость)")
            print(f"  • Самый быстрый: {fastest['mss']} ({fastest['time']*1000:.0f}ms)")
            
            recommended = optimal['mss']
            print(f"  {CYAN}→ Рекомендуется: {recommended} (MTU ≈ {recommended + 40}){RESET}")
            
            return {
                'optimal_mss': recommended,
                'all_results': results,
                'working_range': [r['mss'] for r in successful],
                'fastest_mss': fastest['mss']
            }
        else:
            print(f"{RED}❌ Не найдено работающих значений MSS{RESET}")
            return {'optimal_mss': None, 'all_results': results}

class RTTDiscrepancyAnalyzer:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def analyze(self, host: str, port: int = 443, sni: str = None) -> Dict:
        result = {
            'tcp_rtt': None,
            'tls_rtt': None,
            'discrepancy': None,
            'dpi_detected': False,
            'confidence': 0
        }
        
        try:
            start = time.time()
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((host, port))
            tcp_time = time.time() - start
            sock.close()
            
            result['tcp_rtt'] = tcp_time
        except:
            pass
        
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            start = time.time()
            with socket.create_connection((host, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=sni or host) as ssock:
                    cert = ssock.getpeercert()
                    tls_time = time.time() - start
            
            result['tls_rtt'] = tls_time
        except:
            pass
        
        if result['tcp_rtt'] and result['tls_rtt']:
            expected_tls = result['tcp_rtt'] * 2
            actual_tls = result['tls_rtt']
            
            result['discrepancy'] = actual_tls / expected_tls if expected_tls > 0 else 0
            
            if result['discrepancy'] > 3.0:
                result['dpi_detected'] = True
                result['confidence'] = min(100, int((result['discrepancy'] - 2) * 50))
            elif result['discrepancy'] > 2.0:
                result['dpi_detected'] = True
                result['confidence'] = min(70, int((result['discrepancy'] - 1.5) * 40))
        
        return result

class PortHunting:
    COMMON_PORTS = [
        443, 8443, 2053, 2083, 2087, 2096, 4443, 6443, 9443, 8080, 8888,
        11443, 12443, 13443, 14443, 15443, 16443, 17443, 18443, 19443, 20443,
    ]
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
    
    def test_port(self, host: str, port: int, proxy_info: Dict,
                 xray_binary: str, temp_dir: str) -> Dict:
        result = {
            'port': port,
            'success': False,
            'time': 0,
            'error': None
        }
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            tcp_result = sock.connect_ex((host, port))
            sock.close()
            
            if tcp_result != 0:
                result['error'] = f"TCP connect failed: {tcp_result}"
                return result
        except Exception as e:
            result['error'] = str(e)
            return result
        
        base_config = {
            "log": {"loglevel": "error"},
            "inbounds": [
                {"port": 10808, "protocol": "socks", "settings": {"auth": "noauth", "udp": True}}
            ],
            "outbounds": [
                {
                    "protocol": proxy_info.get('protocol', 'vless'),
                    "settings": {
                        "vnext": [{
                            "address": host,
                            "port": port,
                            "users": [{
                                "id": proxy_info.get('uuid', ''),
                                "encryption": proxy_info.get('encryption', 'none'),
                                "flow": proxy_info.get('flow', '')
                            }]
                        }]
                    },
                    "streamSettings": {
                        "network": proxy_info.get('type', 'tcp'),
                        "security": proxy_info.get('security', 'none')
                    }
                }
            ]
        }
        
        if proxy_info.get('security') == 'reality':
            base_config['outbounds'][0]['streamSettings']['realitySettings'] = {
                "serverName": proxy_info.get('sni', host),
                "fingerprint": proxy_info.get('fp', 'chrome'),
                "publicKey": proxy_info.get('pbk', ''),
                "shortId": proxy_info.get('sid', '')
            }
        
        config_hash = hashlib.md5(f"{host}_{port}".encode()).hexdigest()[:8]
        config_path = os.path.join(temp_dir, f"port_{config_hash}.json")
        
        with open(config_path, 'w') as f:
            json.dump(base_config, f, indent=2)
        
        process = None
        try:
            process = subprocess.Popen(
                [xray_binary, '-c', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(1)
            
            if process.poll() is not None:
                result['error'] = "Xray не запустился"
                return result
            
            start = time.time()
            proxy_host, proxy_port = '127.0.0.1', '10808'
            
            cmd = [
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--socks5-hostname', f'{proxy_host}:{proxy_port}',
                '--connect-timeout', '5',
                '--max-time', '10',
                'https://www.google.com/generate_204'
            ]
            
            curl_result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if curl_result.stdout.strip() in ['204', '200']:
                result['success'] = True
                result['time'] = time.time() - start
                
        except Exception as e:
            result['error'] = str(e)
        finally:
            if process:
                process.terminate()
                try:
                    process.wait(timeout=2)
                except:
                    process.kill()
            
            try:
                os.remove(config_path)
            except:
                pass
        
        return result
    
    def hunt_ports(self, proxy_info: Dict, xray_binary: str, temp_dir: str,
                  fast_mode: bool = True) -> Dict:
        print(f"\n{CYAN}🔍 Port Hunting...{RESET}")
        
        host = proxy_info.get('host', '')
        original_port = proxy_info.get('port', 0)
        
        print(f"  Хост: {host}")
        print(f"  Оригинальный порт: {original_port}")
        
        ports_to_test = self.COMMON_PORTS[:20] if fast_mode else self.COMMON_PORTS
        
        if original_port not in ports_to_test and fast_mode:
            ports_to_test = [original_port] + ports_to_test[:19]
        
        results = []
        
        for port in ports_to_test:
            if self.verbose:
                print(f"  Тест порта {port}... ", end='', flush=True)
            
            result = self.test_port(host, port, proxy_info, xray_binary, temp_dir)
            results.append(result)
            
            if self.verbose:
                if result['success']:
                    print(f"{GREEN}✓ {result['time']*1000:.0f}ms{RESET}")
                else:
                    print(f"{RED}✗{RESET}")
            
            time.sleep(0.5)
        
        working_ports = [r for r in results if r['success']]
        
        print(f"\n{GREEN}📊 Результаты Port Hunting:{RESET}")
        print(f"  Проверено портов: {len(results)}")
        print(f"  Работающих портов: {len(working_ports)}")
        
        if working_ports:
            working_ports.sort(key=lambda x: x['time'])
            
            print(f"\n{CYAN}🏆 Топ-5 лучших портов:{RESET}")
            for i, r in enumerate(working_ports[:5], 1):
                marker = "★" if r['port'] == original_port else " "
                print(f"  {i}. {marker} Порт {r['port']:5} | {r['time']*1000:5.0f}ms")
            
            best_port = working_ports[0]['port']
            print(f"\n{YELLOW}💡 Рекомендуемый порт: {best_port}{RESET}")
            if best_port != original_port:
                print(f"  (оригинальный порт {original_port} медленнее или не работает)")
            
            return {
                'all_results': results,
                'working_ports': working_ports,
                'best_port': best_port,
                'original_port_works': any(r['port'] == original_port and r['success'] for r in results)
            }
        else:
            print(f"{RED}❌ Не найдено работающих портов{RESET}")
            return {
                'all_results': results,
                'working_ports': [],
                'best_port': None
            }

class NetworkEmulator:
    def __init__(self, interface: str = "eth0", verbose: bool = False):
        self.interface = interface
        self.verbose = verbose
        self.current_profile = None
        self.is_linux = sys.platform.startswith('linux')
        self.emulation_enabled = False
    
    def apply_mobile_profile(self, operator: str, dst_ip: str = None, dst_port: int = 443) -> bool:
        if operator not in MOBILE_OPERATORS:
            print(f"{RED}Неизвестный оператор: {operator}{RESET}")
            return False
        
        profile = MOBILE_OPERATORS[operator]
        self.current_profile = profile
        
        print(f"\n{CYAN}Применение профиля {operator}: {profile['description']}{RESET}")
        print(f"  📡 Задержка: {profile['latency'][0]}-{profile['latency'][1]} мс, джиттер: {profile['jitter']} мс")
        print(f"  📉 Потери: {profile['packet_loss']}% (burst: {profile['burst_loss']}%)")
        print(f"  ⚡ Скорость: ↓{profile['bandwidth_down']/1000:.1f} Мбит/с, ↑{profile['bandwidth_up']/1000:.1f} Мбит/с")
        print(f"  📦 MTU: {profile['mtu']} байт")
        
        return True

# =============================================================================
# ЧАСТЬ 7: ОБЩИЙ МЕНЕДЖЕР БАЗЫ ДАННЫХ ПРОВЕРОК (aiosqlite) - ИСПРАВЛЕННЫЙ
# =============================================================================

class CheckDatabaseManager:
    def __init__(self, db_path: str = CHECK_DB_FILE):
        self.db_path = db_path
        print(f"{GREEN}✅ CheckDatabaseManager инициализирован: {db_path}{RESET}")
    
    @asynccontextmanager
    async def get_connection(self):
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
        finally:
            await conn.close()
    
    async def init_database(self):
        async with self.get_connection() as conn:
            # Получаем список всех таблиц
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = await cursor.fetchall()
            table_names = [t[0] for t in tables]
            
            # Удаляем старую таблицу если она есть, чтобы создать новую с правильной структурой
            if 'check_results' in table_names:
                print(f"{YELLOW}⚠ Обновление структуры таблицы check_results...{RESET}")
                
                # Сохраняем старые данные если нужно
                try:
                    cursor = await conn.execute("SELECT * FROM check_results")
                    old_rows = await cursor.fetchall()
                    
                    # Получаем названия колонок
                    cursor = await conn.execute("PRAGMA table_info(check_results)")
                    columns_info = await cursor.fetchall()
                    old_columns = [col[1] for col in columns_info]
                    
                    # Сохраняем старые данные во временную переменную
                    old_data = []
                    for row in old_rows:
                        row_dict = {}
                        for i, col in enumerate(old_columns):
                            row_dict[col] = row[i]
                        old_data.append(row_dict)
                    
                    print(f"{GREEN}✅ Сохранено {len(old_data)} записей из старой таблицы{RESET}")
                except Exception as e:
                    print(f"{YELLOW}⚠ Не удалось сохранить старые данные: {e}{RESET}")
                    old_data = []
                
                # Удаляем старую таблицу
                await conn.execute("DROP TABLE IF EXISTS check_results")
                print(f"{GREEN}✅ Старая таблица удалена{RESET}")
            
            # Создаем новую таблицу с правильной структурой
            await conn.execute('''
                CREATE TABLE check_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    proxy_id TEXT NOT NULL,
                    proxy_url TEXT NOT NULL,
                    checker_id TEXT NOT NULL,
                    check_time TEXT NOT NULL,
                    success INTEGER NOT NULL,
                    latency_ms INTEGER,
                    blocked_success INTEGER,
                    blocked_total INTEGER,
                    blocked_percent INTEGER,
                    base_connection_success INTEGER,
                    error TEXT,
                    verdict TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            print(f"{GREEN}✅ Создана новая таблица check_results с правильной структурой{RESET}")

            # Создаем таблицу proxy_locks, если её нет
            await conn.execute('''
                CREATE TABLE IF NOT EXISTS proxy_locks (
                    proxy_id TEXT PRIMARY KEY,
                    checker_id TEXT NOT NULL,
                    locked_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    task_data TEXT
                )
            ''')
            
            # Индексы
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_check_results_proxy_id 
                ON check_results(proxy_id)
            ''')
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_check_results_check_time 
                ON check_results(check_time)
            ''')
            
            await conn.commit()
            print(f"{GREEN}✅ База данных {self.db_path} инициализирована{RESET}")
    
    async def save_check_result(self, proxy_id: str, checker_id: str, proxy_url: str, result: Dict) -> bool:
        try:
            async with self.get_connection() as conn:
                await conn.execute('''
                    INSERT INTO check_results (
                        proxy_id, proxy_url, checker_id, check_time, success, 
                        latency_ms, blocked_success, blocked_total, 
                        blocked_percent, base_connection_success, error, verdict
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    proxy_id,
                    proxy_url,
                    checker_id,
                    datetime.now().isoformat(),
                    1 if result.get('success', False) or result.get('verdict') == 'good' else 0,
                    result.get('latency_ms', 0),
                    result.get('blocked_success', 0),
                    result.get('blocked_total', 0),
                    result.get('blocked_percent', 0),
                    1 if result.get('base_connection_success', False) else 0,
                    result.get('error'),
                    result.get('verdict', 'unknown')
                ))
                await conn.commit()
                return True
        except Exception as e:
            print(f"{RED}Ошибка сохранения результата: {e}{RESET}")
            traceback.print_exc()
            return False
    
    async def get_last_check(self, proxy_id: str) -> Optional[Dict]:
        try:
            async with self.get_connection() as conn:
                cursor = await conn.execute('''
                    SELECT * FROM check_results 
                    WHERE proxy_id = ? 
                    ORDER BY check_time DESC LIMIT 1
                ''', (proxy_id,))
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return None
        except Exception as e:
            print(f"{RED}Ошибка get_last_check: {e}{RESET}")
            return None
    
    async def acquire_lock(self, proxy_id: str, checker_id: str, task_data: Dict = None) -> bool:
        try:
            now = datetime.now()
            expires = datetime.fromtimestamp(now.timestamp() + LOCK_TIMEOUT)
            
            # Сериализуем task_data в JSON строку
            task_data_json = None
            if task_data:
                try:
                    task_data_json = json.dumps(task_data, ensure_ascii=False)
                except:
                    task_data_json = str(task_data)
            
            async with self.get_connection() as conn:
                # Проверяем существующую блокировку
                cursor = await conn.execute('SELECT * FROM proxy_locks WHERE proxy_id = ?', (proxy_id,))
                existing = await cursor.fetchone()
                
                if existing:
                    # Проверяем не истекла ли блокировка
                    if existing['expires_at'] > now.isoformat():
                        return False
                    else:
                        # Обновляем истекшую блокировку
                        await conn.execute('''
                            UPDATE proxy_locks 
                            SET checker_id = ?, locked_at = ?, expires_at = ?, task_data = ?
                            WHERE proxy_id = ?
                        ''', (checker_id, now.isoformat(), expires.isoformat(), task_data_json, proxy_id))
                else:
                    # Создаем новую блокировку
                    await conn.execute('''
                        INSERT INTO proxy_locks (proxy_id, checker_id, locked_at, expires_at, task_data)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (proxy_id, checker_id, now.isoformat(), expires.isoformat(), task_data_json))
                
                await conn.commit()
                return True
        except Exception as e:
            print(f"{RED}Ошибка acquire_lock: {e}{RESET}")
            traceback.print_exc()
            return False
    
    async def release_lock(self, proxy_id: str, checker_id: str) -> bool:
        try:
            async with self.get_connection() as conn:
                cursor = await conn.execute('''
                    DELETE FROM proxy_locks 
                    WHERE proxy_id = ? AND checker_id = ?
                ''', (proxy_id, checker_id))
                await conn.commit()
                return cursor.rowcount > 0
        except Exception as e:
            print(f"{RED}Ошибка release_lock: {e}{RESET}")
            return False
    
    async def clean_expired_locks(self) -> int:
        try:
            now = datetime.now().isoformat()
            async with self.get_connection() as conn:
                cursor = await conn.execute('DELETE FROM proxy_locks WHERE expires_at < ?', (now,))
                await conn.commit()
                return cursor.rowcount
        except Exception as e:
            print(f"{RED}Ошибка clean_expired_locks: {e}{RESET}")
            return 0
    
    async def get_checker_stats(self, checker_id: str) -> Dict:
        try:
            async with self.get_connection() as conn:
                cursor = await conn.execute('''
                    SELECT 
                        COUNT(*) as total,
                        SUM(success) as success_count,
                        AVG(latency_ms) as avg_latency,
                        AVG(blocked_percent) as avg_blocked_percent
                    FROM check_results 
                    WHERE checker_id = ?
                ''', (checker_id,))
                row = await cursor.fetchone()
                if row:
                    return dict(row)
                return {'total': 0, 'success_count': 0}
        except Exception as e:
            print(f"{RED}Ошибка get_checker_stats: {e}{RESET}")
            return {'total': 0, 'success_count': 0}

# =============================================================================
# ЧАСТЬ 8: МЕНЕДЖЕР ОСНОВНОЙ БАЗЫ ПРОКСИ (aiosqlite)
# =============================================================================

class MainDatabaseManager:
    def __init__(self, db_path: str = MAIN_DB_FILE):
        self.db_path = db_path
        print(f"{GREEN}✅ MainDatabaseManager инициализирован: {db_path}{RESET}")
    
    @asynccontextmanager
    async def get_connection(self):
        conn = await aiosqlite.connect(self.db_path)
        conn.row_factory = aiosqlite.Row
        await conn.execute("PRAGMA journal_mode=WAL")
        await conn.execute("PRAGMA synchronous=NORMAL")
        try:
            yield conn
        finally:
            await conn.close()
    
    async def init_database(self):
        async with self.get_connection() as conn:
            cursor = await conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='proxies'")
            table_exists = await cursor.fetchone() is not None
            
            if table_exists:
                cursor = await conn.execute("PRAGMA table_info(proxies)")
                columns_info = await cursor.fetchall()
                columns = [col[1] for col in columns_info]
                
                if 'proxy_id' not in columns:
                    print(f"{YELLOW}⚠ Обновление структуры таблицы proxies...{RESET}")
                    
                    await conn.execute('''
                        CREATE TABLE proxies_new (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            proxy_id TEXT UNIQUE NOT NULL,
                            full_config TEXT NOT NULL,
                            protocol TEXT,
                            host TEXT,
                            port INTEGER,
                            country TEXT,
                            city TEXT,
                            isp TEXT,
                            latency_ms INTEGER DEFAULT 0,
                            blocked_percent INTEGER DEFAULT 0,
                            success_count INTEGER DEFAULT 0,
                            fail_count INTEGER DEFAULT 0,
                            last_check TEXT,
                            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                            updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                            protocol_data TEXT
                        )
                    ''')
                    
                    cursor = await conn.execute('SELECT * FROM proxies')
                    old_rows = await cursor.fetchall()
                    old_column_names = [col[1] for col in columns_info]
                    
                    migrated_count = 0
                    error_count = 0
                    
                    for row in old_rows:
                        try:
                            old_data = {}
                            for i, col_name in enumerate(old_column_names):
                                old_data[col_name] = row[i]
                            
                            full_config = old_data.get('full_config', '')
                            if full_config:
                                proxy_id = hashlib.md5(full_config.encode()).hexdigest()[:16]
                            else:
                                proxy_id = hashlib.md5(str(time.time() + random.random()).encode()).hexdigest()[:16]
                            
                            host = old_data.get('host')
                            if host is None:
                                host = old_data.get('ip', '')
                            
                            await conn.execute('''
                                INSERT INTO proxies_new (
                                    proxy_id, full_config, protocol, host, port,
                                    country, city, isp, latency_ms, blocked_percent,
                                    success_count, fail_count, last_check, created_at,
                                    updated_at, protocol_data
                                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (
                                proxy_id,
                                old_data.get('full_config', ''),
                                old_data.get('protocol'),
                                host,
                                old_data.get('port'),
                                old_data.get('country'),
                                old_data.get('city'),
                                old_data.get('isp'),
                                old_data.get('latency_ms', 0),
                                old_data.get('blocked_percent', 0),
                                old_data.get('success_count', 0),
                                old_data.get('fail_count', 0),
                                old_data.get('last_check'),
                                old_data.get('created_at', datetime.now().isoformat()),
                                datetime.now().isoformat(),
                                old_data.get('protocol_data', '{}')
                            ))
                            migrated_count += 1
                        except Exception as e:
                            error_count += 1
                            print(f"{RED}Ошибка при миграции записи: {e}{RESET}")
                            continue
                    
                    await conn.execute('DROP TABLE proxies')
                    await conn.execute('ALTER TABLE proxies_new RENAME TO proxies')
                    
                    print(f"{GREEN}✅ Структура таблицы обновлена, перенесено {migrated_count} записей, ошибок: {error_count}{RESET}")
                else:
                    print(f"{GREEN}✅ Таблица proxies уже имеет правильную структуру{RESET}")
            else:
                await conn.execute('''
                    CREATE TABLE proxies (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        proxy_id TEXT UNIQUE NOT NULL,
                        full_config TEXT NOT NULL,
                        protocol TEXT,
                        host TEXT,
                        port INTEGER,
                        country TEXT,
                        city TEXT,
                        isp TEXT,
                        latency_ms INTEGER DEFAULT 0,
                        blocked_percent INTEGER DEFAULT 0,
                        success_count INTEGER DEFAULT 0,
                        fail_count INTEGER DEFAULT 0,
                        last_check TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        protocol_data TEXT
                    )
                ''')
                print(f"{GREEN}✅ Создана новая таблица proxies{RESET}")
            
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_proxies_proxy_id 
                ON proxies(proxy_id)
            ''')
            await conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_proxies_last_check 
                ON proxies(last_check)
            ''')
            
            await conn.commit()
    
    async def add_working_proxy(self, proxy_url: str, check_result: Dict, location: Dict = None) -> bool:
        try:
            proxy_id = hashlib.md5(proxy_url.encode()).hexdigest()[:16]
            info = extract_proxy_info(proxy_url)
            
            if location is None and info['host'] and info['host'] != 'unknown':
                try:
                    socket.inet_aton(info['host'])
                    detector = LocationDetector(verbose=False)
                    location = detector.get_location(info['host'])
                except socket.error:
                    location = {
                        'country': 'Unknown',
                        'country_code': 'XX',
                        'country_flag': '🇺🇳',
                        'city': '',
                        'region': '',
                        'isp': '',
                        'ip': info['host']
                    }
            elif location is None:
                location = {
                    'country': 'Unknown',
                    'country_code': 'XX',
                    'country_flag': '🇺🇳',
                    'city': '',
                    'region': '',
                    'isp': '',
                    'ip': info['host']
                }
            
            detector = LocationDetector(verbose=False)
            renamed_url = detector.rename_proxy(proxy_url, location)
            
            async with self.get_connection() as conn:
                cursor = await conn.execute('SELECT id FROM proxies WHERE proxy_id = ?', (proxy_id,))
                existing = await cursor.fetchone()
                
                if existing:
                    await conn.execute('''
                        UPDATE proxies 
                        SET full_config = ?,
                            protocol = ?,
                            host = ?,
                            port = ?,
                            country = ?,
                            city = ?,
                            isp = ?,
                            latency_ms = ?,
                            blocked_percent = ?,
                            success_count = success_count + 1,
                            last_check = ?,
                            updated_at = ?,
                            protocol_data = ?
                        WHERE proxy_id = ?
                    ''', (
                        renamed_url,
                        info['protocol'],
                        info['host'],
                        info['port'],
                        location.get('country', 'Unknown'),
                        location.get('city', ''),
                        location.get('isp', ''),
                        check_result.get('latency_ms', 0),
                        check_result.get('blocked_percent', 0),
                        datetime.now().isoformat(),
                        datetime.now().isoformat(),
                        info['protocol_data'],
                        proxy_id
                    ))
                else:
                    await conn.execute('''
                        INSERT INTO proxies (
                            proxy_id, full_config, protocol, host, port,
                            country, city, isp, latency_ms, blocked_percent,
                            success_count, last_check, protocol_data
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        proxy_id,
                        renamed_url,
                        info['protocol'],
                        info['host'],
                        info['port'],
                        location.get('country', 'Unknown'),
                        location.get('city', ''),
                        location.get('isp', ''),
                        check_result.get('latency_ms', 0),
                        check_result.get('blocked_percent', 0),
                        1,
                        datetime.now().isoformat(),
                        info['protocol_data']
                    ))
                
                await conn.commit()
                return True
                
        except Exception as e:
            print(f"{RED}Ошибка добавления рабочего прокси: {e}{RESET}")
            return False
    
    async def proxy_exists(self, proxy_url: str) -> bool:
        proxy_id = hashlib.md5(proxy_url.encode()).hexdigest()[:16]
        async with self.get_connection() as conn:
            cursor = await conn.execute('SELECT id FROM proxies WHERE proxy_id = ?', (proxy_id,))
            return await cursor.fetchone() is not None
    
    async def get_all_proxies(self) -> List[Dict]:
        async with self.get_connection() as conn:
            cursor = await conn.execute('''
                SELECT id, proxy_id, full_config, protocol, host, port,
                       country, city, isp, latency_ms, blocked_percent,
                       success_count, fail_count, last_check, created_at
                FROM proxies 
                ORDER BY blocked_percent DESC, latency_ms ASC
            ''')
            
            rows = await cursor.fetchall()
            proxies = [dict(row) for row in rows]
            return proxies
    
    async def get_stats(self) -> Dict:
        async with self.get_connection() as conn:
            cursor = await conn.execute('''
                SELECT 
                    COUNT(*) as total,
                    AVG(latency_ms) as avg_latency,
                    AVG(blocked_percent) as avg_blocked_percent,
                    SUM(success_count) as total_success
                FROM proxies
            ''')
            row = await cursor.fetchone()
            if row:
                return dict(row)
            return {'total': 0, 'avg_latency': 0, 'avg_blocked_percent': 0, 'total_success': 0}

# =============================================================================
# ЧАСТЬ 9: МЕНЕДЖЕР СПИСКА ПРОКСИ ДЛЯ ПРОВЕРКИ
# =============================================================================

class ProxyListManager:
    def __init__(self, config_dir: str, verbose: bool = False):
        self.config_dir = config_dir
        self.verbose = verbose
        self.proxies = []
        self.proxy_queue = queue.Queue()
        self.loaded = False
        self.total = 0
        self.processed = 0
        self.lock = threading.RLock()
        self.file_hashes = {}
        self.last_scan = 0
        
        self.load_from_directory(config_dir)
        
        self.running = True
        self.monitor_thread = threading.Thread(target=self._monitor_directory, daemon=True)
        self.monitor_thread.start()
    
    def load_from_directory(self, dir_path: str):
        try:
            with self.lock:
                if not os.path.exists(dir_path):
                    print(f"{RED}❌ Директория не найдена: {dir_path}{RESET}")
                    return
                
                if not os.path.isdir(dir_path):
                    print(f"{RED}❌ Указанный путь не является директорией: {dir_path}{RESET}")
                    return
                
                txt_files = list(Path(dir_path).glob("*.txt"))
                
                if not txt_files:
                    print(f"{YELLOW}⚠ В директории {dir_path} не найдено .txt файлов{RESET}")
                    return
                
                current_hashes = {}
                new_proxies = []
                file_counts = {}
                
                for file_path in txt_files:
                    try:
                        file_stat = os.stat(file_path)
                        file_mtime = file_stat.st_mtime
                        file_hash = hashlib.md5(f"{file_path}_{file_mtime}".encode()).hexdigest()[:16]
                        current_hashes[str(file_path)] = file_hash
                        
                        if file_hash == self.file_hashes.get(str(file_path)):
                            continue
                        
                        encoding = detect_encoding(str(file_path))
                        with open(file_path, 'r', encoding=encoding) as f:
                            lines = f.readlines()
                        
                        file_count = 0
                        for line in lines:
                            line = line.strip()
                            if line and not line.startswith('#'):
                                if any(line.startswith(p) for p in ['vless://', 'vmess://', 'trojan://', 'ss://', 'hy2://']):
                                    proxy_id = hashlib.md5(line.encode()).hexdigest()[:16]
                                    if proxy_id not in [hashlib.md5(p.encode()).hexdigest()[:16] for p in new_proxies]:
                                        new_proxies.append(line)
                                        file_count += 1
                        
                        if file_count > 0:
                            file_counts[file_path.name] = file_count
                            
                    except Exception as e:
                        print(f"{RED}  • Ошибка чтения {file_path.name}: {e}{RESET}")
                
                self.file_hashes = current_hashes
                
                if new_proxies:
                    old_total = self.total
                    
                    self.proxies.extend(new_proxies)
                    random.shuffle(new_proxies)
                    for proxy in new_proxies:
                        self.proxy_queue.put(proxy)
                    
                    self.total = len(self.proxies)
                    
                    if self.verbose:
                        print(f"\n{GREEN}➕ Добавлено {len(new_proxies)} новых прокси{RESET}")
                        for fname, count in file_counts.items():
                            print(f"  • {fname}: +{count}")
                        print(f"{GREEN}✅ Всего в очереди: {self.total} прокси{RESET}")
                
                self.loaded = True
                
        except Exception as e:
            print(f"{RED}❌ Ошибка загрузки прокси: {e}{RESET}")
    
    def _monitor_directory(self):
        while self.running:
            try:
                time.sleep(60)
                if self.verbose:
                    print(f"{CYAN}🔍 Проверка обновлений в {self.config_dir}...{RESET}")
                self.load_from_directory(self.config_dir)
            except Exception as e:
                if self.verbose:
                    print(f"{RED}Ошибка мониторинга: {e}{RESET}")
    
    def get_next_proxy(self) -> Optional[Tuple[str, str]]:
        try:
            with self.lock:
                if not self.proxy_queue.empty():
                    proxy_url = self.proxy_queue.get_nowait()
                    proxy_id = hashlib.md5(proxy_url.encode()).hexdigest()[:16]
                    return proxy_url, proxy_id
                return None
        except queue.Empty:
            return None
    
    def mark_processed(self):
        with self.lock:
            self.processed += 1
    
    def get_progress(self) -> Dict:
        with self.lock:
            return {
                'total': self.total,
                'processed': self.processed,
                'remaining': self.total - self.processed,
                'percent': (self.processed / self.total * 100) if self.total > 0 else 0
            }
    
    def stop(self):
        self.running = False

# =============================================================================
# ЧАСТЬ 10: WHITELIST МЕНЕДЖЕР
# =============================================================================

class WhitelistManager:
    def __init__(self, whitelist_file: str = WHITELIST_FILE):
        self.whitelist_file = whitelist_file
        self.allowed_domains = set()
        self.allowed_patterns = []
        self.load_whitelist()
    
    def load_whitelist(self) -> bool:
        if not os.path.exists(self.whitelist_file):
            print(f"{YELLOW}⚠ Файл whitelist не найден: {self.whitelist_file}{RESET}")
            print(f"{YELLOW}  Все ресурсы будут считаться потенциально заблокированными{RESET}")
            return False
        
        try:
            with open(self.whitelist_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                
                if not line or line.startswith('#'):
                    continue
                
                if '#' in line:
                    line = line[:line.index('#')].strip()
                
                if not line:
                    continue
                
                if '*' in line:
                    pattern = line.replace('.', r'\.').replace('*', r'.*')
                    pattern = f"^{pattern}$"
                    try:
                        compiled = re.compile(pattern, re.IGNORECASE)
                        self.allowed_patterns.append((line, compiled))
                        continue
                    except:
                        pass
                
                self.allowed_domains.add(line.lower())
            
            total = len(self.allowed_domains) + len(self.allowed_patterns)
            print(f"{GREEN}✅ Загружено {total} разрешенных ресурсов: {len(self.allowed_domains)} доменов, "
                  f"{len(self.allowed_patterns)} паттернов{RESET}")
            
            return total > 0
            
        except Exception as e:
            print(f"{RED}❌ Ошибка загрузки whitelist: {e}{RESET}")
            return False
    
    def is_allowed(self, host: str) -> bool:
        if not host:
            return False
        
        host_lower = host.lower()
        
        if host_lower in self.allowed_domains:
            return True
        
        for pattern_name, pattern in self.allowed_patterns:
            if pattern.match(host_lower):
                return True
        
        parts = host_lower.split('.')
        for i in range(len(parts)):
            test_domain = '.'.join(parts[i:])
            if test_domain in self.allowed_domains:
                return True
        
        return False
    
    def is_blocked(self, host: str) -> bool:
        return not self.is_allowed(host)
    
    def categorize_urls(self, urls: List[str]) -> Tuple[List[Dict], List[Dict]]:
        allowed = []
        blocked = []
        
        for url in urls:
            try:
                parsed = urllib.parse.urlparse(url)
                host = parsed.netloc
                
                if self.is_allowed(host):
                    allowed.append({'url': url, 'host': host})
                else:
                    blocked.append({'url': url, 'host': host})
            except:
                blocked.append({'url': url, 'host': url})
        
        return allowed, blocked

# =============================================================================
# ЧАСТЬ 11: ПОЛНОЦЕННЫЙ ТЕСТЕР ПРОКСИ - ИСПРАВЛЕННЫЙ
# =============================================================================

class ProxyTester:
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.xray_binary = self._find_xray()
        self.temp_dir = TEMP_DIR
        os.makedirs(self.temp_dir, exist_ok=True)
        self.process = None
        self.location_detector = LocationDetector(verbose)
        self.freeze_detector = TCPFreezeDetector(verbose)
        self.mss_optimizer = MSSOptimizer(verbose)
        self.rtt_analyzer = RTTDiscrepancyAnalyzer(verbose)
        self.port_hunter = PortHunting(verbose)
        self.network_emulator = NetworkEmulator(verbose=verbose)
        self.test_urls = CONTROL_URLS + DEFAULT_BLOCKED_RESOURCES
    
    def _find_xray(self) -> Optional[str]:
        possible_paths = [
            "/usr/local/bin/xray",
            "/usr/bin/xray",
            "./xray",
            "xray",
            "/opt/xray/xray",
            "/tmp/xray",
            os.path.expanduser("~/xray"),
        ]
        
        for path in possible_paths:
            try:
                result = subprocess.run([path, "--version"],
                                      capture_output=True,
                                      text=True,
                                      timeout=2)
                if result.returncode == 0:
                    if self.verbose:
                        print(f"{GREEN}✓ Xray найден: {path}{RESET}")
                    return path
            except:
                continue
        
        print(f"{YELLOW}⚠ Xray не найден. Проверка будет ограничена{RESET}")
        return None
    
    def create_xray_config(self, proxy_info: Dict, mobile_profile: str = None,
                          custom_mss: int = None) -> Dict:
        protocol = proxy_info.get('protocol', 'vless')
        
        config = {
            "log": {"loglevel": "error"},
            "inbounds": [
                {
                    "port": XRAY_PORT,
                    "protocol": "socks",
                    "settings": {"auth": "noauth", "udp": False},
                    "sniffing": {"enabled": True, "destOverride": ["http", "tls"]}
                }
            ],
            "outbounds": [
                {
                    "protocol": protocol,
                    "settings": {},
                    "streamSettings": {
                        "network": proxy_info.get('type', 'tcp'),
                        "security": proxy_info.get('security', 'none')
                    }
                }
            ]
        }
        
        if protocol == 'vless':
            config['outbounds'][0]['settings'] = {
                "vnext": [{
                    "address": proxy_info.get('host', proxy_info.get('ip', '')),
                    "port": proxy_info.get('port', 0),
                    "users": [{
                        "id": proxy_info.get('uuid', ''),
                        "encryption": proxy_info.get('encryption', 'none'),
                        "flow": proxy_info.get('flow', '')
                    }]
                }]
            }
        elif protocol == 'vmess':
            config['outbounds'][0]['settings'] = {
                "vnext": [{
                    "address": proxy_info.get('host', proxy_info.get('ip', '')),
                    "port": proxy_info.get('port', 0),
                    "users": [{
                        "id": proxy_info.get('uuid', ''),
                        "alterId": proxy_info.get('aid', 0),
                        "security": proxy_info.get('scy', 'auto')
                    }]
                }]
            }
        elif protocol == 'trojan':
            config['outbounds'][0]['settings'] = {
                "servers": [{
                    "address": proxy_info.get('host', proxy_info.get('ip', '')),
                    "port": proxy_info.get('port', 0),
                    "password": proxy_info.get('uuid', '')
                }]
            }
        elif protocol == 'shadowsocks':
            config['outbounds'][0]['settings'] = {
                "servers": [{
                    "address": proxy_info.get('host', proxy_info.get('ip', '')),
                    "port": proxy_info.get('port', 0),
                    "method": proxy_info.get('method', 'chacha20-ietf-poly1305'),
                    "password": proxy_info.get('password', '')
                }]
            }
        elif protocol == 'hysteria2':
            config['outbounds'][0]['settings'] = {
                "vnext": [{
                    "address": proxy_info.get('host', proxy_info.get('ip', '')),
                    "port": proxy_info.get('port', 0),
                    "users": [{"password": proxy_info.get('uuid', '')}]
                }]
            }
        
        stream = config['outbounds'][0]['streamSettings']
        
        if proxy_info.get('security') == 'reality':
            stream['realitySettings'] = {
                "serverName": proxy_info.get('sni', proxy_info.get('host', '')),
                "fingerprint": proxy_info.get('fp', 'chrome'),
                "publicKey": proxy_info.get('pbk', ''),
                "shortId": proxy_info.get('sid', '')
            }
        elif proxy_info.get('security') == 'tls':
            stream['tlsSettings'] = {
                "serverName": proxy_info.get('sni', proxy_info.get('host', '')),
                "fingerprint": proxy_info.get('fp', 'chrome'),
                "allowInsecure": True
            }
        
        if proxy_info.get('type') == 'ws':
            ws_settings = {}
            if proxy_info.get('path'):
                ws_settings['path'] = proxy_info['path']
            if proxy_info.get('host_header'):
                ws_settings['headers'] = {"Host": proxy_info['host_header']}
            stream['wsSettings'] = ws_settings
        
        if proxy_info.get('type') == 'grpc' and proxy_info.get('serviceName'):
            stream['grpcSettings'] = {
                "serviceName": proxy_info['serviceName'],
                "multiMode": True
            }
        
        if 'sockopt' not in stream:
            stream['sockopt'] = {}
        if custom_mss:
            stream['sockopt']['tcpMaxSeg'] = custom_mss
        stream['sockopt']['tcpNoDelay'] = True
        
        if mobile_profile:
            config['mux'] = {
                'enabled': True,
                'concurrency': 8
            }
        
        return config
    
    def start_xray(self, config: Dict) -> bool:
        if not self.xray_binary:
            return False
        
        config_hash = hashlib.md5(json.dumps(config).encode()).hexdigest()[:8]
        config_path = os.path.join(self.temp_dir, f"xray_config_{config_hash}.json")
        
        with open(config_path, 'w') as f:
            json.dump(config, f, indent=2)
        
        try:
            self.process = subprocess.Popen(
                [self.xray_binary, '-c', config_path],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            
            time.sleep(1.5)
            
            if self.process.poll() is not None:
                return False
            
            return True
            
        except Exception as e:
            print(f"{RED}  Ошибка запуска Xray: {e}{RESET}")
            return False
    
    def stop_xray(self):
        if self.process:
            self.process.terminate()
            try:
                self.process.wait(timeout=2)
            except:
                self.process.kill()
            self.process = None
    
    def test_connection(self, url: str, timeout: int = 10) -> Tuple[bool, int, int, str]:
        start_time = time.time()
        
        try:
            proxy = f'127.0.0.1:{XRAY_PORT}'
            
            cmd = [
                'curl', '-s', '-o', '/dev/null', '-w', '%{http_code}',
                '--socks5-hostname', proxy,
                '--connect-timeout', str(timeout),
                '--max-time', str(timeout + 5),
                '--retry', '1',
                '--retry-delay', '1',
                url
            ]
            
            result = subprocess.run(
                cmd, 
                capture_output=True, 
                text=True, 
                timeout=timeout + 10
            )
            
            elapsed_ms = int((time.time() - start_time) * 1000)
            
            if result.returncode == 0 and result.stdout.strip():
                status_code = result.stdout.strip()
                try:
                    status_code_int = int(status_code)
                    if status_code_int in [200, 204, 301, 302, 307, 308]:
                        return True, elapsed_ms, status_code_int, None
                    else:
                        return False, elapsed_ms, status_code_int, f"HTTP {status_code}"
                except ValueError:
                    return False, elapsed_ms, 0, f"Invalid status: {status_code}"
            else:
                error_msg = result.stderr.strip() if result.stderr else "Unknown error"
                return False, elapsed_ms, 0, error_msg
                
        except subprocess.TimeoutExpired:
            return False, int((time.time() - start_time) * 1000), 0, "Timeout"
        except Exception as e:
            return False, int((time.time() - start_time) * 1000), 0, str(e)
    
    def test_proxy_full(self, proxy_url: str, task: Dict) -> Dict:
        proxy_id = task.get('proxy_id')
        
        proxy_info = parse_proxy_url(proxy_url)
        if not proxy_info:
            return {
                'proxy_id': proxy_id,
                'proxy_url': proxy_url,
                'success': False,
                'verdict': 'error',
                'error': 'Failed to parse proxy URL',
                'details': {}
            }
        
        proxy_info['ip'] = task.get('ip', proxy_info.get('host', ''))
        proxy_info['port'] = task.get('port', proxy_info.get('port', 0))
        proxy_info['country'] = task.get('country', 'Unknown')
        proxy_info['city'] = task.get('city', '')
        proxy_info['isp'] = task.get('isp', '')
        
        # Получаем страну и флаг из task
        country_code = task.get('country_code', 'XX')
        country_name = task.get('country', 'Unknown')
        flag = COUNTRY_FLAGS.get(country_code.upper(), '🇺🇳')
        city = task.get('city', '')
        
        print(f"\n{MAGENTA}{BOLD}🔍 ТЕСТ ДОСТУПА К ЗАБЛОКИРОВАННЫМ РЕСУРСАМ{RESET}")
        print(f"{MAGENTA}{'='*60}{RESET}")
        
        # Используем правильное отображение страны и флага
        if city and city != 'Unknown' and city.strip():
            print(f"Прокси: {flag} {city}, {country_name} X RAY")
        else:
            print(f"Прокси: {flag} {country_name} X RAY")
        print(f"Хост: {proxy_info.get('host', 'unknown')}:{proxy_info.get('port', 0)}")
        
        result = {
            'proxy_id': proxy_id,
            'proxy_url': proxy_url,
            'proxy_info': proxy_info,
            'ip': proxy_info.get('host', ''),
            'port': proxy_info.get('port', 0),
            'country': country_name,
            'country_code': country_code,
            'country_flag': flag,
            'city': city,
            'isp': task.get('isp', ''),
            'protocol': proxy_info.get('protocol', 'unknown'),
            'base_connection': {'success': False, 'latency_ms': 0},
            'whitelist_tests': [],
            'blocked_success': 0,
            'blocked_total': 0,
            'blocked_percent': 0,
            'success': False,
            'verdict': 'unknown',
            'details': {}
        }
        
        config = self.create_xray_config(proxy_info)
        if not self.start_xray(config):
            result['error'] = 'Xray startup failed'
            result['verdict'] = 'error'
            print(f"{RED}❌ Xray не запустился{RESET}")
            return result
        
        try:
            print(f"\n{CYAN}📋 Проверка базового соединения...{RESET}")
            
            base_success = False
            base_latency = 0
            base_error = None
            
            for url in CONTROL_URLS[:2]:
                success, latency, status_code, error = self.test_connection(url, timeout=8)
                if success:
                    base_success = True
                    base_latency = latency
                    break
                base_error = error
                time.sleep(0.5)
            
            result['base_connection'] = {
                'success': base_success,
                'latency_ms': base_latency,
                'error': None if base_success else base_error
            }
            result['base_connection_success'] = base_success
            result['latency_ms'] = base_latency
            
            if base_success:
                print(f"{GREEN}✓ Базовое соединение работает ({base_latency}ms){RESET}")
            else:
                print(f"{RED}❌ Базовое соединение не работает: {base_error}{RESET}")
                result['verdict'] = 'bad_base'
                result['error'] = f"Base connection failed: {base_error}"
                return result
            
            test_urls = task.get('test_urls', {})
            blocked_urls = test_urls.get('blocked', DEFAULT_BLOCKED_RESOURCES)
            
            if blocked_urls:
                print(f"\n{CYAN}🔍 Тестирование {len(blocked_urls)} ресурсов...{RESET}")
                
                blocked_success = 0
                whitelist_tests = []
                
                for i, url in enumerate(blocked_urls, 1):
                    try:
                        parsed = urllib.parse.urlparse(url)
                        domain = parsed.netloc
                        
                        start = time.time()
                        success, latency, status_code, error = self.test_connection(url, timeout=8)
                        elapsed_ms = latency
                        
                        test_result = {
                            'url': url,
                            'domain': domain,
                            'success': success,
                            'time': elapsed_ms,
                            'status_code': status_code,
                            'error': error
                        }
                        
                        if success:
                            status_symbol = "✅"
                            status_text = "ДОСТУПЕН"
                            status_color = GREEN
                            blocked_success += 1
                        else:
                            status_symbol = "❌"
                            status_text = "НЕДОСТУПЕН"
                            status_color = RED
                        
                        test_result['status_text'] = status_text
                        whitelist_tests.append(test_result)
                        
                        print(f"  [{i}/{len(blocked_urls)}] {status_color}{status_symbol} {url[:50]:50} | {elapsed_ms:4}ms | {status_text}{RESET}")
                        
                    except Exception as e:
                        whitelist_tests.append({
                            'url': url,
                            'success': False,
                            'time': 0,
                            'error': str(e)[:50],
                            'status_text': 'ОШИБКА'
                        })
                        print(f"  [{i}/{len(blocked_urls)}] {RED}❌ {url[:50]:50} | ОШИБКА{RESET}")
                
                result['whitelist_tests'] = whitelist_tests
                result['blocked_success'] = blocked_success
                result['blocked_total'] = len(blocked_urls)
                result['blocked_percent'] = int((blocked_success / len(blocked_urls)) * 100) if blocked_urls else 0
                
                print(f"\n{CYAN}{'='*60}{RESET}")
                print(f"{BOLD}ИТОГИ ТЕСТА:{RESET}")
                print(f"{CYAN}{'='*60}{RESET}")
                
                if blocked_urls:
                    bypass_ratio = result['blocked_percent']
                    print(f"🚫 Доступ к заблокированным ресурсам: {blocked_success}/{len(blocked_urls)} ({bypass_ratio}%)")
                    
                    if bypass_ratio >= 80:
                        print(f"  {GREEN}✓ Отличный обход блокировок!{RESET}")
                        result['verdict'] = 'good'
                        result['success'] = True
                    elif bypass_ratio >= 50:
                        print(f"  {YELLOW}⚠ Средний обход блокировок{RESET}")
                        result['verdict'] = 'good'
                        result['success'] = True
                    else:
                        print(f"  {RED}✗ Плохой обход блокировок{RESET}")
                        result['verdict'] = 'bad'
                        result['success'] = False
                    
                    if bypass_ratio >= 80:
                        marker = "🚀"
                        color = GREEN
                    elif bypass_ratio >= 50:
                        marker = "👍"
                        color = YELLOW
                    else:
                        marker = "👎"
                        color = RED
                    
                    print(f"    {color}Итог: {marker} {blocked_success}/{len(blocked_urls)} доступны ({bypass_ratio}%){RESET}")
            
            if self.verbose and result['success']:
                socks5_proxy = f"socks5://127.0.0.1:{XRAY_PORT}"
                freeze_result = self.freeze_detector.test_freeze(socks5_proxy)
                if freeze_result.get('freeze_detected'):
                    print(f"{YELLOW}  ⚠ Обнаружено замораживание TCP!{RESET}")
                    result['freeze_detected'] = True
                    result['freeze_details'] = freeze_result
            
        finally:
            self.stop_xray()
        
        return result

# =============================================================================
# ЧАСТЬ 12: HTTP HANDLER ДЛЯ КООРДИНАТОРА
# =============================================================================

class CoordinatorHandler(BaseHTTPRequestHandler):
    coordinator = None
    
    def log_message(self, format, *args):
        if self.coordinator and self.coordinator.verbose:
            try:
                print(f"{BLUE}[{datetime.now().strftime('%H:%M:%S')}] {format % args}{RESET}")
            except:
                pass
    
    def send_json_response(self, data: Dict, status: int = 200):
        try:
            response_data = json.dumps(data, ensure_ascii=False).encode('utf-8')
            
            self.send_response(status)
            self.send_header('Content-Type', 'application/json; charset=utf-8')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Content-Length', str(len(response_data)))
            self.end_headers()
            
            self.wfile.write(response_data)
            self.wfile.flush()
            
        except (BrokenPipeError, ConnectionError, ConnectionResetError) as e:
            if self.coordinator and self.coordinator.verbose:
                print(f"{YELLOW}⚠ Клиент разорвал соединение: {e}{RESET}")
        except Exception as e:
            if self.coordinator and self.coordinator.verbose:
                print(f"{RED}❌ Ошибка отправки ответа: {e}{RESET}")
    
    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            
            if path == '/task':
                self.handle_get_task()
            elif path == '/stats':
                self.handle_get_stats()
            elif path == '/progress':
                self.handle_get_progress()
            elif path == '/health':
                self.handle_health()
            else:
                self.send_json_response({'error': 'Not found'}, 404)
        except Exception as e:
            print(f"{RED}Ошибка в do_GET: {e}{RESET}")
            traceback.print_exc()
            self.send_json_response({'error': str(e)}, 500)
    
    def do_POST(self):
        try:
            parsed = urlparse(self.path)
            path = parsed.path
            
            if path == '/result':
                self.handle_post_result()
            else:
                self.send_json_response({'error': 'Not found'}, 404)
        except Exception as e:
            print(f"{RED}Ошибка в do_POST: {e}{RESET}")
            traceback.print_exc()
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_get_task(self):
        try:
            query = parse_qs(urlparse(self.path).query)
            checker_id = query.get('checker_id', [None])[0]
            
            if not checker_id:
                checker_id = self.headers.get('X-Checker-ID')
            
            if not checker_id:
                checker_id = f"box_{socket.gethostname()}_{int(time.time())}"
            
            # Создаем новый цикл событий для каждого запроса
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                task = loop.run_until_complete(self.coordinator.get_task(checker_id))
            finally:
                loop.close()
            
            if task:
                self.send_json_response({
                    'success': True,
                    'task': task
                })
            else:
                self.send_json_response({
                    'success': False,
                    'message': 'No tasks available'
                }, 404)
        except Exception as e:
            print(f"{RED}Ошибка в handle_get_task: {e}{RESET}")
            traceback.print_exc()
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_post_result(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            data = json.loads(post_data.decode('utf-8'))
            
            checker_id = self.headers.get('X-Checker-ID') or data.get('checker_id')
            
            if not checker_id:
                self.send_json_response({'error': 'Missing checker_id'}, 400)
                return
            
            # Создаем новый цикл событий для каждого запроса
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                success = loop.run_until_complete(self.coordinator.process_result(checker_id, data))
            finally:
                loop.close()
            
            if success:
                self.send_json_response({'success': True})
            else:
                self.send_json_response({'success': False, 'error': 'Processing failed'}, 500)
                
        except json.JSONDecodeError as e:
            print(f"{RED}Ошибка JSON: {e}{RESET}")
            self.send_json_response({'error': 'Invalid JSON'}, 400)
        except Exception as e:
            print(f"{RED}Ошибка в handle_post_result: {e}{RESET}")
            traceback.print_exc()
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_get_stats(self):
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                stats = loop.run_until_complete(self.coordinator.get_stats())
            finally:
                loop.close()
            self.send_json_response(stats)
        except Exception as e:
            print(f"{RED}Ошибка в handle_get_stats: {e}{RESET}")
            traceback.print_exc()
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_get_progress(self):
        try:
            progress = self.coordinator.get_progress()
            self.send_json_response(progress)
        except Exception as e:
            print(f"{RED}Ошибка в handle_get_progress: {e}{RESET}")
            traceback.print_exc()
            self.send_json_response({'error': str(e)}, 500)
    
    def handle_health(self):
        self.send_json_response({
            'status': 'ok',
            'timestamp': datetime.now().isoformat(),
            'version': '3.2.0'
        })

# =============================================================================
# ЧАСТЬ 13: КООРДИНАТОР (ЦЕНТРАЛЬНЫЙ СЕРВЕР) - С АВТОВОССТАНОВЛЕНИЕМ
# =============================================================================

class Coordinator:
    def __init__(self, host: str = COORDINATOR_BIND_HOST, port: int = COORDINATOR_PORT, 
                 verbose: bool = True, threshold: int = THRESHOLD_PERCENT,
                 config_dir: str = None, auto_boxes: int = 10, detect_location: bool = True):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.threshold = threshold
        self.config_dir = config_dir
        self.auto_boxes = auto_boxes
        self.detect_location = detect_location
        self.running = True
        self.server = None
        
        self.main_db = MainDatabaseManager()
        self.check_db = CheckDatabaseManager()
        
        if config_dir:
            self.proxy_list = ProxyListManager(config_dir, verbose)
        else:
            print(f"{YELLOW}⚠ Не указана директория с конфигами. Используйте --config-dir{RESET}")
            self.proxy_list = ProxyListManager(".", verbose)
        
        self.whitelist = WhitelistManager()
        self.allowed_resources, self.blocked_resources = self.whitelist.categorize_urls(
            DEFAULT_BLOCKED_RESOURCES
        )
        
        self.stats = {
            'tasks_given': 0,
            'results_received': 0,
            'working_proxies': 0,
            'bad_proxies': 0,
            'active_checkers': set(),
            'start_time': datetime.now().isoformat()
        }
        
        self.cleanup_thread = threading.Thread(target=self._cleanup_worker, daemon=True)
        self.cleanup_thread.start()
        
        self.box_processes = []
        self.box_monitor_thread = threading.Thread(target=self._monitor_boxes, daemon=True)
        self.box_monitor_thread.start()
        
        if self.verbose:
            self._print_startup_info()
    
    def _print_startup_info(self):
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{BOLD}{MAGENTA}🚀 КООРДИНАТОР ЗАПУЩЕН (Мульти-API геолокация + AutoBox + Автовосстановление){RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"{GREEN}✅ Координатор инициализирован{RESET}")
        print(f"  • Хост для прослушивания: {self.host}")
        print(f"  • Порт: {self.port}")
        print(f"  • URL для подключения: http://127.0.0.1:{self.port}")
        print(f"  • Порог обхода: {self.threshold}%")
        print(f"  • Директория с конфигами: {self.config_dir}")
        print(f"  • Автоматических ящиков: {self.auto_boxes}")
        print(f"  • Определение локации: {'включено (5 API)' if self.detect_location else 'отключено'}")
        print(f"  • Тестовых ресурсов: {len(DEFAULT_BLOCKED_RESOURCES)}")
        print(f"  • Заблокированных: {len(self.blocked_resources)}")
        print(f"{CYAN}{'='*70}{RESET}")
    
    def _monitor_boxes(self):
        """Мониторинг и перезапуск упавших ящиков"""
        while self.running:
            time.sleep(30)  # Проверяем каждые 30 секунд
            
            if not self.box_processes:
                continue
            
            for i, process in enumerate(self.box_processes[:], 1):
                if process.poll() is not None:  # Процесс завершился
                    print(f"{YELLOW}⚠ Ящик #{i} (PID: {process.pid}) упал, перезапускаю...{RESET}")
                    
                    try:
                        script_path = os.path.abspath(__file__)
                        coordinator_url = f"http://127.0.0.1:{self.port}"
                        box_id = f"autobox_{i}_{int(time.time())}"
                        
                        if platform.system().lower() == 'windows':
                            new_process = subprocess.Popen(
                                [sys.executable, script_path, 'blackbox', 
                                 '--coordinator', coordinator_url,
                                 '--id', box_id,
                                 '--verbose' if self.verbose else '--quiet'],
                                stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT,
                                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                            )
                        else:
                            stdout_dest = None if self.verbose else subprocess.DEVNULL
                            stderr_dest = None if self.verbose else subprocess.DEVNULL
                            
                            new_process = subprocess.Popen(
                                [sys.executable, script_path, 'blackbox',
                                 '--coordinator', coordinator_url,
                                 '--id', box_id,
                                 '--verbose' if self.verbose else '--quiet'],
                                stdout=stdout_dest,
                                stderr=stderr_dest,
                                start_new_session=True
                            )
                        
                        # Заменяем старый процесс новым
                        index = self.box_processes.index(process)
                        self.box_processes[index] = new_process
                        print(f"{GREEN}  ✓ Ящик #{i} перезапущен (новый PID: {new_process.pid}){RESET}")
                        
                    except Exception as e:
                        print(f"{RED}  ✗ Ошибка перезапуска ящика #{i}: {e}{RESET}")
    
    def _start_auto_boxes(self):
        print(f"\n{GREEN}🚀 Запуск {self.auto_boxes} автоматических черных ящиков...{RESET}")
        
        script_path = os.path.abspath(__file__)
        coordinator_url = f"http://127.0.0.1:{self.port}"
        
        # Даем серверу время полностью инициализироваться
        time.sleep(2)
        
        for i in range(1, self.auto_boxes + 1):
            try:
                box_id = f"autobox_{i}_{int(time.time())}"
                
                if platform.system().lower() == 'windows':
                    process = subprocess.Popen(
                        [sys.executable, script_path, 'blackbox', 
                         '--coordinator', coordinator_url,
                         '--id', box_id,
                         '--verbose' if self.verbose else '--quiet'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
                    )
                else:
                    # Перенаправляем stdout/stderr в /dev/null если не verbose
                    stdout_dest = None if self.verbose else subprocess.DEVNULL
                    stderr_dest = None if self.verbose else subprocess.DEVNULL
                    
                    process = subprocess.Popen(
                        [sys.executable, script_path, 'blackbox',
                         '--coordinator', coordinator_url,
                         '--id', box_id,
                         '--verbose' if self.verbose else '--quiet'],
                        stdout=stdout_dest,
                        stderr=stderr_dest,
                        start_new_session=True
                    )
                
                self.box_processes.append(process)
                print(f"{GREEN}  ✓ Ящик #{i} (PID: {process.pid}) запущен{RESET}")
                time.sleep(0.5)
                
            except Exception as e:
                print(f"{RED}  ✗ Ошибка запуска ящика #{i}: {e}{RESET}")
        
        print(f"{GREEN}✅ Запущено {len(self.box_processes)} черных ящиков{RESET}")
    
    def _cleanup_boxes(self):
        for process in self.box_processes:
            try:
                process.terminate()
                process.wait(timeout=5)
            except:
                try:
                    process.kill()
                except:
                    pass
        self.box_processes.clear()
    
    async def init_databases(self):
        await self.main_db.init_database()
        await self.check_db.init_database()
    
    def _cleanup_worker(self):
        while self.running:
            try:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                cleaned = loop.run_until_complete(self.check_db.clean_expired_locks())
                loop.close()
                
                if cleaned > 0 and self.verbose:
                    print(f"{YELLOW}🧹 Очищено {cleaned} истекших блокировок{RESET}")
                time.sleep(CLEANUP_INTERVAL)
            except Exception as e:
                if self.verbose:
                    print(f"{RED}Ошибка в cleanup worker: {e}{RESET}")
                time.sleep(CLEANUP_INTERVAL)
    
    async def get_task(self, checker_id: str) -> Optional[Dict]:
        try:
            self.stats['active_checkers'].add(checker_id)
            
            next_proxy = self.proxy_list.get_next_proxy()
            if not next_proxy:
                return None
            
            proxy_url, proxy_id = next_proxy
            
            # ПОЛУЧАЕМ ЛОКАЦИЮ ДО ВЫДАЧИ ЗАДАЧИ
            location = None
            country = 'Unknown'
            country_code = 'XX'
            city = ''
            isp = ''
            
            if self.detect_location:
                parsed = parse_proxy_url(proxy_url)
                if parsed and parsed.get('host'):
                    try:
                        socket.inet_aton(parsed['host'])
                        detector = LocationDetector(verbose=False)
                        location = detector.get_location(parsed['host'])
                        if location:
                            country = location.get('country', 'Unknown')
                            country_code = location.get('country_code', 'XX')
                            city = location.get('city', '')
                            isp = location.get('isp', '')
                            if self.verbose:
                                flag = COUNTRY_FLAGS.get(country_code, '🇺🇳')
                                if city and city.strip():
                                    print(f"{GREEN}📍 Прокси {proxy_id}: {flag} {city}, {country}{RESET}")
                                else:
                                    print(f"{GREEN}📍 Прокси {proxy_id}: {flag} {country}{RESET}")
                    except socket.error:
                        pass
            
            task = {
                'proxy_id': proxy_id,
                'proxy_url': proxy_url,
                'test_urls': {
                    'control': CONTROL_URLS,
                    'blocked': [r['url'] for r in self.blocked_resources]
                },
                'timeout': LOCK_TIMEOUT,
                'threshold': self.threshold,
                'country': country,
                'country_code': country_code,
                'city': city,
                'isp': isp,
                'country_flag': COUNTRY_FLAGS.get(country_code, '🇺🇳')
            }
            
            if not await self.check_db.acquire_lock(proxy_id, checker_id, task):
                return None
            
            self.stats['tasks_given'] += 1
            
            if self.verbose:
                flag = COUNTRY_FLAGS.get(country_code, '🇺🇳')
                if city and city.strip():
                    location_str = f"{flag} {city}, {country}"
                else:
                    location_str = f"{flag} {country}"
                
                print(f"{GREEN}📤 Задача #{proxy_id} ({location_str}) выдана ящику {checker_id}{RESET}")
                progress = self.proxy_list.get_progress()
                print(f"  Прогресс: {progress['processed']}/{progress['total']} "
                      f"({progress['percent']:.1f}%)")
            
            return task
        except Exception as e:
            print(f"{RED}Ошибка в get_task: {e}{RESET}")
            traceback.print_exc()
            return None
    
    async def process_result(self, checker_id: str, data: Dict) -> bool:
        try:
            proxy_id = data.get('proxy_id')
            proxy_url = data.get('proxy_url')
            result = data.get('result', {})
            
            if not proxy_id or not proxy_url:
                if self.verbose:
                    print(f"{RED}❌ Результат без proxy_id или proxy_url от {checker_id}{RESET}")
                return False
            
            verdict = result.get('verdict')
            
            await self.check_db.save_check_result(proxy_id, checker_id, proxy_url, result)
            await self.check_db.release_lock(proxy_id, checker_id)
            self.proxy_list.mark_processed()
            
            if verdict == 'good':
                # Создаем location из данных результата
                location = {
                    'country': result.get('country', 'Unknown'),
                    'country_code': result.get('country_code', 'XX'),
                    'country_flag': result.get('country_flag', '🇺🇳'),
                    'city': result.get('city', ''),
                    'isp': result.get('isp', '')
                }
                
                if await self.main_db.add_working_proxy(proxy_url, result, location):
                    self.stats['working_proxies'] += 1
                    if self.verbose:
                        flag = location.get('country_flag', '🇺🇳')
                        city = location.get('city', '')
                        country = location.get('country', 'Unknown')
                        if city and city.strip():
                            location_str = f"{flag} {city}, {country}"
                        else:
                            location_str = f"{flag} {country}"
                        
                        print(f"{GREEN}✅ Прокси #{proxy_id} РАБОЧЕЕ - сохранено в БД "
                              f"({result.get('blocked_percent', 0)}% обход, "
                              f"{result.get('latency_ms', 0)}ms) [{location_str} X RAY]{RESET}")
                else:
                    if self.verbose:
                        print(f"{YELLOW}⚠ Прокси #{proxy_id} рабочее, но не сохранено в БД{RESET}")
            else:
                self.stats['bad_proxies'] += 1
                if self.verbose:
                    reason = "плохой обход" if verdict == 'bad' else "базовое соединение"
                    print(f"{RED}❌ Прокси #{proxy_id} НЕРАБОЧЕЕ ({reason}){RESET}")
            
            self.stats['results_received'] += 1
            
            progress = self.proxy_list.get_progress()
            if progress['remaining'] == 0 and self.verbose:
                print(f"\n{GREEN}{'='*70}{RESET}")
                print(f"{BOLD}🎉 ВСЕ ПРОКСИ ПРОВЕРЕНЫ!{RESET}")
                print(f"{GREEN}{'='*70}{RESET}")
                print(f"  Всего проверено: {progress['total']}")
                print(f"  Рабочих прокси: {self.stats['working_proxies']}")
                print(f"  Нерабочих прокси: {self.stats['bad_proxies']}")
                print(f"{GREEN}{'='*70}{RESET}\n")
            
            return True
            
        except Exception as e:
            if self.verbose:
                print(f"{RED}Ошибка обработки результата: {e}{RESET}")
                traceback.print_exc()
            return False
    
    async def get_stats(self) -> Dict:
        try:
            runtime = datetime.now() - datetime.fromisoformat(self.stats['start_time'])
            
            proxy_stats = await self.main_db.get_stats()
            progress = self.proxy_list.get_progress()
            
            return {
                'coordinator': {
                    'tasks_given': self.stats['tasks_given'],
                    'results_received': self.stats['results_received'],
                    'working_proxies': self.stats['working_proxies'],
                    'bad_proxies': self.stats['bad_proxies'],
                    'active_checkers': len(self.stats['active_checkers']),
                    'uptime_seconds': int(runtime.total_seconds()),
                    'uptime_human': str(runtime).split('.')[0],
                    'config_dir': self.config_dir,
                    'auto_boxes': self.auto_boxes
                },
                'progress': progress,
                'database': {
                    'total_proxies': proxy_stats.get('total', 0),
                    'avg_latency': round(proxy_stats.get('avg_latency', 0), 1),
                    'avg_bypass': round(proxy_stats.get('avg_blocked_percent', 0), 1)
                },
                'checkers': list(self.stats['active_checkers'])
            }
        except Exception as e:
            print(f"{RED}Ошибка в get_stats: {e}{RESET}")
            traceback.print_exc()
            return {}
    
    def get_progress(self) -> Dict:
        try:
            return self.proxy_list.get_progress()
        except Exception as e:
            print(f"{RED}Ошибка в get_progress: {e}{RESET}")
            return {'total': 0, 'processed': 0, 'remaining': 0, 'percent': 0}
    
    def run(self):
        # Сначала инициализируем базы данных
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.init_databases())
        loop.close()
        
        # СОЗДАЕМ сервер
        handler = CoordinatorHandler
        handler.coordinator = self
        
        # Запускаем сервер в отдельном потоке, чтобы можно было мониторить его состояние
        def run_server():
            try:
                self.server = HTTPServer((self.host, self.port), handler)
                print(f"\n{CYAN}{'='*70}{RESET}")
                print(f"{BOLD}{MAGENTA}🚀 КООРДИНАТОР ЗАПУЩЕН И ГОТОВ К РАБОТЕ (Мульти-API геолокация){RESET}")
                print(f"{CYAN}{'='*70}{RESET}")
                print(f"📍 Адрес для прослушивания: http://{self.host}:{self.port}")
                print(f"📍 Адрес для подключения: http://127.0.0.1:{self.port}")
                print(f"📋 Эндпоинты API:")
                print(f"   • GET  /task?checker_id=XXX - получить задачу")
                print(f"   • POST /result - отправить результат")
                print(f"   • GET  /stats - статистика")
                print(f"   • GET  /progress - прогресс обработки")
                print(f"   • GET  /health - проверка здоровья")
                print(f"\n📊 Всего прокси для проверки: {self.proxy_list.total}")
                print(f"🤖 Автоматических ящиков: {self.auto_boxes}")
                print(f"{CYAN}{'='*70}{RESET}\n")
                
                self.server.serve_forever()
            except Exception as e:
                if self.running:
                    print(f"{RED}❌ Ошибка сервера: {e}{RESET}")
                    traceback.print_exc()
        
        server_thread = threading.Thread(target=run_server, daemon=True)
        server_thread.start()
        
        # Даем серверу время запуститься
        time.sleep(2)
        
        # ЗАПУСКАЕМ ящики
        if self.auto_boxes > 0:
            self._start_auto_boxes()
        
        # Основной цикл мониторинга
        try:
            while self.running:
                time.sleep(10)
                # Проверяем, жив ли сервер
                if not server_thread.is_alive():
                    print(f"{RED}❌ Сервер остановился!{RESET}")
                    break
        except KeyboardInterrupt:
            print(f"\n{YELLOW}🛑 Остановка координатора...{RESET}")
        finally:
            self.running = False
            self.proxy_list.stop()
            if self.server:
                self.server.shutdown()
            self._cleanup_boxes()
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            stats = loop.run_until_complete(self.get_stats())
            loop.close()
            
            self._print_final_stats(stats)
    
    def _print_final_stats(self, stats):
        print(f"\n{GREEN}{'='*70}{RESET}")
        print(f"{BOLD}📊 ИТОГОВАЯ СТАТИСТИКА{RESET}")
        print(f"{GREEN}{'='*70}{RESET}")
        print(f"  Проверено прокси: {stats['progress']['processed']}/{stats['progress']['total']}")
        print(f"  Рабочих прокси: {stats['coordinator']['working_proxies']}")
        print(f"  Нерабочих прокси: {stats['coordinator']['bad_proxies']}")
        print(f"  Активных ящиков: {stats['coordinator']['active_checkers']}")
        print(f"  Время работы: {stats['coordinator']['uptime_human']}")
        print(f"\n  Рабочие прокси сохранены в: {MAIN_DB_FILE}")
        print(f"{GREEN}{'='*70}{RESET}")

# =============================================================================
# ЧАСТЬ 14: ЧЕРНЫЙ ЯЩИК (АГЕНТ) - С АВТОВОССТАНОВЛЕНИЕМ
# =============================================================================

class BlackBox:
    def __init__(self, checker_id: str, coordinator_url: str, 
                 verbose: bool = True, threshold: int = THRESHOLD_PERCENT):
        self.checker_id = checker_id
        self.coordinator_url = coordinator_url.rstrip('/')
        self.verbose = verbose
        self.threshold = threshold
        self.running = True
        
        self.check_db = CheckDatabaseManager()
        self.tester = ProxyTester(verbose=verbose)
        
        self.stats = {
            'tasks_processed': 0,
            'successful': 0,
            'failed': 0,
            'errors': 0,
            'consecutive_errors': 0,
            'start_time': datetime.now().isoformat()
        }
        
        # Настраиваем сессию с повторными попытками если requests доступен
        if REQUESTS_AVAILABLE:
            self.session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            self.session.mount("http://", adapter)
            self.session.mount("https://", adapter)
        else:
            self.session = None
        
        os.makedirs(VPN_JSON_DIR, exist_ok=True)
    
    def print_header(self):
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{BOLD}{MAGENTA}📦 ЧЕРНЫЙ ЯЩИК #{self.checker_id}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        print(f"📍 Координатор: {self.coordinator_url}")
        print(f"🔄 Интервал опроса: {POLL_INTERVAL}с")
        print(f"📊 Порог обхода: {self.threshold}%")
        print(f"🔄 Автовосстановление: включено")
        print(f"{CYAN}{'='*70}{RESET}\n")
    
    async def init(self):
        await self.check_db.init_database()
    
    def check_coordinator_health(self) -> bool:
        """Проверка доступности координатора"""
        try:
            if self.session:
                response = self.session.get(
                    f"{self.coordinator_url}/health",
                    timeout=5,
                    verify=False
                )
                return response.status_code == 200
            else:
                cmd = ['curl', '-s', '-o', '/dev/null', '-w', '%{http_code}', 
                       '--max-time', '5', f"{self.coordinator_url}/health"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=6)
                return result.stdout.strip() == '200'
        except:
            return False
    
    def wait_for_coordinator(self):
        """Ожидание восстановления координатора"""
        print(f"{YELLOW}⚠ Координатор недоступен, ожидание восстановления...{RESET}")
        attempts = 0
        
        while self.running and attempts < MAX_RECONNECT_ATTEMPTS:
            time.sleep(RECONNECT_DELAY)
            if self.check_coordinator_health():
                print(f"{GREEN}✅ Соединение с координатором восстановлено{RESET}")
                self.stats['consecutive_errors'] = 0
                return True
            attempts += 1
            print(f"{YELLOW}  Попытка {attempts}/{MAX_RECONNECT_ATTEMPTS}...{RESET}")
        
        print(f"{RED}❌ Не удалось восстановить соединение с координатором{RESET}")
        return False
    
    def get_task(self) -> Optional[Dict]:
        try:
            headers = {'X-Checker-ID': self.checker_id}
            
            if self.session:
                try:
                    response = self.session.get(
                        f"{self.coordinator_url}/task",
                        headers=headers,
                        timeout=10,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        data = response.json()
                        if data.get('success'):
                            self.stats['consecutive_errors'] = 0
                            return data.get('task')
                    elif response.status_code == 404:
                        # Нет задач - это нормально
                        self.stats['consecutive_errors'] = 0
                        return None
                except requests.exceptions.RequestException as e:
                    if self.verbose:
                        print(f"{YELLOW}⚠ Ошибка подключения к координатору: {e}{RESET}")
                    self.stats['consecutive_errors'] += 1
                    return None
            else:
                cmd = ['curl', '-s', '-k', '-H', f'X-Checker-ID: {self.checker_id}', 
                       '--max-time', '10', f"{self.coordinator_url}/task"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=12)
                if result.returncode == 0 and result.stdout:
                    try:
                        data = json.loads(result.stdout)
                        if data.get('success'):
                            self.stats['consecutive_errors'] = 0
                            return data.get('task')
                    except:
                        pass
                self.stats['consecutive_errors'] += 1
            
            return None
            
        except Exception as e:
            if self.verbose:
                print(f"{RED}❌ Ошибка получения задачи: {e}{RESET}")
            self.stats['consecutive_errors'] += 1
            return None
    
    def send_result(self, proxy_id: str, proxy_url: str, result: Dict) -> bool:
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            report_file = os.path.join(VPN_JSON_DIR, f"report_{self.checker_id}_{timestamp}_{proxy_id}.json")
            with open(report_file, 'w', encoding='utf-8') as f:
                json.dump(result, f, indent=2, ensure_ascii=False)
            
            data = {
                'checker_id': self.checker_id,
                'proxy_id': proxy_id,
                'proxy_url': proxy_url,
                'result': result,
                'timestamp': datetime.now().isoformat()
            }
            
            headers = {'X-Checker-ID': self.checker_id}
            
            if self.session:
                try:
                    response = self.session.post(
                        f"{self.coordinator_url}/result",
                        json=data,
                        headers=headers,
                        timeout=30,
                        verify=False
                    )
                    
                    if response.status_code == 200:
                        result_data = response.json()
                        if result_data.get('success'):
                            self.stats['consecutive_errors'] = 0
                            if self.verbose:
                                print(f"{GREEN}💾 Отчет сохранен в: {report_file}{RESET}")
                            return True
                except Exception as e:
                    if self.verbose:
                        print(f"{RED}❌ Ошибка отправки результата: {e}{RESET}")
                    self.stats['consecutive_errors'] += 1
                    return False
            else:
                data_str = json.dumps(data)
                cmd = ['curl', '-s', '-k', '-X', 'POST', 
                       '-H', 'Content-Type: application/json',
                       '-H', f'X-Checker-ID: {self.checker_id}',
                       '-d', data_str,
                       '--max-time', '30',
                       f"{self.coordinator_url}/result"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=35)
                if result.returncode == 0:
                    try:
                        resp_data = json.loads(result.stdout)
                        if resp_data.get('success'):
                            self.stats['consecutive_errors'] = 0
                            if self.verbose:
                                print(f"{GREEN}💾 Отчет сохранен в: {report_file}{RESET}")
                            return True
                    except:
                        pass
                self.stats['consecutive_errors'] += 1
            
            return False
            
        except Exception as e:
            if self.verbose:
                print(f"{RED}❌ Ошибка отправки результата: {e}{RESET}")
            self.stats['consecutive_errors'] += 1
            return False
    
    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self.init())
        loop.close()
        
        self.print_header()
        
        while self.running:
            try:
                # Проверяем доступность координатора
                if not self.check_coordinator_health():
                    if not self.wait_for_coordinator():
                        break
                
                if self.stats['consecutive_errors'] >= MAX_CONSECUTIVE_ERRORS:
                    print(f"{RED}❌ Слишком много ошибок подряд ({MAX_CONSECUTIVE_ERRORS}). Переподключение...{RESET}")
                    if not self.wait_for_coordinator():
                        break
                    self.stats['consecutive_errors'] = 0
                
                task = self.get_task()
                
                if task:
                    proxy_id = task['proxy_id']
                    proxy_url = task['proxy_url']
                    self.stats['consecutive_errors'] = 0
                    
                    # Получаем информацию о местоположении для отображения
                    country = task.get('country', 'Unknown')
                    country_code = task.get('country_code', 'XX')
                    city = task.get('city', '')
                    flag = COUNTRY_FLAGS.get(country_code.upper(), '🇺🇳')
                    
                    if city and city.strip():
                        location_str = f"{flag} {city}, {country}"
                    else:
                        location_str = f"{flag} {country}"
                    
                    print(f"\n{CYAN}{'='*70}{RESET}")
                    print(f"{BOLD}{MAGENTA}📦 ПОЛУЧЕНА ЗАДАЧА {proxy_id}{RESET}")
                    print(f"{CYAN}{'='*70}{RESET}")
                    print(f"Локация: {location_str}")
                    print(f"Прокси: {proxy_url[:100]}...")
                    
                    result = self.tester.test_proxy_full(proxy_url, task)
                    
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    loop.run_until_complete(self.check_db.save_check_result(proxy_id, self.checker_id, proxy_url, result))
                    loop.close()
                    
                    if self.send_result(proxy_id, proxy_url, result):
                        self.stats['tasks_processed'] += 1
                        if result.get('verdict') == 'good':
                            self.stats['successful'] += 1
                            verdict_color = GREEN
                            verdict_text = "РАБОЧЕЕ"
                        else:
                            self.stats['failed'] += 1
                            verdict_color = RED
                            verdict_text = "НЕРАБОЧЕЕ"
                        
                        print(f"\n{verdict_color}{'='*70}{RESET}")
                        print(f"{verdict_color}{verdict_text} Прокси {proxy_id} "
                              f"(обход {result.get('blocked_percent', 0)}%, "
                              f"{result.get('latency_ms', 0)}ms) [{location_str} X RAY]{RESET}")
                        print(f"{verdict_color}{'='*70}{RESET}")
                    else:
                        self.stats['errors'] += 1
                        print(f"{RED}❌ Не удалось отправить результат координатору{RESET}")
                    
                    print(f"\n{YELLOW}⏳ Пауза {POLL_INTERVAL}с перед следующим запросом...{RESET}")
                    time.sleep(POLL_INTERVAL)
                else:
                    if self.verbose:
                        dots = "." * (int(time.time()) % 4)
                        print(f"{YELLOW}⏳ Нет задач. Ожидание {POLL_INTERVAL}с{dots:<4}{RESET}", end='\r')
                    time.sleep(POLL_INTERVAL)
                
            except KeyboardInterrupt:
                print(f"\n{YELLOW}🛑 Остановка черного ящика...{RESET}")
                break
            except Exception as e:
                self.stats['consecutive_errors'] += 1
                self.stats['errors'] += 1
                if self.verbose:
                    print(f"{RED}❌ Необработанная ошибка: {e}{RESET}")
                    traceback.print_exc()
                time.sleep(POLL_INTERVAL)
        
        self.print_stats()
    
    def print_stats(self):
        print(f"\n{CYAN}{'='*70}{RESET}")
        print(f"{BOLD}{MAGENTA}📊 СТАТИСТИКА ЧЕРНОГО ЯЩИКА #{self.checker_id}{RESET}")
        print(f"{CYAN}{'='*70}{RESET}")
        
        runtime = datetime.now() - datetime.fromisoformat(self.stats['start_time'])
        hours = runtime.total_seconds() / 3600
        
        print(f"⏱️  Время работы: {str(runtime).split('.')[0]}")
        print(f"📋 Обработано задач: {self.stats['tasks_processed']}")
        print(f"{GREEN}✅ Рабочих прокси: {self.stats['successful']}{RESET}")
        print(f"{RED}❌ Нерабочих прокси: {self.stats['failed']}{RESET}")
        print(f"{YELLOW}⚠ Ошибок: {self.stats['errors']}{RESET}")
        
        if self.stats['tasks_processed'] > 0:
            success_rate = (self.stats['successful'] / self.stats['tasks_processed']) * 100
            print(f"\n{BOLD}📈 Процент рабочих: {success_rate:.1f}%{RESET}")
            print(f"⚡ Скорость: {self.stats['tasks_processed'] / hours:.1f} задач/час")
        
        print(f"{CYAN}{'='*70}{RESET}")

# =============================================================================
# ЧАСТЬ 15: ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# =============================================================================

def signal_handler(sig, frame):
    print(f"\n\n{RED}Прервано пользователем{RESET}")
    kill_all_cores_manual()
    sys.exit(0)

def generate_checker_id() -> str:
    hostname = socket.gethostname()
    pid = os.getpid()
    timestamp = int(time.time())
    return f"box_{hostname}_{pid}_{timestamp}"

def check_dependencies() -> bool:
    missing = []
    
    try:
        subprocess.run(['curl', '--version'], capture_output=True, check=True)
    except:
        missing.append('curl')
    
    try:
        import base64
    except:
        missing.append('base64 (встроенный модуль Python)')
    
    try:
        import aiosqlite
    except:
        missing.append('aiosqlite (установите: pip install aiosqlite)')
    
    try:
        import requests
    except:
        missing.append('requests (установите: pip install requests)')
    
    if missing:
        print(f"{YELLOW}⚠ Отсутствуют: {', '.join(missing)}{RESET}")
        print(f"{YELLOW}  Некоторые функции могут не работать{RESET}")
        return False
    
    return True

def create_whitelist_example():
    if not os.path.exists(WHITELIST_FILE):
        example = """# Разрешенные ресурсы (WHITELIST)
# Ресурсы из этого списка считаются "разрешенными"
# Программа будет тестировать доступ к ресурсам НЕ из этого списка

# Поисковики и облачные сервисы
google.com
yandex.ru
mail.ru
cloudflare.com

# Социальные сети (разрешенные в РФ)
vk.com
ok.ru

# Новостные сайты
ria.ru
lenta.ru
rbc.ru

# Видеохостинги
rutube.ru

# Wildcard паттерны
*.google.com
*.yandex.ru
"""
        with open(WHITELIST_FILE, 'w', encoding='utf-8') as f:
            f.write(example)
        print(f"{GREEN}✅ Создан пример файла {WHITELIST_FILE}{RESET}")

def test_location():
    """Тестирование определения геолокации"""
    print(f"{CYAN}{'='*70}{RESET}")
    print(f"{BOLD}🔍 ТЕСТИРОВАНИЕ ГЕОЛОКАЦИИ (Мульти-API){RESET}")
    print(f"{CYAN}{'='*70}{RESET}")
    
    detector = LocationDetector(verbose=True)
    
    test_ips = [
        '8.8.8.8',        # Google DNS
        '1.1.1.1',        # Cloudflare DNS
        '77.88.8.8',      # Yandex DNS
        '194.226.96.100', # Ukraine
        '217.69.139.200', # Germany
    ]
    
    for ip in test_ips:
        print(f"\n{YELLOW}Тестируем IP: {ip}{RESET}")
        location = detector.get_location(ip)
        print(f"  Результат: {location['country_flag']} {location['country']} / {location['city']}")
        print(f"  Код: {location['country_code']}, ISP: {location['isp']}")
        print(f"  Источник: {location.get('source', 'unknown')}")
        time.sleep(1)
    
    print(f"\n{GREEN}✅ Тест завершен{RESET}")

# =============================================================================
# ЧАСТЬ 16: ТОЧКА ВХОДА
# =============================================================================

def main():
    signal.signal(signal.SIGINT, signal_handler)
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='📦 DB CLEANER PRO v3.2.0 - Распределенная система проверки прокси',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='mode', help='Режим работы')
    
    coord_parser = subparsers.add_parser('coordinator', help='Запуск координатора')
    coord_parser.add_argument('--host', default=COORDINATOR_BIND_HOST, 
                              help=f'Хост для прослушивания (по умолчанию: {COORDINATOR_BIND_HOST})')
    coord_parser.add_argument('--port', type=int, default=COORDINATOR_PORT, 
                              help=f'Порт (по умолчанию: {COORDINATOR_PORT})')
    coord_parser.add_argument('--config-dir', required=True,
                              help='Директория с .txt файлами конфигов прокси')
    coord_parser.add_argument('-t', '--threshold', type=int, default=THRESHOLD_PERCENT,
                              help=f'Порог обхода блокировок в % (по умолчанию: {THRESHOLD_PERCENT})')
    coord_parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    coord_parser.add_argument('--create-whitelist', action='store_true', 
                              help='Создать пример файла whitelist.txt')
    coord_parser.add_argument('--auto-boxes', type=int, default=10,
                              help='Количество автоматически запускаемых черных ящиков (по умолчанию: 10)')
    coord_parser.add_argument('--no-location', action='store_true',
                              help='Отключить определение геолокации (ускоряет работу)')
    
    box_parser = subparsers.add_parser('blackbox', help='Запуск черного ящика')
    box_parser.add_argument('--coordinator', default=f"http://127.0.0.1:{COORDINATOR_PORT}", 
                            help=f'URL координатора (по умолчанию: http://127.0.0.1:{COORDINATOR_PORT})')
    box_parser.add_argument('--id', help='ID черного ящика (генерируется автоматически если не указан)')
    box_parser.add_argument('-t', '--threshold', type=int, default=THRESHOLD_PERCENT,
                            help=f'Порог обхода блокировок в % (по умолчанию: {THRESHOLD_PERCENT})')
    box_parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    box_parser.add_argument('--interval', type=int, default=POLL_INTERVAL,
                            help=f'Интервал опроса в секундах (по умолчанию: {POLL_INTERVAL})')
    box_parser.add_argument('--quiet', action='store_true', help='Минимальный вывод (подавляет verbose)')
    
    test_parser = subparsers.add_parser('test-location', help='Тестирование определения геолокации')
    test_parser.add_argument('-v', '--verbose', action='store_true', help='Подробный вывод')
    
    args = parser.parse_args()
    
    # Проверяем зависимости
    check_dependencies()
    
    if hasattr(args, 'create_whitelist') and args.create_whitelist:
        create_whitelist_example()
        if args.mode == 'coordinator' and not args.verbose:
            return
    
    if args.mode == 'coordinator':
        print(f"{GREEN}🚀 Запуск в режиме КООРДИНАТОРА (Мульти-API геолокация + AutoBox + Автовосстановление){RESET}")
        
        if not args.config_dir:
            print(f"{RED}❌ Не указана директория с конфигами. Используйте --config-dir{RESET}")
            sys.exit(1)
        
        verbose = args.verbose
        
        coordinator = Coordinator(
            host=args.host,
            port=args.port,
            verbose=verbose,
            threshold=args.threshold,
            config_dir=args.config_dir,
            auto_boxes=args.auto_boxes,
            detect_location=not args.no_location
        )
        
        try:
            coordinator.run()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{RED}❌ Ошибка координатора: {e}{RESET}")
            traceback.print_exc()
            sys.exit(1)
    
    elif args.mode == 'blackbox':
        print(f"{GREEN}📦 Запуск в режиме ЧЕРНОГО ЯЩИКА (Автовосстановление){RESET}")
        
        checker_id = args.id if args.id else generate_checker_id()
        
        verbose = args.verbose and not args.quiet
        
        blackbox = BlackBox(
            checker_id=checker_id,
            coordinator_url=args.coordinator,
            verbose=verbose,
            threshold=args.threshold
        )
        
        try:
            blackbox.run()
        except KeyboardInterrupt:
            pass
        except Exception as e:
            print(f"{RED}❌ Ошибка черного ящика: {e}{RESET}")
            traceback.print_exc()
            sys.exit(1)
    
    elif args.mode == 'test-location':
        test_location()
        return
    
    else:
        parser.print_help()
        print(f"\n{YELLOW}⚠ Укажите режим работы: coordinator, blackbox или test-location{RESET}")
        sys.exit(1)

if __name__ == '__main__':
    main()