#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
import re
import urllib.parse
import base64
import concurrent.futures
from datetime import datetime
import argparse
import sys
import os
from typing import List, Dict, Optional, Tuple

try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ==========================================
# ИСТОЧНИКИ КОНФИГОВ (vless://, vmess://, ...)
# ==========================================
SOURCES = {
    "RKP": [
        "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/blacklist.txt",
        "https://gitverse.ru/api/repos/RKP_channel/RKP_bypass_configs/raw/branch/master/whitelist.txt"
    ],
    "EtoNeYa": ["https://etoneya.best/whitelist"],
    "BYWARM": ["https://gitverse.ru/api/repos/bywarm/rser/raw/branch/master/selected.txt"],
    "ByeWhite": ["https://raw.githubusercontent.com/ByeWhiteLists/ByeWhiteLists2/refs/heads/main/ByeWhiteLists2.txt"],
}

# ==========================================
# ОТДЕЛЬНЫЙ СПИСОК РЕПОЗИТОРИЕВ С БЕЛЫМИ SNI
# (ТОЛЬКО ДОМЕНЫ, БЕЗ КОНФИГОВ)
# ==========================================
WHITELIST_SOURCES = [
    "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/refs/heads/main/WHITE-SNI-RU.txt",
    "https://gitverse.ru/api/repos/RKP_channel/RKP_bypass_configs/raw/branch/master/whitelist.txt",
    "https://raw.githubusercontent.com/RKPchannel/RKP_bypass_configs/refs/heads/main/whitelist.txt",
    "https://raw.githubusercontent.com/SomeUser/whitelist/main/whitelist.txt",  # новый источник
]

# --- Базовый белый список (запасной, если не удалось загрузить) ---
DEFAULT_WHITE_SNI_LIST = [
    "gosuslugi.ru", "gov.ru", "kremlin.ru", "yandex.ru", "vk.com", "mail.ru",
    "ok.ru", "rambler.ru", "sberbank.ru", "tinkoff.ru", "vtb.ru",
]

WHITE_SNI_LIST = DEFAULT_WHITE_SNI_LIST.copy()

# ==========================================
# БАЗА ФЛАГОВ (не меняется)
# ==========================================
FLAG_DB = {
    "🇪🇺": "Europe", "🇦🇫": "Afghanistan", "🇦🇱": "Albania", "🇩🇿": "Algeria",
    "🇦🇸": "American Samoa", "🇦🇩": "Andorra", "🇦🇴": "Angola", "🇦🇮": "Anguilla",
    "🇦🇶": "Antarctica", "🇦🇬": "Antigua", "🇦🇷": "Argentina", "🇦🇲": "Armenia",
    "🇦🇼": "Aruba", "🇦🇺": "Australia", "🇦🇹": "Austria", "🇦🇿": "Azerbaijan",
    "🇧🇸": "Bahamas", "🇧🇭": "Bahrain", "🇧🇩": "Bangladesh", "🇧🇧": "Barbados",
    "🇧🇾": "Belarus", "🇧🇪": "Belgium", "🇧🇿": "Belize", "🇧🇯": "Benin",
    "🇧🇲": "Bermuda", "🇧🇹": "Bhutan", "🇧🇴": "Bolivia", "🇧🇦": "Bosnia",
    "🇧🇼": "Botswana", "🇧🇷": "Brazil", "🇻🇬": "British Virgin Islands",
    "🇧🇳": "Brunei", "🇧🇬": "Bulgaria", "🇧🇫": "Burkina Faso", "🇧🇮": "Burundi",
    "🇰🇭": "Cambodia", "🇨🇲": "Cameroon", "🇨🇦": "Canada", "🇨🇻": "Cape Verde",
    "🇰🇾": "Cayman Islands", "🇨🇫": "Central African Republic", "🇹🇩": "Chad",
    "🇨🇱": "Chile", "🇨🇳": "China", "🇨🇴": "Colombia", "🇰🇲": "Comoros",
    "🇨🇬": "Congo", "🇨🇰": "Cook Islands", "🇨🇷": "Costa Rica", "🇭🇷": "Croatia",
    "🇨🇺": "Cuba", "🇨🇾": "Cyprus", "🇨🇿": "Czechia", "🇩🇰": "Denmark",
    "🇩🇯": "Djibouti", "🇩🇲": "Dominica", "🇩🇴": "Dominican Republic",
    "🇪🇨": "Ecuador", "🇪🇬": "Egypt", "🇸🇻": "El Salvador",
    "🇬🇶": "Equatorial Guinea", "🇪🇷": "Eritrea", "🇪🇪": "Estonia",
    "🇪🇹": "Ethiopia", "🇫🇯": "Fiji", "🇫🇮": "Finland", "🇫🇷": "France",
    "🇬🇦": "Gabon", "🇬🇲": "Gambia", "🇬🇪": "Georgia", "🇩🇪": "Germany",
    "🇬🇭": "Ghana", "🇬🇮": "Gibraltar", "🇬🇷": "Greece", "🇬🇱": "Greenland",
    "🇬🇩": "Grenada", "🇬🇵": "Guadeloupe", "🇬🇺": "Guam", "🇬🇹": "Guatemala",
    "🇬🇳": "Guinea", "🇬🇼": "Guinea-Bissau", "🇬🇾": "Guyana", "🇭🇹": "Haiti",
    "🇭🇳": "Honduras", "🇭🇰": "Hong Kong", "🇭🇺": "Hungary", "🇮🇸": "Iceland",
    "🇮🇳": "India", "🇮🇩": "Indonesia", "🇮🇷": "Iran", "🇮🇶": "Iraq",
    "🇮🇪": "Ireland", "🇮🇲": "Isle of Man", "🇮🇱": "Israel", "🇮🇹": "Italy",
    "🇯🇲": "Jamaica", "🇯🇵": "Japan", "🇯🇪": "Jersey", "🇯🇴": "Jordan",
    "🇰🇿": "Kazakhstan", "🇰🇪": "Kenya", "🇰🇮": "Kiribati", "🇰🇼": "Kuwait",
    "🇰🇬": "Kyrgyzstan", "🇱🇦": "Laos", "🇱🇻": "Latvia", "🇱🇧": "Lebanon",
    "🇱🇸": "Lesotho", "🇱🇷": "Liberia", "🇱🇾": "Libya", "🇱🇮": "Liechtenstein",
    "🇱🇹": "Lithuania", "🇱🇺": "Luxembourg", "🇲🇴": "Macau", "🇲🇰": "Macedonia",
    "🇲🇬": "Madagascar", "🇲🇼": "Malawi", "🇲🇾": "Malaysia", "🇲🇻": "Maldives",
    "🇲🇱": "Mali", "🇲🇹": "Malta", "🇲🇭": "Marshall Islands", "🇲🇶": "Martinique",
    "🇲🇷": "Mauritania", "🇲🇺": "Mauritius", "🇲🇽": "Mexico", "🇫🇲": "Micronesia",
    "🇲🇩": "Moldova", "🇲🇨": "Monaco", "🇲🇳": "Mongolia", "🇲🇪": "Montenegro",
    "🇲🇸": "Montserrat", "🇲🇦": "Morocco", "🇲🇿": "Mozambique", "🇲🇲": "Myanmar",
    "🇳🇦": "Namibia", "🇳🇷": "Nauru", "🇳🇵": "Nepal", "🇳🇱": "Netherlands",
    "🇳🇨": "New Caledonia", "🇳🇿": "New Zealand", "🇳🇮": "Nicaragua",
    "🇳🇪": "Niger", "🇳🇬": "Nigeria", "🇳🇺": "Niue", "🇳🇫": "Norfolk Island",
    "🇲🇵": "Northern Mariana Islands", "🇰🇵": "North Korea", "🇳🇴": "Norway",
    "🇴🇲": "Oman", "🇵🇰": "Pakistan", "🇵🇼": "Palau", "🇵🇸": "Palestine",
    "🇵🇦": "Panama", "🇵🇬": "Papua New Guinea", "🇵🇾": "Paraguay", "🇵🇪": "Peru",
    "🇵🇭": "Philippines", "🇵🇳": "Pitcairn Islands", "🇵🇱": "Poland",
    "🇵🇹": "Portugal", "🇵🇷": "Puerto Rico", "🇶🇦": "Qatar", "🇷🇪": "Reunion",
    "🇷🇴": "Romania", "🇷🇺": "Russia", "🇷🇼": "Rwanda", "🇼🇸": "Samoa",
    "🇸🇲": "San Marino", "🇸🇹": "Sao Tome", "🇸🇦": "Saudi Arabia", "🇸🇳": "Senegal",
    "🇷🇸": "Serbia", "🇸🇨": "Seychelles", "🇸🇱": "Sierra Leone", "🇸🇬": "Singapore",
    "🇸🇽": "Sint Maarten", "🇸🇰": "Slovakia", "🇸🇮": "Slovenia",
    "🇸🇧": "Solomon Islands", "🇸🇴": "Somalia", "🇿🇦": "South Africa",
    "🇰🇷": "South Korea", "🇸🇸": "South Sudan", "🇪🇸": "Spain", "🇱🇰": "Sri Lanka",
    "🇸🇩": "Sudan", "🇸🇷": "Suriname", "🇸🇿": "Swaziland", "🇸🇪": "Sweden",
    "🇨🇭": "Switzerland", "🇸🇾": "Syria", "🇹🇼": "Taiwan", "🇹🇯": "Tajikistan",
    "🇹🇿": "Tanzania", "🇹🇭": "Thailand", "🇹🇱": "Timor-Leste", "🇹🇬": "Togo",
    "🇹🇰": "Tokelau", "🇹🇴": "Tonga", "🇹🇹": "Trinidad", "🇹🇳": "Tunisia",
    "🇹🇷": "Turkey", "🇹🇲": "Turkmenistan", "🇹🇨": "Turks and Caicos",
    "🇹🇻": "Tuvalu", "🇺🇬": "Uganda", "🇺🇦": "Ukraine", "🇦🇪": "UAE",
    "🇬🇧": "UK", "🇺🇸": "USA", "🇺🇾": "Uruguay", "🇺🇿": "Uzbekistan",
    "🇻🇺": "Vanuatu", "🇻🇦": "Vatican City", "🇻🇪": "Venezuela", "🇻🇳": "Vietnam",
    "🇼🇫": "Wallis and Futuna", "🇪🇭": "Western Sahara", "🇾🇪": "Yemen",
    "🇿🇲": "Zambia", "🇿🇼": "Zimbabwe"
}

# ==========================================
# УТИЛИТЫ
# ==========================================
def extract_domain_from_link(link: str) -> Optional[str]:
    """Извлекает домен (SNI) из прокси-ссылки."""
    proto_end = link.find("://")
    if proto_end == -1:
        return None
    rest = link[proto_end+3:]
    if '@' in rest:
        host_part = rest.split('@', 1)[1]
    else:
        host_part = rest
    host_part = host_part.split(':')[0]
    host_part = host_part.split('/')[0]
    host_part = host_part.split('?')[0]
    return host_part if host_part else None

def is_whitelist_domain(domain: str, whitelist: List[str]) -> bool:
    """Проверяет, входит ли домен в белый список (точное совпадение или суффикс)."""
    if not domain:
        return False
    domain = domain.lower().strip()
    for w in whitelist:
        w = w.lower()
        if domain == w or domain.endswith('.' + w):
            return True
    return False

def load_whitelist_from_sources(sources: List[str]) -> List[str]:
    """Загружает белые SNI из указанных репозиториев (только домены)."""
    whitelist = set()
    for url in sources:
        try:
            resp = requests.get(url, timeout=10, headers={'User-Agent': 'Mozilla/5.0'})
            if resp.status_code == 200:
                lines = resp.text.splitlines()
                for line in lines:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        domain = line.split(' ')[0].split('#')[0].strip()
                        if domain:
                            whitelist.add(domain)
            else:
                print(f"⚠️ HTTP {resp.status_code} при загрузке белого списка из {url}", file=sys.stderr)
        except Exception as e:
            print(f"⚠️ Не удалось загрузить белый список из {url}: {e}", file=sys.stderr)
    return list(whitelist)

# ==========================================
# ОСНОВНОЙ КЛАСС ПАРСЕРА
# ==========================================
class UltraParser:
    def __init__(self, sources_dict: dict, whitelist_sources: Optional[List[str]] = None,
                 max_per_source: int = 0, show_progress: bool = True):
        self.sources_dict = sources_dict
        self.whitelist_sources = whitelist_sources if whitelist_sources else []
        self.max_per_source = max_per_source
        self.buckets = {auth: [] for auth in sources_dict.keys()}
        self.counters = {auth: 1 for auth in sources_dict.keys()}
        self.whitelist = DEFAULT_WHITE_SNI_LIST.copy()
        self.show_progress = show_progress and HAS_TQDM and not os.environ.get('CI')

        # --- ШАГ 2: Загружаем белый SNI из репозиториев ---
        if self.whitelist_sources:
            print("🔄 Загрузка белого SNI из репозиториев (только домены)...")
            loaded = load_whitelist_from_sources(self.whitelist_sources)
            if loaded:
                self.whitelist = loaded
                print(f"✅ Загружено {len(self.whitelist)} доменов белого списка")
            else:
                print("⚠️ Не удалось загрузить белый список, использую встроенный базовый")
        else:
            print("ℹ️ Белый список не загружается (используется встроенный)")

    def decode_display_name(self, raw_name: str, link: str, author: str) -> str:
        """Формирует имя для ссылки, проверяя домен по белому списку."""
        # Особый случай для EtoNeYa
        if author == "EtoNeYa":
            name = f"🏳 White lists #{self.counters[author]} | EtoNeYa | Ваш котенок ❤"
            self.counters[author] += 1
            return name

        # --- ШАГ 3: Проверяем домен конфига по белому списку ---
        domain = extract_domain_from_link(link)
        is_white = is_whitelist_domain(domain, self.whitelist) if domain else False
        white_tag = " 🏳️ White list" if is_white else ""

        # Определяем флаг (по имени)
        found_flags = re.findall(r'[\U0001F1E6-\U0001F1FF]{2}', raw_name)
        if found_flags:
            flag = found_flags[0]
            country = FLAG_DB.get(flag, "Location")
            label = f"{flag} {country}"
        elif "anycast" in raw_name.lower():
            label = "🌐 Anycast"
        else:
            label = "🌐 Unknown"

        name = f"{label} | {author} #{self.counters[author]}{white_tag} | Ваш котенок ❤"
        self.counters[author] += 1
        return name

    def fetch_and_parse(self, author: str, urls: List[str]):
        """Загружает конфиги из источников (ШАГ 1)."""
        for url in urls:
            try:
                resp = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
                if resp.status_code != 200:
                    continue
                content = resp.text

                # Если нет ссылок, пробуем Base64
                if not any(p in content for p in ["vless://", "ss://", "vmess://", "trojan://", "tuic://", "hysteria2://"]):
                    try:
                        content = base64.b64decode(content).decode('utf-8')
                    except:
                        pass

                # Извлекаем ссылки
                links = re.findall(r'(?:vless|vmess|ss|trojan|tuic|hysteria2)://[^\r\n\t\s]+', content)
                for l in links:
                    l = l.strip()
                    if '#' in l:
                        clean_link, raw_name = l.split("#", 1)
                    else:
                        clean_link, raw_name = l, ""
                    if clean_link:
                        decoded_name = urllib.parse.unquote(raw_name)
                        self.buckets[author].append({
                            "link": clean_link,
                            "name": decoded_name
                        })
            except Exception as e:
                print(f"❌ Ошибка при загрузке {author} из {url}: {e}", file=sys.stderr)

    def run(self, output_file: str = "subscription.txt", max_total: int = 0):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🥪 Сборка подписки...")

        # --- ШАГ 1: Сбор конфигов ---
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = []
            for auth, urls in self.sources_dict.items():
                futures.append(executor.submit(self.fetch_and_parse, auth, urls))
            for f in concurrent.futures.as_completed(futures):
                pass

        # Удаление дубликатов внутри каждого источника
        for auth in self.buckets:
            seen = set()
            unique = []
            for item in self.buckets[auth]:
                if item["link"] not in seen:
                    seen.add(item["link"])
                    unique.append(item)
            self.buckets[auth] = unique

        # Ограничения
        if self.max_per_source > 0:
            for auth in self.buckets:
                if len(self.buckets[auth]) > self.max_per_source:
                    self.buckets[auth] = self.buckets[auth][:self.max_per_source]

        authors = list(self.buckets.keys())
        total_collected = sum(len(self.buckets[a]) for a in authors)
        print(f"📊 Собрано {total_collected} уникальных ссылок из {len(authors)} источников")

        if max_total > 0 and total_collected > max_total:
            for auth in authors:
                current = len(self.buckets[auth])
                if current == 0:
                    continue
                new_count = max(1, int(current * max_total / total_collected))
                self.buckets[auth] = self.buckets[auth][:new_count]
            total_collected = sum(len(self.buckets[a]) for a in authors)
            print(f"✂️ Урезано до {total_collected} ссылок (по лимиту {max_total})")

        # --- ШАГ 4: Формирование подписки (с пометкой белых) ---
        final_list = []
        global_count = 0
        white_count = 0
        while any(self.buckets[a] for a in authors):
            for a in authors:
                chunk = self.buckets[a][:10]
                self.buckets[a] = self.buckets[a][10:]
                for item in chunk:
                    display = self.decode_display_name(item["name"], item["link"], a)
                    if "🏳️ White list" in display:
                        white_count += 1
                    safe_display = urllib.parse.quote(display)
                    final_list.append(f"{item['link']}#{safe_display}")
                    global_count += 1
                    if global_count % 20 == 0:
                        final_list.append("")

        if final_list:
            content = "\n".join(final_list)
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            b64_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
            b64_file = output_file.replace(".txt", "_b64.txt")
            with open(b64_file, "w", encoding="utf-8") as f:
                f.write(b64_content)
            print(f"✅ Готово! Сохранено в {output_file} ({len(final_list)} строк)")
            print(f"   Из них помечено как белые: {white_count}")
            print(f"✅ Base64 сохранён в {b64_file}")
        else:
            print("❌ Не найдено ни одной ссылки!")

# ==========================================
# ЗАПУСК
# ==========================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Парсер прокси-конфигов с отдельным белым списком")
    parser.add_argument("--output", "-o", default="subscription.txt", help="Выходной файл (plain)")
    parser.add_argument("--max-total", type=int, default=0, help="Максимальное общее количество ссылок (0 - без ограничения)")
    parser.add_argument("--max-per-source", type=int, default=0, help="Максимум ссылок от одного источника (0 - без ограничения)")
    parser.add_argument("--no-whitelist", action="store_true", help="Не загружать белый список (использовать встроенный)")
    args = parser.parse_args()

    whitelist_sources = None
    if not args.no_whitelist:
        whitelist_sources = WHITELIST_SOURCES  # отдельные репозитории с SNI

    parser_obj = UltraParser(SOURCES, whitelist_sources=whitelist_sources,
                             max_per_source=args.max_per_source,
                             show_progress=True)
    parser_obj.run(output_file=args.output, max_total=args.max_total)
