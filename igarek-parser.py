#!/usr/bin/env python3
"""
Парсер и агрегатор публичных VLESS/VMESS/Trojan/SS конфигов.

Логика:
  1. Тянем сырые файлы из источников, поделённых на две категории:
       - black: обычный обход DPI-блокировок (YouTube, Discord, соцсети и т.п.)
       - white: обход белых списков (мобильный "шатдаун", позитивный список адресов)
  2. Парсим строки вида vless://..., vmess://..., trojan://..., ss://...
     (умеем распознать как обычный plaintext-список, так и файл,
     целиком закодированный в base64).
  3. Дедуплицируем.
  4. Собираем единый файл: сначала black-раздел с "плашкой"-разделителем,
     потом white-раздел со своей плашкой.
  5. Пишем результат в output/combined.txt (plain) и output/combined_base64.txt
     (некоторым клиентам нужна именно base64-подписка целиком).

Простой формат конфигурации источников — см. SOURCES ниже.
"""

import base64
import re
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import quote
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

# ---------------------------------------------------------------------------
# Настройки
# ---------------------------------------------------------------------------

# Метки-разделители, которые превращаются в фейковый vless:// узел.
# Клиент (NekoBox/v2rayNG/…) отобразит его просто как ещё один "сервер"
# с таким именем — по факту не рабочий (127.0.0.1:1080), но глазами
# читается как заголовок секции.
LABEL_BLACK = "Обычные сервера⬇️"
LABEL_WHITE = "Обходы БС⬇️"

DUMMY_TEMPLATE = "vless://999999@127.0.0.1:1080/?type=tcp&encryption=none&flow=&packetEncoding=none#{label}"

# Источники: ключ "black" или "white" -> список raw-ссылок на txt-файлы.
# Добавляй сюда любые свои источники — формат минимальный, всё само
# распарсится в общий список.
SOURCES = {
    "black": [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_VLESS_RUS_mobile.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS%2BAll_RUS.txt",
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/BLACK_SS_WEAK_DPI_RUS.txt",
    ],
    "white": [
        "https://raw.githubusercontent.com/igareck/vpn-configs-for-russia/main/Vless-Reality-White-Lists-Rus-Mobile.txt",
    ],
}

# Поддерживаемые схемы прокси-ссылок
PROXY_SCHEMES = ("vless://", "vmess://", "trojan://", "ss://", "ssr://", "hysteria2://", "hy2://", "tuic://")

REQUEST_TIMEOUT = 20
USER_AGENT = "vpn-parser/1.0 (+https://github.com/)"


@dataclass
class FetchStats:
    source: str
    ok: bool
    count: int = 0
    error: str = ""


@dataclass
class ParseResult:
    black: list = field(default_factory=list)
    white: list = field(default_factory=list)
    stats: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# Сеть
# ---------------------------------------------------------------------------

def fetch_text(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT})
    with urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
        raw = resp.read()
    return raw.decode("utf-8", errors="ignore")


def fetch_with_retry(url: str, retries: int = 3, backoff: float = 2.0) -> str:
    last_err = None
    for attempt in range(1, retries + 1):
        try:
            return fetch_text(url)
        except (URLError, HTTPError, TimeoutError) as e:
            last_err = e
            if attempt < retries:
                time.sleep(backoff * attempt)
    raise RuntimeError(f"failed after {retries} attempts: {last_err}")


# ---------------------------------------------------------------------------
# Парсинг
# ---------------------------------------------------------------------------

def looks_like_base64_blob(text: str) -> bool:
    """Эвристика: если в тексте почти нет строк, начинающихся с известной
    схемы, но текст выглядит как одна большая base64-строка — считаем,
    что весь файл закодирован целиком (так делают некоторые агрегаторы)."""
    stripped = text.strip()
    if not stripped:
        return False
    if any(scheme in stripped for scheme in PROXY_SCHEMES):
        # уже есть открытые ссылки — не нужно ничего декодировать
        return False
    sample = re.sub(r"\s+", "", stripped)
    return bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", sample)) and len(sample) > 40


def decode_base64_blob(text: str) -> str:
    sample = re.sub(r"\s+", "", text.strip())
    # base64url -> base64 стандартный, плюс паддинг
    sample = sample.replace("-", "+").replace("_", "/")
    sample += "=" * (-len(sample) % 4)
    try:
        return base64.b64decode(sample).decode("utf-8", errors="ignore")
    except Exception:
        return ""


def extract_proxy_uris(text: str) -> list:
    if looks_like_base64_blob(text):
        decoded = decode_base64_blob(text)
        if decoded:
            text = decoded

    uris = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(PROXY_SCHEMES):
            uris.append(line)
    return uris


def dedupe(uris: list) -> list:
    seen = set()
    result = []
    for u in uris:
        # ключ дедупликации — без фрагмента (#имя), т.к. имена у разных
        # источников на один и тот же сервер могут отличаться
        key = u.split("#", 1)[0]
        if key not in seen:
            seen.add(key)
            result.append(u)
    return result


def build_dummy(label: str) -> str:
    return DUMMY_TEMPLATE.format(label=quote(label, safe=""))


# ---------------------------------------------------------------------------
# Основной прогон
# ---------------------------------------------------------------------------

def collect() -> ParseResult:
    result = ParseResult()
    for category, urls in SOURCES.items():
        bucket = result.black if category == "black" else result.white
        for url in urls:
            try:
                text = fetch_with_retry(url)
                uris = extract_proxy_uris(text)
                bucket.extend(uris)
                result.stats.append(FetchStats(url, True, len(uris)))
                print(f"[ok]   {category:5} {len(uris):4} configs  <- {url}")
            except Exception as e:  # noqa: BLE001
                result.stats.append(FetchStats(url, False, error=str(e)))
                print(f"[fail] {category:5} {url}: {e}", file=sys.stderr)

    result.black = dedupe(result.black)
    result.white = dedupe(result.white)
    return result


def render(result: ParseResult) -> str:
    lines = []
    lines.append(build_dummy(LABEL_BLACK))
    lines.extend(result.black)
    lines.append(build_dummy(LABEL_WHITE))
    lines.extend(result.white)
    return "\n".join(lines) + "\n"


def main() -> int:
    result = collect()

    if not result.black and not result.white:
        print("Ни одного конфига не удалось получить — прерываю, "
              "чтобы не перезаписать рабочий файл пустотой.", file=sys.stderr)
        return 1

    plain = render(result)

    with open("output/igarek-configs-parser.txt", "w", encoding="utf-8") as f:
        f.write(plain)

    b64 = base64.b64encode(plain.encode("utf-8")).decode("ascii")
    with open("output/combined_base64.txt", "w", encoding="utf-8") as f:
        f.write(b64)

    total = len(result.black) + len(result.white)
    print(f"\nГотово: {len(result.black)} black + {len(result.white)} white = {total} конфигов")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
