import datetime
import json
import os

KNOWN_DEVICES = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...": "user1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...": "admin",
}

TRUSTED_IP_RANGES = [
    "127.0.0.1",
    "192.168.",
    "10.0.",
    "::1",
]

HEADLESS_UA_MARKERS = [
    "HeadlessChrome", "PhantomJS", "Selenium", "python-requests",
    "curl/", "wget/", "Go-http-client", "scrapy",
]

LOGS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
LOG_FILE = os.path.join(LOGS_DIR, "device_logs.txt")


def _ensure_log_dir():
    os.makedirs(LOGS_DIR, exist_ok=True)


def is_trusted_ip(ip):
    return any(ip.startswith(r) for r in TRUSTED_IP_RANGES)


def is_known_device(ua):
    return ua in KNOWN_DEVICES


def is_outdated_browser(ua):
    return any(marker in ua for marker in ["Chrome/5", "Firefox/3", "MSIE", "Trident/4", "Trident/5"])


def _detect_automation(data):
    """Return a list of automation/bot signal names found in the data."""
    signals = []

    if data.get("webdriver") is True:
        signals.append("webdriver_flag")

    plugin_count = data.get("plugin_count")
    if plugin_count is not None and int(plugin_count) == 0:
        signals.append("no_plugins")

    hw = data.get("hardware_concurrency")
    if hw is not None and int(hw) == 0:
        signals.append("zero_cpu_cores")

    ua = data.get("user_agent", "")
    for marker in HEADLESS_UA_MARKERS:
        if marker.lower() in ua.lower():
            signals.append(f"ua_marker:{marker}")
            break

    # Touch inconsistency: mobile UA but no touch support
    if data.get("touch_support") is False and "Mobile" in ua:
        signals.append("mobile_ua_no_touch")

    return signals


def calculate_trust_score(data):
    score = 0
    risk = []
    positive = []

    ip = data.get("ip_address", "")
    ua = data.get("user_agent", "")

    # Normalise language: accept either 'language' (string) or 'languages' (list)
    lang = data.get("language") or data.get("languages") or ""
    if isinstance(lang, list):
        lang = lang[0] if lang else ""
    lang = str(lang)

    tz = data.get("timezone", "")
    w  = int(data.get("screen_width",  0) or 0)
    h  = int(data.get("screen_height", 0) or 0)

    # --- Positive signals ---

    if is_trusted_ip(ip):
        score += 30
        positive.append("Trusted IP range")
    else:
        risk.append("Unrecognised IP range")

    if is_known_device(ua):
        score += 30
        positive.append("Known device fingerprint")

    if ua and not is_outdated_browser(ua):
        score += 20
        positive.append("Modern browser")
    elif is_outdated_browser(ua):
        score -= 10
        risk.append("Outdated browser detected")

    if lang.lower().startswith("en") and "Africa" in tz:
        score += 10
        positive.append("Consistent locale (Africa/English)")
    elif lang and tz:
        score -= 5
        risk.append("Language/timezone mismatch")

    hw = int(data.get("hardware_concurrency", 0) or 0)
    if hw >= 2:
        score += 5
        positive.append(f"Multi-core CPU ({hw} cores)")
    elif hw == 1:
        risk.append("Single-core CPU (uncommon for real devices)")

    if data.get("canvas_fingerprint"):
        score += 5
        positive.append("Canvas fingerprint available")

    if data.get("plugin_count") is not None and int(data.get("plugin_count", 0)) > 0:
        score += 5
        positive.append("Browser plugins present")

    # --- Screen size ---
    if w > 0 and h > 0:
        if w < 400 or h < 300:
            score -= 15
            risk.append(f"Unusually small screen ({w}x{h})")
        elif w >= 1024:
            score += 5
            positive.append(f"Normal desktop resolution ({w}x{h})")
    else:
        score -= 10
        risk.append("Screen dimensions unavailable")

    # --- Automation/bot detection (heavy penalty) ---
    auto_signals = _detect_automation(data)
    if auto_signals:
        score -= 40
        risk.append("Automation detected: " + ", ".join(auto_signals))

    # --- Clamp ---
    score = max(0, min(100, score))

    if score >= 60:
        verdict = "Trusted"
    elif score >= 30:
        verdict = "Neutral"
    else:
        verdict = "Suspicious"

    return score, verdict, risk, positive


def log_device_info(data):
    _ensure_log_dir()
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    entry = {
        "timestamp":       timestamp,
        "ip_address":      data.get("ip_address", ""),
        "user_agent":      str(data.get("user_agent", ""))[:120],
        "screen":          f"{data.get('screen_width')}x{data.get('screen_height')}",
        "language":        data.get("language") or data.get("languages") or "",
        "timezone":        data.get("timezone", ""),
        "platform":        data.get("platform", ""),
        "trust_score":     data.get("trust_score", ""),
        "verdict":         data.get("verdict", ""),
        "risk_factors":    data.get("risk_factors", []),
        "positive_factors": data.get("positive_factors", []),
        "canvas_fp":       data.get("canvas_fingerprint", "")[:20] if data.get("canvas_fingerprint") else "",
    }

    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


def get_recent_logs(limit=50):
    _ensure_log_dir()
    if not os.path.exists(LOG_FILE):
        return []

    entries = []
    try:
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    entries.append({"raw": line, "verdict": "", "trust_score": "?"})
    except Exception:
        return []

    return list(reversed(entries))[:limit]
