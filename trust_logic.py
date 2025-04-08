import datetime

known_devices = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)...": "user1",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...": "admin",
}

trusted_ip_ranges = [
    "127.0.0.1",     
    "192.168.",      
    "10.0."          
]

def is_trusted_ip(ip):
    return any(ip.startswith(r) for r in trusted_ip_ranges)

def is_known_device(ua):
    return ua in known_devices

def is_outdated_browser(ua):
    if "Chrome/5" in ua or "Firefox/3" in ua or "MSIE" in ua:
        return True
    return False

def suspicious_screen_size(w, h):
    return (w <= 1024 and h <= 768)

def calculate_trust_score(device_data):
    score = 0
    ip = device_data.get("ip_address", "")
    ua = device_data.get("user_agent", "")
    lang = device_data.get("language", "")
    tz = device_data.get("timezone", "")
    w = int(device_data.get("screen_width", 0))
    h = int(device_data.get("screen_height", 0))

    
    if is_trusted_ip(ip):
        score += 30

    if is_known_device(ua):
        score += 30

    if not is_outdated_browser(ua):
        score += 20

    
    if lang.startswith("en") and "Africa" in tz:
        score += 10
    else:
        score -= 10

    if suspicious_screen_size(w, h):
        score -= 20

    
    if score >= 60:
        verdict = "Trusted"
    elif score >= 30:
        verdict = "Neutral"
    else:
        verdict = "Suspicious"

    return score, verdict

def log_device_info(device_data):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log = {
        "timestamp": timestamp,
        "ip_address": device_data.get("ip_address", ""),
        "user_agent": device_data.get("user_agent", ""),
        "screen": f"{device_data.get('screen_width')}x{device_data.get('screen_height')}",
        "language": device_data.get("language", ""),
        "timezone": device_data.get("timezone", ""),
        "trust_score": device_data.get("trust_score", ""),
        "verdict": device_data.get("verdict", "")
    }

    with open("logs/device_logs.txt", "a") as f:
        f.write(str(log) + "\n")
