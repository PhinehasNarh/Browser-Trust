from flask import Flask, request, render_template, jsonify
from trust_logic import calculate_trust_score, log_device_info, get_recent_logs
from collections import defaultdict
import time
import threading

try:
    import tkinter as tk
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

app = Flask(__name__)

# Simple in-memory rate limiter (10 requests/minute per IP)
_request_log = defaultdict(list)
_rate_lock = threading.Lock()
RATE_LIMIT = 10
RATE_WINDOW = 60


def is_rate_limited(ip):
    now = time.time()
    cutoff = now - RATE_WINDOW
    with _rate_lock:
        _request_log[ip] = [t for t in _request_log[ip] if t > cutoff]
        if len(_request_log[ip]) >= RATE_LIMIT:
            return True
        _request_log[ip].append(now)
        return False


def show_alert_popup(data):
    if not TKINTER_AVAILABLE:
        return

    def _popup():
        try:
            root = tk.Tk()
            root.title("Suspicious Device Alert")
            root.geometry("480x230")
            root.configure(bg='black')
            root.resizable(False, False)

            risks = ', '.join(data.get('risk_factors', []))[:80]
            msg = (
                f"  Suspicious Device Detected!\n\n"
                f"  IP      : {data['ip_address']}\n"
                f"  Browser : {str(data.get('user_agent', ''))[:45]}...\n"
                f"  Score   : {data['trust_score']}\n"
                f"  Verdict : {data['verdict']}\n"
                f"  Risks   : {risks}"
            )

            label = tk.Label(root, text=msg, bg='black', fg='red',
                             font=("Courier", 10), justify="left", anchor="w")
            label.pack(fill="both", expand=True, padx=10, pady=16)

            btn = tk.Button(root, text="Dismiss", command=root.destroy,
                            bg='#cc0000', fg='white', font=("Courier", 10),
                            relief="flat", padx=20, pady=4)
            btn.pack(pady=(0, 16))

            root.mainloop()
        except Exception:
            pass

    threading.Thread(target=_popup, daemon=True).start()


@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/dashboard')
def dashboard():
    logs = get_recent_logs(100)
    stats = {
        "total":      len(logs),
        "trusted":    sum(1 for l in logs if l.get("verdict") == "Trusted"),
        "neutral":    sum(1 for l in logs if l.get("verdict") == "Neutral"),
        "suspicious": sum(1 for l in logs if l.get("verdict") == "Suspicious"),
    }
    return render_template('dashboard.html', logs=logs, stats=stats)


@app.route('/submit-device-info', methods=['POST'])
def submit_device_info():
    ip_address = request.remote_addr

    if is_rate_limited(ip_address):
        return jsonify({"error": "Rate limit exceeded. Try again later."}), 429

    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    # Sanitize string fields to cap length and enforce type
    for field in ('user_agent', 'timezone', 'language', 'platform'):
        if field in data:
            data[field] = str(data[field])[:300]

    data['ip_address'] = ip_address

    score, verdict, risk_factors, positive_factors = calculate_trust_score(data)
    data['trust_score']      = score
    data['verdict']          = verdict
    data['risk_factors']     = risk_factors
    data['positive_factors'] = positive_factors

    log_device_info(data)

    if verdict == "Suspicious":
        show_alert_popup(data)

    return jsonify({
        "trust_score":      score,
        "verdict":          verdict,
        "risk_factors":     risk_factors,
        "positive_factors": positive_factors,
    })


if __name__ == '__main__':
    app.run(debug=True)
