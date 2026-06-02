# Browser Trust: Zero Trust Device Assessment Module

## What It Does

This module collects basic device fingerprints (user-agent, screen size, language, canvas hash, etc.)
and uses custom logic to calculate a trust score based on Zero Trust principles:

- Is the device known?
- Is it coming from a trusted IP?
- Is the browser outdated?
- Are screen size, location, and language consistent?
- Are there any signs of bots or virtual machines?

Based on these checks, a verdict is returned: `Trusted`, `Neutral`, or `Suspicious`.

---

## Zero Trust Principles in Action

This is not just fingerprinting. It is about "never trust, always verify":

- No device is automatically trusted
- Trust is scored per request
- Logs are stored for monitoring and auditing
- Alerts fire on suspicious sessions
- Easy to extend with user ID, behaviour analytics, and more

---

## Tech Stack

- Python + Flask (backend scoring and API)
- JavaScript (client-side fingerprinting)
- JSON-lines logs in `logs/device_logs.txt`
- Lightweight and fast - works in any browser

---

## Project Structure

```
Browser-Trust/
├── app.py              # Flask app, routes, rate limiting, security headers
├── trust_logic.py      # Trust score engine, bot detection, log writer
├── static/
│   └── device.js       # Client-side fingerprint collection
├── templates/
│   ├── index.html      # Assessment UI
│   └── dashboard.html  # Admin session dashboard
├── logs/
│   └── device_logs.txt # JSON-lines session log (gitignored)
├── requirements.txt
└── .gitignore
```

---

## How to Run Locally

```bash
git clone https://github.com/PhinehasNarh/Browser-Trust.git
cd Browser-Trust
pip install -r requirements.txt
python app.py
```

Then visit:
- http://127.0.0.1:5000 - device assessment
- http://127.0.0.1:5000/dashboard - admin session log

---

## Sample Output

```json
{
  "trust_score": 75,
  "verdict": "Trusted",
  "positive_factors": ["Trusted IP range", "Modern browser", "Canvas fingerprint available"],
  "risk_factors": []
}
```

---

### #ph1n3y
