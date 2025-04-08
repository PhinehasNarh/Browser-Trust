# Device Trust Checker – Zero Trust Module

##  What It Does

This module collects **basic device fingerprints** (like user-agent, screen size, language, etc.) and uses custom logic to calculate a **trust score** based on Zero Trust principles:

✅ Is the device known?  
✅ Is it coming from a trusted IP?  
✅ Is the browser outdated?  
✅ Are screen size, location & language consistent?  
❌ Any signs of bot or virtual machine?

Based on these checks, a **verdict** is returned: `Trusted`, `Neutral`, or `Suspicious`.

---

## Zero Trust Principles in Action

This isn't just fingerprinting — this is about **"never trust, always verify"**:

- No device is automatically trusted
- Trust is scored **per request**
- Logs are stored for **monitoring and auditing**
- Easy to scale up to integrate with other Zero Trust components (user ID, behavior, etc.)

---

##  Tech Stack

- 🐍 Python + Flask (for backend logic)
- 📜 JavaScript (for client-side fingerprinting)
- 🧾 YAML-style logs in `.txt` (easy to parse/visualize)
- ⚡️ Lightweight and fast — works in any browser

---

## 📦 Project Structure
device_trust_checker/ │ ├── app.py # Flask app ├── trust_logic.py # Core trust score logic ├── logs/ │ └── device_logs.txt # Saved logs (in YAML-style format) ├── static/ │ └── device.js # Collects browser info └── templates/ └── index.html 

---

## 🧪 How to Run Locally

```bash
git clone https://github.com/PhinehasNarh/Browser-Trust.git
cd device-trust-checker
pip install flask
python app.py
```
Then visit 👉 http://127.0.0.1:5000


📈 Sample Output
{
  "trust_score": 80,
  "verdict": "Trusted"
}


### #ph1n3y
