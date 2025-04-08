from flask import Flask, request, render_template, jsonify
from trust_logic import calculate_trust_score, log_device_info
import tkinter as tk
from threading import Thread

app = Flask(__name__)

# --- ALERT FUNCTION ---
def show_alert_popup(data):
    def _popup():
        root = tk.Tk()
        root.title("Suspicious Device Alert")
        root.geometry("400x200")
        root.configure(bg='black')

        msg = f"""
        Suspicious Device Detected!

        IP: {data['ip_address']}
        Browser: {data['user_agent'][:30]}...
        Score: {data['trust_score']}
        Verdict: {data['verdict']}
        """

        label = tk.Label(root, text=msg, bg='black', fg='red', font=("Courier", 10), justify="left")
        label.pack(pady=20)

        button = tk.Button(root, text="Dismiss", command=root.destroy)
        button.pack(pady=10)

        root.mainloop()

    Thread(target=_popup).start()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/submit-device-info', methods=['POST'])
def submit_device_info():
    data = request.get_json()
    ip_address = request.remote_addr
    data['ip_address'] = ip_address

    score, verdict = calculate_trust_score(data)
    data['trust_score'] = score
    data['verdict'] = verdict

    log_device_info(data)

    if verdict == "Suspicious":
        show_alert_popup(data)

    return jsonify({
        "trust_score": score,
        "verdict": verdict
    })

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, request, render_template, jsonify
from trust_logic import calculate_trust_score, log_device_info
import tkinter as tk
from threading import Thread

app = Flask(__name__)

# --- ALERT FUNCTION ---
def show_alert_popup(data):
    def _popup():
        root = tk.Tk()
        root.title(" Suspicious Device Alert")
        root.geometry("400x200")
        root.configure(bg='black')

        msg = f"""
        Suspicious Device Detected!

        IP: {data['ip_address']}
        Browser: {data['user_agent'][:30]}...
        Score: {data['trust_score']}
        Verdict: {data['verdict']}
        """

        label = tk.Label(root, text=msg, bg='black', fg='red', font=("Courier", 10), justify="left")
        label.pack(pady=20)

        button = tk.Button(root, text="Dismiss", command=root.destroy)
        button.pack(pady=10)

        root.mainloop()

    Thread(target=_popup).start()

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/submit-device-info', methods=['POST'])
def submit_device_info():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Invalid request data"}), 400

        ip_address = request.remote_addr
        data['ip_address'] = ip_address

        score, verdict = calculate_trust_score(data)
        data['trust_score'] = score
        data['verdict'] = verdict

        log_device_info(data)

        if verdict == "Suspicious":
            show_alert_popup(data)

        return jsonify({
            "trust_score": score,
            "verdict": verdict
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
