import pyudev
import logging
import time
import os
import json
import subprocess
import threading
import psutil
from collections import deque
from evdev import InputDevice, ecodes

# =========================
# CONFIG
# =========================
CONFIG_FILE = "trusted_devices.json"

def load_config():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            json.dump({"trusted_devices": []}, f, indent=2)
    try:
        with open(CONFIG_FILE) as f:
            return json.load(f)
    except:
        return {"trusted_devices": []}

TRUSTED_DEVICES = set(tuple(x) for x in load_config().get("trusted_devices", []))

# =========================
# KNOWN DEVICES
# =========================
BLACKLIST_DEVICES = {
    ("1b4f", "9206"): "Rubber Ducky",
    ("1b4f", "9205"): "Bash Bunny",
    ("16c0", "0486"): "Digispark",
}

PICO_DEVICES = {
    ("2e8a", "0005"): "Raspberry Pi Pico",
    ("239a", "80f4"): "Pico HID"
}

# =========================
# STATE
# =========================
seen_devices = {}
keystroke_data = {}
camera_active = False

# detection tuning
MIN_KEYS = 8
FAST_THRESHOLD = 0.04
VARIANCE_THRESHOLD = 0.0008
BURST_COUNT = 12
BURST_WINDOW = 1.2

suspicious_keywords = [
    "powershell", "cmd", "wget", "curl",
    "bash", "sudo", "sh", "python"
]

# =========================
# LOGGING
# =========================
logging.basicConfig(
    filename="security_log.txt",
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

def log(msg, level="info"):
    print(msg)
    if level == "warning":
        logging.warning(msg)
    else:
        logging.info(msg)

# =========================
# NOTIFY
# =========================
def notify(title, message, critical=False):
    subprocess.run([
        "notify-send",
        "-u", "critical" if critical else "normal",
        title,
        message
    ])

def alert(msg):
    log(msg, "warning")
    notify("🚨 SECURITY ALERT", msg, True)

# =========================
# DEVICE ID
# =========================
def get_physical_id(device):
    parent = device.find_parent('usb', 'usb_device')
    if parent:
        props = parent.properties
        return (
            props.get('ID_VENDOR_ID', '').lower(),
            props.get('ID_MODEL_ID', '').lower()
        )
    return None

# =========================
# KEYCODE → TEXT (simple mapping)
# =========================
def key_to_char(code):
    try:
        return ecodes.KEY[code].replace("KEY_", "").lower()
    except:
        return ""

# =========================
# ADVANCED BEHAVIOR DETECTION
# =========================
def detect_keystroke(device_path, key):
    now = time.time()

    if device_path not in keystroke_data:
        keystroke_data[device_path] = {
            "times": deque(maxlen=50),
            "keys": deque(maxlen=50),
            "buffer": "",
            "start_time": now
        }

    data = keystroke_data[device_path]

    data["times"].append(now)
    data["keys"].append(key)

    char = key_to_char(key)
    data["buffer"] += char

    if len(data["times"]) < MIN_KEYS:
        return

    reasons = []
    score = 0

    times = list(data["times"])
    intervals = [times[i] - times[i-1] for i in range(1, len(times))]
    avg = sum(intervals) / len(intervals)

    # ⚡ Speed
    if avg < FAST_THRESHOLD:
        score += 2
        reasons.append(f"Fast typing ({round(avg*1000)} ms avg)")

    # 🚨 Burst
    recent = [t for t in times if now - t < BURST_WINDOW]
    if len(recent) >= BURST_COUNT:
        score += 2
        reasons.append(f"Burst typing ({len(recent)} keys in {BURST_WINDOW}s)")

    # 🤖 Variance
    mean = avg
    variance = sum((x - mean)**2 for x in intervals) / len(intervals)
    if variance < VARIANCE_THRESHOLD:
        score += 3
        reasons.append("Consistent timing (script-like)")

    # 🔤 Diversity
    if len(set(data["keys"])) < 5:
        score += 1
        reasons.append("Low key diversity")

    # 🔴 Immediate typing
    if now - data["start_time"] < 1 and len(data["keys"]) > 5:
        score += 2
        reasons.append("Immediate typing after connection")

    # 🔴 Long sequence
    if len(data["buffer"]) > 40:
        score += 2
        reasons.append("Long continuous typing sequence")
        data["buffer"] = ""

    # 🔴 Command detection
    for word in suspicious_keywords:
        if word in data["buffer"]:
            score += 3
            reasons.append(f"Suspicious command: {word}")
            data["buffer"] = ""
            break

    # 🚨 FINAL
    if score >= 5:
        message = f"""
🚨 HID ATTACK DETECTED
Device: {device_path}

Reasons:
""" + "\n".join(f"• {r}" for r in reasons) + """

⚠️ Possible Rubber Ducky / BadUSB
"""
        alert(message)

        data["times"].clear()
        data["keys"].clear()

# =========================
# KEYBOARD MONITOR
# =========================
def monitor_keyboard():
    for file in os.listdir("/dev/input"):
        if file.startswith("event"):
            path = f"/dev/input/{file}"
            try:
                dev = InputDevice(path)

                if "keyboard" in dev.name.lower():
                    log(f"Monitoring keyboard: {dev.path}")

                    def listen(d):
                        try:
                            for event in d.read_loop():
                                if event.type == ecodes.EV_KEY and event.value == 1:
                                    detect_keystroke(d.path, event.code)
                        except:
                            pass

                    threading.Thread(target=listen, args=(dev,), daemon=True).start()
            except:
                continue

# =========================
# CAMERA MONITOR
# =========================
def monitor_camera():
    global camera_active

    while True:
        active = False
        proc_name = None

        for p in psutil.process_iter(['name']):
            try:
                for f in p.open_files():
                    if f.path.startswith("/dev/video"):
                        active = True
                        proc_name = p.info['name']
                        break
            except:
                continue

        if active and not camera_active:
            camera_active = True
            alert(f"📷 Camera ON (used by {proc_name})")

        elif not active and camera_active:
            camera_active = False
            log("📷 Camera OFF")

        time.sleep(1)

# =========================
# USB DETECTION
# =========================
def detect_usb(device):
    uid = get_physical_id(device)
    if not uid:
        return

    if uid in seen_devices:
        return
    seen_devices[uid] = True

    name = device.get('NAME', 'Unknown')
    dev_id = uid

    if dev_id in BLACKLIST_DEVICES:
        alert(f"Known BadUSB detected: {BLACKLIST_DEVICES[dev_id]}")
        return

    if dev_id in PICO_DEVICES:
        alert(f"Suspicious Pico device detected: {name}")
        return

    if dev_id in TRUSTED_DEVICES:
        return

    if device.get('ID_INPUT_KEYBOARD') == '1':
        alert(f"Untrusted keyboard connected: {name}")
    else:
        notify("⚠️ Unknown USB Device", name)

# =========================
# EVENT HANDLER
# =========================
def handle_event(action, device):
    if 'ID_INPUT' not in device:
        return

    if action == "add":
        detect_usb(device)

# =========================
# USB MONITOR
# =========================
def monitor_usb():
    ctx = pyudev.Context()
    mon = pyudev.Monitor.from_netlink(ctx)
    mon.filter_by(subsystem='input')

    for action, device in mon:
        handle_event(action, device)

# =========================
# MAIN
# =========================
if __name__ == "__main__":
    print("🔒 Advanced Security System Running...\n")

    threading.Thread(target=monitor_keyboard, daemon=True).start()
    threading.Thread(target=monitor_camera, daemon=True).start()

    monitor_usb()
