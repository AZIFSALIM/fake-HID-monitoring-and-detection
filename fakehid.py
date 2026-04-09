import pyudev
import logging
import time
import os
import notify2
import threading
from collections import deque
from evdev import InputDevice, ecodes, list_devices

# =========================
# 🔧 CONFIG
# =========================
TRUSTED_FILE = "trusted_devices.txt"

WINDOW = 2.0
HUMAN_LIMIT = 8
HARD_LIMIT = 12

# =========================
# 📂 LOAD TRUSTED DEVICES
# =========================
def load_trusted():
    trusted = set()

    if not os.path.exists(TRUSTED_FILE):
        return trusted

    with open(TRUSTED_FILE, "r") as f:
        for line in f:
            line = line.strip()

            if not line or line.startswith("#"):
                continue

            if ":" not in line:
                continue

            vendor, product = line.split(":")
            trusted.add((vendor.lower(), product.lower()))

    return trusted


WHITELIST_DEVICES = load_trusted()

# =========================
# STATIC LISTS
# =========================
BLACKLIST_DEVICES = {
    ("1b4f", "9206"): "Rubber Ducky",
    ("1b4f", "9205"): "Bash Bunny",
}

PICO_DEVICES = {
    ("2e8a", "0005"): "Raspberry Pi Pico",
    ("239a", "80f4"): "Pico HID"
}

# =========================
# STATE
# =========================
seen_devices = {}
keystrokes = {}
blocked_devices = {}

# =========================
# LOGGING
# =========================
logging.basicConfig(
    filename="hid_log.txt",
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
# 🔔 NOTIFY
# =========================
notify2.init("USB IDS")

def notify(title, message, critical=False):
    n = notify2.Notification(title, message)
    n.set_urgency(notify2.URGENCY_CRITICAL if critical else notify2.URGENCY_NORMAL)
    n.show()

# =========================
# 🛑 BLOCK DEVICE
# =========================
def block_device(device_path):
    if device_path in blocked_devices:
        return

    try:
        dev = InputDevice(device_path)
        dev.grab()
        blocked_devices[device_path] = dev

        log(f"🛑 BLOCKED: {device_path}", "warning")
        notify("🛑 Device Blocked", device_path, True)

    except Exception as e:
        log(f"Block failed: {e}", "warning")

# =========================
# ⌨️ BEHAVIOR DETECTION
# =========================
def detect_behavior(device_path):
    now = time.time()

    if device_path not in keystrokes:
        keystrokes[device_path] = deque()

    ks = keystrokes[device_path]
    ks.append(now)

    # remove old entries
    while ks and now - ks[0] > WINDOW:
        ks.popleft()

    speed = len(ks) / WINDOW

    # 🚨 Attack detection
    if speed > HARD_LIMIT:
        log(f"🚨 EXTREME typing speed: {speed:.1f} keys/sec ({device_path})", "warning")
        notify("🚨 HID Attack", f"Extreme typing speed ({speed:.1f})", True)
        block_device(device_path)
        ks.clear()

    elif speed > HUMAN_LIMIT:
        log(f"⚠️ Suspicious typing speed: {speed:.1f} keys/sec ({device_path})", "warning")
        notify("⚠️ Suspicious Typing", f"{speed:.1f} keys/sec")

# =========================
# 🎯 KEYBOARD MONITOR
# =========================
monitored = set()

def monitor_inputs():
    while True:
        for path in list_devices():
            if path in monitored:
                continue

            try:
                dev = InputDevice(path)

                # only devices with keys
                if ecodes.EV_KEY in dev.capabilities():
                    log(f"🎯 Monitoring: {path} ({dev.name})")

                    def listen(d):
                        try:
                            for e in d.read_loop():
                                if e.type == ecodes.EV_KEY and e.value == 1:
                                    detect_behavior(d.path)
                        except:
                            pass

                    threading.Thread(target=listen, args=(dev,), daemon=True).start()
                    monitored.add(path)

            except:
                continue

        time.sleep(1)

# =========================
# 🔑 GET PHYSICAL DEVICE
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
# 🚨 USB DETECTION
# =========================
def detect(device):
    uid = get_physical_id(device)
    if uid is None:
        return

    if uid in seen_devices:
        return
    seen_devices[uid] = True

    vendor, product = uid
    name = device.get('NAME', 'Unknown')

    dev_id = (vendor, product)

    is_keyboard = device.get('ID_INPUT_KEYBOARD') == '1'
    is_mouse = device.get('ID_INPUT_MOUSE') == '1'

    # 🔴 BadUSB
    if dev_id in BLACKLIST_DEVICES:
        notify("🚨 BadUSB Detected", name, True)
        return

    # 🟡 Pico
    if dev_id in PICO_DEVICES:
        notify("⚠️ Pico Detected", name)

        if is_keyboard:
            notify("🚨 Pico as Keyboard", name, True)

    # trusted
    if dev_id in WHITELIST_DEVICES:
        return

    if is_mouse:
        return

    if is_keyboard:
        notify("🚨 Untrusted Keyboard", name, True)

# =========================
# 📋 EVENT HANDLER
# =========================
def handle_event(action, device):
    if 'ID_INPUT' not in device:
        return

    if action == "add":
        detect(device)

# =========================
# 👀 USB MONITOR
# =========================
def monitor_usb():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='input')

    for action, device in monitor:
        handle_event(action, device)

# =========================
# 🚀 MAIN
# =========================
if __name__ == "__main__":
    print("🔒 USB HID IDS + Behavior Detection Running...")

    threading.Thread(target=monitor_inputs, daemon=True).start()
    monitor_usb()
