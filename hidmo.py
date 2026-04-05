import pyudev
import logging
import time
import os
import notify2

# =========================
# 🔧 CONFIG
# =========================
TRUSTED_FILE = "trusted_devices.txt"

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

            parts = line.split(":")
            if len(parts) != 2:
                continue

            vendor, product = parts
            trusted.add((vendor.lower(), product.lower()))

    return trusted


WHITELIST_DEVICES = load_trusted()

# =========================
# STATIC LISTS
# =========================
BLACKLIST_DEVICES = {
    ("1b4f", "9206"): "Rubber Ducky",
    ("1b4f", "9205"): "Bash Bunny",
    ("16c0", "0486"): "Digispark",
}

PICO_DEVICES = {
    ("2e8a", "0005"): "Raspberry Pi Pico",
}

# Track physical devices
seen_devices = {}

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
# 🔔 NOTIFICATIONS (notify2)
# =========================
notify2.init("USB IDS")

def notify(title, message, critical=False):
    n = notify2.Notification(title, message)

    if critical:
        n.set_urgency(notify2.URGENCY_CRITICAL)
    else:
        n.set_urgency(notify2.URGENCY_NORMAL)

    n.show()

# =========================
# 🔑 GET PHYSICAL DEVICE
# =========================
def get_physical_id(device):
    parent = device.find_parent('usb', 'usb_device')

    if parent:
        props = parent.properties

        vendor = props.get('ID_VENDOR_ID', '').lower()
        product = props.get('ID_MODEL_ID', '').lower()
        serial = props.get('ID_SERIAL_SHORT', '')

        return (vendor, product, serial)

    return None

# =========================
# 🚨 DETECTION
# =========================
def detect(device):
    uid = get_physical_id(device)

    if uid is None:
        return

    # Deduplicate
    if uid in seen_devices:
        return
    seen_devices[uid] = time.time()

    vendor, product, serial = uid
    name = device.get('NAME', 'Unknown')

    dev_id = (vendor, product)

    is_keyboard = device.get('ID_INPUT_KEYBOARD') == '1'
    is_mouse = device.get('ID_INPUT_MOUSE') == '1'

    # 🔴 Known BadUSB
    if dev_id in BLACKLIST_DEVICES:
        msg = f"{BLACKLIST_DEVICES[dev_id]} ({vendor}:{product})"
        log(f"🚨 CRITICAL: Known BadUSB → {msg}", "warning")
        notify("🚨 BadUSB Detected", msg, True)
        return

    # 🟡 Pico detection
    if dev_id in PICO_DEVICES:
        log(f"⚠️ Pico detected → {name} ({vendor}:{product})", "warning")
        notify("⚠️ Pico Detected", f"{name} ({vendor}:{product})")

        if is_keyboard:
            notify("🚨 Pico Acting as Keyboard", name, True)

    # ✅ Trusted device
    if dev_id in WHITELIST_DEVICES:
        return

    # Ignore mouse alerts
    if is_mouse:
        log(f"ℹ️ Untrusted mouse → {name} ({vendor}:{product})")
        return

    # 🚨 Unknown keyboard
    if is_keyboard:
        msg = f"{name} ({vendor}:{product})"
        log(f"🚨 ALERT: Untrusted keyboard → {msg}", "warning")
        notify("🚨 Untrusted Keyboard", msg, True)
    else:
        notify("⚠️ Unknown USB Device", f"{name} ({vendor}:{product})")

# =========================
# 📋 EVENT HANDLER
# =========================
def handle_event(action, device):
    if 'ID_INPUT' not in device:
        return

    # Ignore duplicate interfaces
    if device.device_node and "event" not in device.device_node:
        return

    name = device.get('NAME', 'Unknown HID')
    node = device.device_node or 'N/A'
    vendor = device.get('ID_VENDOR_ID', 'unknown').lower()
    product = device.get('ID_MODEL_ID', 'unknown').lower()

    log(f"{action.upper()} | {name} | {node} | {vendor}:{product}")

    if action == "add":
        detect(device)

# =========================
# 👀 MONITOR
# =========================
def monitor():
    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by(subsystem='input')

    print("🔒 USB HID IDS Running (notify2 popup enabled)...")

    for item in monitor:
        if isinstance(item, tuple):
            action, device = item
        else:
            device = item
            action = device.action

        if action in ['add', 'remove']:
            handle_event(action, device)

# =========================
# 🚀 MAIN
# =========================
if __name__ == "__main__":
    try:
        monitor()
    except KeyboardInterrupt:
        print("\n🔴 Monitoring stopped.")
