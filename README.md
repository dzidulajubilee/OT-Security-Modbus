

# Modbus Toolkit

A Python-based toolkit for scanning, fingerprinting, and interacting with Modbus TCP devices over a network. Supports subnet scanning, HTML reporting, and fallback fingerprinting using banner grabbing and register sampling.

---

## 🔧 Features

* Subnet scanning for live Modbus devices
* Device fingerprinting using standard Modbus device identification (Function Code 43/14)
* Fallback fingerprinting using:

  * Banner grabbing (raw TCP response)
  * Known register access patterns
* HTML report generation
* `--skip-unresponsive` mode to silence noisy errors

---

## 🚀 Usage

### Basic Subnet Scan with Fingerprint

```bash
python modbus_toolkit.py --subnet 10.20.20.0/24 --fingerprint --report html
```

### Skip Error Spam from Unresponsive Devices

```bash
python modbus_toolkit.py --subnet 10.20.20.0/24 --fingerprint --skip-unresponsive --report html
```

### Scan a Single Host

```bash
python modbus_toolkit.py --ip 10.20.20.100 --fingerprint
```

### Change Modbus Port

```bash
python modbus_toolkit.py --subnet 192.168.1.0/24 --port 1502 --fingerprint
```

---

## 📝 Output

* HTML report saved as `modbus_report_<timestamp>.html`
* Displays:

  * Host IP
  * Device ID (if available)
  * Banner (raw TCP data)
  * Sample register values

---

## 💡 Notes

* Only TCP Modbus (port 502 by default) is supported.
* Fallback fingerprinting works even when devices don't support device ID requests.
* This tool uses `pymodbus`, `socket`, and Python's `concurrent.futures` for scanning.

---

## 📦 Dependencies

* Python 3.7+
* `pymodbus>=3.x`

Install dependencies:

```bash
pip install pymodbus
```

---

## 📜 License

GNU v2
