import sys
import random
import logging
import argparse
import csv
import socket
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

logging.basicConfig(level=logging.INFO)

# ───── CONNECT ─────
def connect(ip, port=502):
    client = ModbusTcpClient(ip, port=port)
    if client.connect():
        return client
    return None

# ───── BANNER GRAB ─────
def banner_grab(ip, port=502):
    try:
        s = socket.create_connection((ip, port), timeout=2)
        s.send(b'\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01')
        data = s.recv(1024)
        s.close()
        return data.hex()
    except Exception:
        return None

# ───── FALLBACK FINGERPRINT ─────
def fallback_fingerprint(client, ip):
    patterns = scan_registers(client, ip, start=0, end=10, step=2)
    banner = banner_grab(ip)
    return {
        "Host": ip,
        "Type": "fallback_fingerprint",
        "Status": "OK",
        "Banner": banner if banner else "None",
        "RegisterSample": str(patterns)
    }

# ───── DEVICE FINGERPRINTING ─────
def fingerprint_device(client, ip):
    try:
        response = client.read_device_information()
        if response.isError():
            return fallback_fingerprint(client, ip)
        info = {"Host": ip, "Type": "device_info", "Status": "OK"}
        for obj_id, value in response.information.items():
            info[f"device_{obj_id}"] = value
        return info
    except Exception:
        return fallback_fingerprint(client, ip)

# ───── SCANNERS ─────
def scan_registers(client, ip, start=0, end=100, step=10, reg_type="holding"):
    results = []
    for addr in range(start, end, step):
        try:
            if reg_type == "holding":
                response = client.read_holding_registers(address=addr, count=step)
            else:
                response = client.read_input_registers(address=addr, count=step)
            status = "OK" if not response.isError() else "Error"
            values = response.registers if not response.isError() else []
        except Exception as e:
            status = f"Exception: {e}"
            values = []
        results.append({"Host": ip, "Type": reg_type, "Address": addr, "Values": values, "Status": status})
    return results

def scan_coils(client, ip, start=0, end=100, step=10):
    results = []
    for addr in range(start, end, step):
        try:
            response = client.read_coils(address=addr, count=step)
            status = "OK" if not response.isError() else "Error"
            values = response.bits if not response.isError() else []
        except Exception as e:
            status = f"Exception: {e}"
            values = []
        results.append({"Host": ip, "Type": "coil", "Address": addr, "Values": values, "Status": status})
    return results

# ───── FUZZERS ─────
def fuzz_registers(client, ip, count=5, iterations=10):
    results = []
    for _ in range(iterations):
        addr = random.randint(0, 120)
        values = [random.randint(0, 65535) for _ in range(count)]
        try:
            response = client.write_registers(address=addr, values=values)
            status = "OK" if not response.isError() else "Error"
        except Exception as e:
            status = f"Exception: {e}"
        results.append({"Host": ip, "Type": "fuzz_register", "Address": addr, "Values": values, "Status": status})
    return results

# ───── REPORTING ─────
def save_html(filename, data, title="Modbus Multi-Host Report"):
    html = f"""<html><head><title>{title}</title><style>
    body {{ font-family: Arial; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border: 1px solid #ddd; padding: 8px; }}
    th {{ background-color: #444; color: #fff; }}
    tr:nth-child(even) {{ background-color: #f9f9f9; }}
    .OK {{ color: green; }} .Error, .Exception {{ color: red; }}
    </style></head><body><h2>{title}</h2><table>
    <tr>{''.join(f'<th>{k}</th>' for k in data[0].keys())}</tr>
    """
    for row in data:
        html += "<tr>"
        for k, v in row.items():
            css = str(v).split(":")[0] if k == "Status" else ""
            html += f"<td class='{css}'>{v}</td>"
        html += "</tr>"
    html += "</table></body></html>"
    with open(filename, "w") as f:
        f.write(html)

# ───── SUBNET SCANNER ─────
def check_modbus(ip, port):
    client = connect(ip, port)
    if client:
        try:
            resp = client.read_coils(0, 1)
            if not resp.isError():
                return ip
        except:
            pass
        client.close()
    return None

def scan_subnet(subnet, port=502):
    logging.info(f"🔎 Scanning subnet {subnet} for Modbus devices...")
    live_hosts = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_modbus, str(ip), port) for ip in ipaddress.IPv4Network(subnet).hosts()]
        for f in futures:
            result = f.result()
            if result:
                logging.info(f"[+] Modbus detected: {result}")
                live_hosts.append(result)
    logging.info(f"✅ Found {len(live_hosts)} Modbus hosts.")
    return live_hosts

# ───── MAIN ─────
def main():
    parser = argparse.ArgumentParser(description="Modbus Toolkit")
    parser.add_argument("--ip")
    parser.add_argument("--subnet")
    parser.add_argument("--port", type=int, default=502)
    parser.add_argument("--fingerprint", action="store_true")
    parser.add_argument("--skip-unresponsive", action="store_true")
    parser.add_argument("--report", choices=["html"])
    args = parser.parse_args()

    targets = []
    if args.subnet:
        targets = scan_subnet(args.subnet, args.port)
    elif args.ip:
        targets = [args.ip]
    else:
        print("❌ Provide --ip or --subnet")
        sys.exit(1)

    all_results = []
    for ip in targets:
        try:
            client = connect(ip, port=args.port)
            if not client:
                continue
            logging.info(f"🔗 Connected to {ip}")
            if args.fingerprint:
                info = fingerprint_device(client, ip)
                if info:
                    all_results.append(info)
            client.close()
        except Exception as e:
            if not args.skip_unresponsive:
                logging.error(f"{ip}: {e}")

    if all_results and args.report == "html":
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        fn = f"modbus_report_{ts}.html"
        save_html(fn, all_results)
        print(f"🌐 HTML saved: {fn}")

if __name__ == "__main__":
    main()
