import sys
import random
import logging
import argparse
import csv
import ipaddress
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from pymodbus.client import ModbusTcpClient
from pymodbus.exceptions import ModbusException

logging.basicConfig(level=logging.INFO)

# Known Vendor Signatures
DEVICE_SIGNATURES = {
    "Schneider Electric": "Schneider PLC",
    "Siemens": "Siemens S7",
    "WAGO": "WAGO Controller",
    "Mitsubishi": "Mitsubishi Electric PLC",
    "Modicon": "Modicon PLC",
    "Rockwell": "Allen-Bradley PLC",
    "Delta": "Delta PLC"
}

# Connect to Modbus Server
def connect(ip, port=502):
    client = ModbusTcpClient(ip, port=port)
    if client.connect():
        return client
    return None

# Identify Vendor
def identify_vendor(info):
    for k, v in info.items():
        for sig in DEVICE_SIGNATURES:
            if sig.lower() in str(v).lower():
                return DEVICE_SIGNATURES[sig]
    return "Unknown Device"

# Fingerprint Device
def fingerprint_device(client, ip, port):
    try:
        response = client.read_device_information()
        if response.isError():
            print(f"{ip}:{port} - No response to device info request")
            return None
        info = {
            "Host": ip,
            "Port": port,
            "Type": "device_info",
            "Status": "OK"
        }
        for obj_id, value in response.information.items():
            info[f"device_{obj_id}"] = value
        info["Vendor"] = identify_vendor(response.information)
        print(f"{ip}:{port} - Fingerprinted as {info['Vendor']}")
        return info
    except Exception as e:
        print(f"{ip}:{port} - Fingerprint failed: {e}")
        return {"Host": ip, "Port": port, "Type": "device_info", "Status": f"Exception: {e}"}

# Check Host for Modbus
def check_modbus(ip, ports, skip_logs=False):
    for port in ports:
        try:
            client = ModbusTcpClient(str(ip), port=port)
            if not client.connect():
                if not skip_logs:
                    logging.error(f"Connection to ({ip}, {port}) failed.")
                continue
            resp = client.read_coils(address=0, count=1)
            if not resp.isError():
                logging.info(f"[+] Modbus detected: {ip}:{port}")
                client.close()
                return str(ip), port
            client.close()
        except Exception as e:
            if not skip_logs:
                logging.error(f"{ip}:{port} raised {e}")
    return None

# Subnet Scanner
def scan_subnet(subnet, ports, skip_logs):
    logging.info(f"Scanning subnet {subnet} on ports {ports}...")
    live_hosts = []
    with ThreadPoolExecutor(max_workers=50) as executor:
        futures = [executor.submit(check_modbus, ip, ports, skip_logs) for ip in ipaddress.IPv4Network(subnet).hosts()]
        for f in futures:
            result = f.result()
            if result:
                live_hosts.append(result)
    logging.info(f"Found {len(live_hosts)} Modbus hosts.")
    print("\nSummary of detected hosts:")
    for ip, port in live_hosts:
        print(f"  - {ip}:{port}")
    return live_hosts

# Save CSV Report
def save_csv(filename, data):
    keys = data[0].keys()
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        writer.writerows(data)

# Save HTML Report
def save_html(filename, data, title="Modbus Multi-Host Report"):
    html = f"""<html><head><title>{title}</title>
<style>
  body {{ font-family: Arial; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #ddd; padding: 8px; }}
  th {{ background-color: #444; color: #fff; }}
  tr:nth-child(even) {{ background-color: #f9f9f9; }}
  .OK {{ color: green; }}
  .Error, .Exception {{ color: red; }}
</style></head><body>
<h2>{title}</h2>
<table>
<tr>""" + "".join(f"<th>{k}</th>" for k in data[0].keys()) + "</tr>\n"

    for row in data:
        html += "<tr>"
        for k, v in row.items():
            css = str(v).split(":")[0] if k == "Status" else ""
            html += f"<td class='{css}'>{v}</td>"
        html += "</tr>\n"
    html += "</table></body></html>"

    with open(filename, "w") as f:
        f.write(html)

# Main
def main():
    parser = argparse.ArgumentParser(description="Modbus Toolkit with Subnet & Fingerprint Support")
    parser.add_argument("--ip", help="Target IP address")
    parser.add_argument("--subnet", help="Scan a subnet (e.g., 192.168.1.0/24)")
    parser.add_argument("--port-range", type=str, default="502", help="e.g., 502 or 502-504")
    parser.add_argument("--skip-unresponsive", action="store_true", help="Suppress connection timeout logs")
    parser.add_argument("--fingerprint", action="store_true", help="Attempt device fingerprinting")
    parser.add_argument("--report", choices=["csv", "html"], help="Generate report")

    args = parser.parse_args()

    # Parse port range
    if "-" in args.port_range:
        start, end = map(int, args.port_range.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(args.port_range)]

    # Build targets
    if not args.subnet and not args.ip:
        print("Please specify either --ip or --subnet.")
        sys.exit(1)

    targets = []
    if args.subnet:
        targets = scan_subnet(args.subnet, ports, skip_logs=args.skip_unresponsive)
    elif args.ip:
        targets = [(args.ip, ports[0])]

    all_results = []

    for ip, port in targets:
        client = connect(ip, port=port)
        if not client:
            continue
        logging.info(f"Connected to {ip}:{port}")

        if args.fingerprint:
            result = fingerprint_device(client, ip, port)
            if result:
                all_results.append(result)

        client.close()

    if all_results and args.report:
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        base = f"modbus_report_{ts}"
        if args.report == "csv":
            save_csv(f"{base}.csv", all_results)
            print(f"CSV saved: {base}.csv")
        elif args.report == "html":
            save_html(f"{base}.html", all_results)
            print(f"HTML saved: {base}.html")


if __name__ == "__main__":
    main()
