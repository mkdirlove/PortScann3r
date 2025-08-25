#!/usr/bin/env python3
import socket
import argparse
import ipaddress
import sys
import re
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import csv
import subprocess

try:
    from tqdm import tqdm
    HAVE_TQDM = True
except Exception:
    HAVE_TQDM = False


COMMON_PORTS = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP-Server",
    68: "DHCP-Client",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    500: "ISAKMP",
    587: "SMTP-Submission",
    636: "LDAPS",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle",
    2049: "NFS",
    2375: "Docker",
    27017: "MongoDB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5672: "RabbitMQ",
    5900: "VNC",
    5985: "WinRM-HTTP",
    5986: "WinRM-HTTPS",
    6379: "Redis",
    8080: "HTTP-Alt",
    9000: "PHP-FPM",
}

def banner():
    banner_txt = r'''
   ___           __      ____                   ____    
  / _ \___  ____/ /_____/ __/______ ____  ___  |_  /____
 / ___/ _ \/ __/ __/___/\ \/ __/ _ `/ _ \/ _ \_/_ </ __/
/_/   \___/_/  \__/   /___/\__/\_,_/_//_/_//_/____/_/

            Made with <3 by @mkdirlove
    '''
    return banner_txt

def getCurrentDateTime():
    time = datetime.now(pytz.utc)
    now = time.strftime("%H:%M:%S %d-%m-%Y")
    return now

def checkValidPortNumber(port):
    return 0 <= port <= 65535

def checkValidPortRange(ports):
    return (ports[0] <= ports[1]) and checkValidPortNumber(ports[0]) and checkValidPortNumber(ports[1])

def validatePorts(port_spec):
    if str(port_spec).isdigit():
        result = int(port_spec)
        if checkValidPortNumber(result):
            return [result]
        print('Invalid specification of port/s')
        sys.exit(-1)
    m = re.fullmatch(r'(\d+)-(\d+)', str(port_spec).strip())
    if m:
        a, b = int(m.group(1)), int(m.group(2))
        ports = [a, b]
        if not checkValidPortRange(ports):
            print("Invalid specification of port/s")
            sys.exit(-1)
        return ports
    print("Invalid specification of port/s")
    sys.exit(-1)

def normalize_host_input(host_input):
    final_host = host_input.strip()
    if "://" in final_host:
        final_host = final_host.split("://", 1)[1]
    final_host = final_host.split("/", 1)[0]
    return final_host

def resolveHost(host):
    """Return IP string, printing status lines to output."""
    global output
    try:
        ipaddress.ip_address(host)
        line = f"[*] Will attempt scanning {host}"
        output.append(line)
        print(line)
        return host
    except ValueError:
        try:
            ip = socket.gethostbyname(host)
            line = f"[*] Hostname resolved to: {ip}"
            output.append(line)
            print(line)
            return ip
        except Exception:
            print("[*] Invalid host")
            sys.exit(-1)

def expand_targets(host_field):
    """
    Accept:
      - single host/IP (e.g., scan.me or 1.2.3.4)
      - comma-separated list of hosts
      - CIDR (e.g., 192.168.1.0/24)
    Return list of IPs (as strings) and a dict for {ip: original_label}
    """
    hosts = []
    labels = {}
    parts = [h for h in host_field.split(",") if h.strip()]
    for raw in parts:
        h = normalize_host_input(raw)
        if "/" in h:
            try:
                net = ipaddress.ip_network(h, strict=False)
                for ip in net.hosts():
                    ip_str = str(ip)
                    hosts.append(ip_str)
                    labels[ip_str] = h
            except Exception:
                print(f"[*] Invalid CIDR: {h}")
                sys.exit(-1)
        else:
            try:
                ipaddress.ip_address(h)
                ip_str = h
            except ValueError:
                ip_str = resolveHost(h)
            hosts.append(ip_str)
            labels[ip_str] = h
    seen = set()
    unique = []
    for h in hosts:
        if h not in seen:
            unique.append(h)
            seen.add(h)
    return unique, labels

def guessOS(host):
    """
    Basic OS guess via TTL in ping reply.
    Windows: ping -n 1
    *nix:    ping -c 1
    """
    try:
        is_windows = sys.platform.startswith("win")
        cmd = ["ping", "-n" if is_windows else "-c", "1", host]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3)
        out = proc.stdout + proc.stderr
        ttl_match = re.search(r"ttl[=:\s](\d+)", out, re.IGNORECASE)
        if ttl_match:
            ttl = int(ttl_match.group(1))
            if ttl <= 64:
                return "Linux/Unix-like (TTL≈64)"
            elif ttl <= 128:
                return "Windows (TTL≈128)"
            elif ttl <= 255:
                return "Networking device (TTL≈255)"
        return "Unknown"
    except Exception:
        return "Unknown"

def grab_http_banner(host, port, timeout):
    """Minimal HTTP HEAD to coax a banner (server header/status line)."""
    try:
        req = b"HEAD / HTTP/1.0\r\nHost: %b\r\n\r\n" % host.encode()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(req)
        data = s.recv(2048)
        s.close()
        try:
            return data.decode(errors="ignore").split("\r\n\r\n", 1)[0].replace("\r", "")
        except Exception:
            return repr(data[:128])
    except Exception:
        return None

def grabBanner(host, port, timeout):
    """
    Try to read a banner. Many text protocols (FTP, SMTP, etc.) send a greeting.
    For HTTP ports, send a HEAD request.
    """
    if port in (80, 8080, 8000, 8888):
        b = grab_http_banner(host, port, timeout)
        if b:
            return b

    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        try:
            s.sendall(b"\r\n")
        except Exception:
            pass
        data = s.recv(1024)
        s.close()
        if data:
            return data.decode(errors="ignore").strip()
    except Exception:
        pass
    return None

def scanPort(host, port, verbosity, timeout, results_list):
    global output
    result = {
        "host": host,
        "port": port,
        "status": "closed",
        "service": COMMON_PORTS.get(port),
        "banner": None,
    }
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()

        line = f"[*] {host}: Port {port} open"
        if result["service"]:
            line += f" ({result['service']})"
        print(line)

        result["status"] = "open"
        banner_text = grabBanner(host, port, timeout)
        if banner_text:
            result["banner"] = banner_text
            line += f" | Banner: {banner_text[:80].replace(chr(10),' ')}"
        output.append(line)
    except ConnectionRefusedError:
        if verbosity:
            line = f"[*] {host}: Port {port} closed (refused)"
            output.append(line)
            print(line)
    except TimeoutError:
        if verbosity:
            line = f"[*] {host}: Connection timed out while scanning port {port}"
            output.append(line)
            print(line)
    except socket.timeout:
        if verbosity:
            line = f"[*] {host}: Socket timeout while scanning port {port}"
            output.append(line)
            print(line)
    except Exception as e:
        if verbosity:
            line = f"[*] {host}: Error on port {port}: {e}"
            output.append(line)
            print(line)
    finally:
        results_list.append(result)

def iter_ports(ports_spec):
    if len(ports_spec) == 1:
        yield ports_spec[0]
    else:
        a, b = ports_spec
        step = 1 if b >= a else -1
        for p in range(a, b + step, step):
            yield p

def scanHost(host, ports, threads, verbosity, timeout):
    """Return list of result dicts for the host."""
    results_list = []
    tasks = []
    port_list = list(iter_ports(ports))

    if threads > 1:
        with ThreadPoolExecutor(max_workers=threads) as executor:
            if HAVE_TQDM:
                futures = [
                    executor.submit(scanPort, host, p, verbosity, timeout, results_list)
                    for p in port_list
                ]
                for _ in tqdm(as_completed(futures), total=len(port_list), desc=f"Scanning {host}"):
                    pass
            else:
                for p in port_list:
                    futures = executor.submit(scanPort, host, p, verbosity, timeout, results_list)
    else:
        itr = tqdm(port_list, desc=f"Scanning {host}") if HAVE_TQDM else port_list
        for p in itr:
            scanPort(host, p, verbosity, timeout, results_list)

    return results_list

def write_text(filename, output_lines):
    try:
        with open(filename, 'w', encoding="utf-8") as f:
            for line in output_lines:
                f.write(f"{line}\n")
    except PermissionError:
        print("[*] Error writing to file. Permission denied")

def write_json(filename, results):
    try:
        with open(filename, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
    except PermissionError:
        print("[*] Error writing JSON. Permission denied")

def write_csv(filename, results):
    try:
        with open(filename, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["host", "port", "status", "service", "banner"])
            for r in results:
                writer.writerow([r.get("host"), r.get("port"), r.get("status"),
                                 r.get("service") or "", (r.get("banner") or "")])
    except PermissionError:
        print("[*] Error writing CSV. Permission denied")

def auto_write_output(path, output_lines, results):
    """
    Decide output format by file extension:
      .txt -> text lines (default)
      .json -> JSON results
      .csv -> CSV results
    """
    if not path:
        return
    lower = path.lower()
    if lower.endswith(".json"):
        write_json(path, results)
    elif lower.endswith(".csv"):
        write_csv(path, results)
    else:
        write_text(path, output_lines)

def main():
    global output
    parser = argparse.ArgumentParser(description="Lightweight threaded TCP port scanner with banners & reporting")
    parser.add_argument("host", help="Hostname/IP, comma list, or CIDR (e.g. 192.168.1.0/24 or host1,host2)")
    parser.add_argument("port", default="1-1000", nargs='?',
                        help="Port/s to scan e.g. 80 or 1-1024. Defaults to 1-1000")
    parser.add_argument("--threads", "-t", default=200, type=int,
                        help="Threads to use for scanning. Default 200")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", default=None,
                        help="Output file path (.txt, .json, or .csv). If omitted, no file is written.")
    parser.add_argument("-n", "--timeout", default=1.0, type=float,
                        help="Timeout (seconds) per port. Default 1.0")
    parser.add_argument("--no-progress", action="store_true",
                        help="Disable progress bar (even if tqdm is installed)")
    parser.add_argument("--os-guess", action="store_true",
                        help="Attempt basic OS fingerprint via ping TTL")
    args = parser.parse_args()

    output = [banner()]
    print(banner())

    verbosity = args.verbose
    threads = max(1, int(args.threads))
    ports = validatePorts(args.port)
    timeout = float(args.timeout)

    global HAVE_TQDM
    if args.no_progress:
        HAVE_TQDM = False
    targets, labels = expand_targets(args.host)

    all_results = []
    start_line = f"[*] Starting scan at {getCurrentDateTime()} UTC"
    output.append(start_line)
    print(start_line)

    try:
        for tgt in targets:
            label = labels.get(tgt, tgt)
            hdr = f"[*] Target {label} ({tgt})"
            output.append(hdr)
            print(hdr)

            if args.os_guess:
                os_guess = guessOS(tgt)
                os_line = f"[*] OS guess: {os_guess}"
                output.append(os_line)
                print(os_line)

            host_results = scanHost(tgt, ports, threads, verbosity, timeout)
            open_ports = [r["port"] for r in host_results if r["status"] == "open"]
            if open_ports:
                sum_line = f"[*] Open ports on {tgt}: {', '.join(str(p) for p in sorted(open_ports))}"
            else:
                sum_line = f"[*] No scanned ports were found open on {tgt}"
            output.append(sum_line)
            print(sum_line)
            all_results.extend(host_results)

    except KeyboardInterrupt:
        print("\n[*] Scan interrupted by user.")
    finally:
        end_line = f"[*] Finished scanning at {getCurrentDateTime()} UTC"
        output.append(end_line)
        print(end_line)

        if args.output:
            auto_write_output(args.output, output, all_results)

if __name__ == "__main__":
    main()
