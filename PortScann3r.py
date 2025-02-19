import socket
import argparse
import ipaddress
import sys
import re
from datetime import datetime
import pytz
from concurrent.futures import ThreadPoolExecutor


def banner():
    banner = '''
   ___           __      ____                   ____    
  / _ \___  ____/ /_____/ __/______ ____  ___  |_  /____
 / ___/ _ \/ __/ __/___/\ \/ __/ _ `/ _ \/ _ \_/_ </ __/
/_/   \___/_/  \__/   /___/\__/\_,_/_//_/_//_/____/_/

            Made with <3 by @mkdirlove
    '''
    return banner


def writeOutputToFile(filename, output):
    try:
        with open(filename, 'w') as f:
            for line in output:
                f.write(f"{line}\n")
    except PermissionError:
        print("[*] Error writing to file. Permission denied")


def getCurrentDateTime():
    time = datetime.now(pytz.utc)
    now = time.strftime("%H:%M:%S %d-%m-%Y")
    return now


def checkValidPortNumber(port):
    return port >= 0 and port <= 65535


def checkValidPortRange(ports):
    return (ports[0] < ports[1]) and checkValidPortNumber(ports[0]) and checkValidPortNumber(ports[1])


def validatePorts(port):
    if (str.isdigit(port)):
        result = int(port)
        if (checkValidPortNumber(result)):
            return [result]
        else:
            print('Invalid specification of port/s')
            sys.exit(-1)
    else:
        if (re.match('\d+-\d+', port)):
            ports = [int(x) for x in port.split('-')]
            if (not checkValidPortRange(ports)):
                print("Invalid specification of port/s")
                sys.exit(-1)
            return ports
        else:
            print("Invalid specification of ports/s")
            sys.exit(-1)


def resolveHost(host):
    global output
    try:
        ip = ipaddress.ip_address(host)
        line = f"[*] Will attempt scanning {host}"
        output.append(line)
        print(line)
        return host
    except ValueError:
        try:
            final_host = host
            if ("://" in final_host):
                final_host = final_host.split("://")[1]
            ip = socket.gethostbyname(final_host)
            line = f"[*] Hotname resolved to: {ip}"
            output.append(line)
            print(line)
            return ip
        except:
            print("Invalid host")
            sys.exit(-1)


def scanPort(host, port, verbosity, timeout):
    global open_ports, output
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()

        line = f"[*] Port {port} open"
        print(line)

        open_ports.append(port)
        output.append(line)
    except ConnectionRefusedError:
        pass
    except TimeoutError:
        if (verbosity):
            line = f"[*] Connection timed out while scanning port {port}"
            output.append(line)
            print(line)
        else:
            pass


def scanHost(host, ports, threads, verbosity, timeout):
    if (len(ports) > 1):
        with ThreadPoolExecutor(threads) as executor:
            for port in range(ports[0], ports[1] + 1):
                executor.submit(scanPort, host, port, verbosity, timeout)
    else:
        scanPort(host, ports[0], verbosity, timeout)


def main():
    global host, port, threads, verbosity, open_ports, output, filename, timeout

    start_line = f"[*] Starting scan at {getCurrentDateTime()} UTC"
    output.append(start_line)
    print(start_line)

    scanHost(host, port, threads, verbosity, timeout)

    end_line = f"[*] Finished scanning at {getCurrentDateTime()} UTC"
    output.append(end_line)
    print(end_line)

    if (not open_ports):
        line = "[*] No scanned ports were found open on host"
        output.append(line)
        print(line)
    if (filename):
        writeOutputToFile(filename, output)


if __name__ == "__main__":
    print(banner())

    parser = argparse.ArgumentParser()
    parser.add_argument("host", help="Hostname or IP to scan")
    parser.add_argument("port", default="1-1000", nargs='?',
                        help="Port/s to scan e.g 80 or 1-1024. By default 1-1000 will be scanned")
    parser.add_argument("--threads", "-t", default=10, type=int,
                        help="Threads to use for scanning. Default value is 10")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("-o", "--output", default=None, help="Output file to store results in")
    parser.add_argument("-n", "--timeout", default=1.0, help="Set timeout value (in seconds). Default value is 1.0s")
    args = parser.parse_args()

    output = [banner()]
    open_ports = []
    verbosity = args.verbose
    threads = args.threads
    port = validatePorts(args.port)
    host = resolveHost(args.host)
    filename = args.output
    timeout = args.timeout
    main()
