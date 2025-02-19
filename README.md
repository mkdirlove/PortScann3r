# PortScann3r

PortScann3r is a basic tool designed to scan ports on a specified host, identify open ports, and provide banner information. It is built using Python and leverages multithreading for efficient scanning.

## Features

- **Port Scanning**: Scan specified ports or a range of ports to check their status (open/closed) on a given host.
- **Verbose Output**: Option to enable verbose output for detailed information about the scanning process.
- **Multithreading**: Utilize multiple threads to speed up the scanning process.
- **Output to File**: Save the scanning results to a file.

## Requirements

- Python 3.6+
- Required Python packages (install using `pip install -r requirements.txt`):
  - argparse
  - socket
  - ipaddress
  - re
  - datetime
  - pytz
  - concurrent.futures

## Installation

Clone the repository:

```bash
git clone https://github.com/mkdirlove/PortScann3r.git
cd PortScann3r
```

Install the required packages:

```bash
python3 -m pip install -r requirements.txt
```
## Usage

Run the script using Python and provide the necessary arguments:

```bash
python PortScann3r.py <host> [port] [--threads THREADS] [--verbose] [-o OUTPUT] [-n TIMEOUT]
```

### Command Line Arguments

- `<host>`: The hostname or IP address to scan.
- `[port]`: Port(s) to scan, e.g., `80` or `1-1024`. By default, ports `1-1000` will be scanned.
- `--threads` or `-t`: Number of threads to use for scanning (default: 10).
- `--verbose` or `-v`: Enable verbose output.
- `-o` or `--output`: Output file to store results in.
- `-n` or `--timeout`: Set timeout value (in seconds) for each connection attempt (default: 1.0s).

### Example Usage

```bash
python PortScann3r.py example.com 1-1024 --threads 20 --verbose -o results.txt -n 0.5
```

This command will scan ports `1-1024` on `example.com` using `20` threads, with verbose output enabled, save the results to `results.txt`, and set a timeout of `0.5` seconds for each connection attempt.

## Contributing

Contributions are welcome! Please submit a pull request or open an issue to discuss what you would like to change.
