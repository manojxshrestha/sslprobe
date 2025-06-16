#!/usr/bin/env python
# Description: SSLProbe is a highly advanced tool for scanning IP ranges and extracting detailed SSL/TLS certificate information.
# Usage: python sslprobe.py --cidr <CIDR> [--ports <PORTS>] [--output <FILE>] [--format <json|csv|html>] [--rate <RATE>] [--validate] [--no-wildcards] [--config <FILE>] [--verbose]
# Example: python sslprobe.py --cidr 10.100.100.0/24 --ports 443,8443 --output results.html --format html --rate 1000
# Python Dependencies: Install with `pip install -r requirements.txt`
# System Dependencies: masscan binary (e.g., sudo apt-get install masscan on Debian/Ubuntu)
# Note: Run with sudo if masscan requires root privileges. Use the virtual environment's Python path with sudo (e.g., sudo /path/to/venv/bin/python sslprobe.py).
# Note: Always use a virtual environment to comply with PEP 668 and avoid system Python conflicts.
# Note: All output files (report, database, log) are saved in the 'results' folder.
# Warning: Ensure you have explicit permission to scan target networks. Unauthorized scanning may be illegal.

import sys
import socket
import ssl
import ipaddress
import json
import csv
import logging
import argparse
import sqlite3
import yaml
import asyncio
import aiohttp
import os
import shutil
from datetime import datetime
from tqdm import tqdm
from retrying import retry

# Try importing optional dependencies with error handling
try:
    from jinja2 import Template
except ImportError:
    print("Error: Jinja2 is not installed. Install it with: pip install -r requirements.txt")
    sys.exit(1)
try:
    from OpenSSL import SSL
    from ndg.httpsclient.subj_alt_name import SubjectAltName
    from pyasn1.codec.der import decoder as der_decoder
except ImportError:
    print("Error: Missing OpenSSL or related dependencies. Install with: pip install -r requirements.txt")
    sys.exit(1)
try:
    import masscan
except ImportError:
    print("Error: python-masscan is not installed. Install it with: pip install -r requirements.txt")
    sys.exit(1)

# Set up results directory
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')
if not os.path.exists(RESULTS_DIR):
    try:
        os.makedirs(RESULTS_DIR)
    except Exception as e:
        print(f"Error: Failed to create results directory {RESULTS_DIR}: {e}")
        sys.exit(1)

# Configure logging to save to results folder
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(os.path.join(RESULTS_DIR, 'sslprobe.log'))
    ]
)
logger = logging.getLogger(__name__)

def check_dependencies():
    """Verify all required Python and system dependencies."""
    # Check Python dependencies
    required_python = ['masscan', 'aiohttp', 'tqdm', 'yaml', 'jinja2', 'retrying']
    missing_python = []
    for module in required_python:
        try:
            __import__(module)
        except ImportError:
            missing_python.append(module)
    if missing_python:
        logger.error(f"Missing Python dependencies: {', '.join(missing_python)}. Install with: pip install -r requirements.txt")
        sys.exit(1)

    # Check system dependencies (masscan binary)
    if not shutil.which('masscan'):
        logger.error("masscan binary not found in PATH. Install it with: sudo apt-get install masscan (Debian/Ubuntu)")
        logger.error("Verify PATH includes /usr/bin or /usr/local/bin: echo $PATH")
        sys.exit(1)

def check_virtual_env():
    """Warn if system Python is used when a virtual environment is detected."""
    if 'VIRTUAL_ENV' in os.environ and sys.executable.startswith('/usr'):
        logger.error(f"Using system Python ({sys.executable}) with sudo, which may lack virtual environment packages.")
        logger.error(f"Use the virtual environment's Python: sudo {os.environ['VIRTUAL_ENV']}/bin/python {' '.join(sys.argv)}")
        sys.exit(1)

def display_banner():
    """Display the tool banner and usage instructions."""
    print("-" * 80)
    print(r"""
                                                                                  
                     ,dPYb,                                    ,dPYb,             
                     IP'`Yb                                    IP'`Yb             
                     I8  8I                                    I8  8I             
                     I8  8'                                    I8  8'             
   ,g,       ,g,     I8 dP  gg,gggg,     ,gggggg,    ,ggggg,   I8 dP       ,ggg,  
  ,8'8,     ,8'8,    I8dP   I8P'  'Yb    dP''''8I   dP'  'Y8gggI8dP   88ggi8' '8i 
 ,8'  Yb   ,8'  Yb   I8P    I8'    ,8i  ,8'    8I  i8'    ,8I  I8P    8I  I8, ,8I 
,8'_   8) ,8'_   8) ,d8b,_ ,I8 _  ,d8' ,dP     Y8,,d8,   ,d8' ,d8b,  ,8I  `YbadP' 
P' "YY8P8PP' "YY8P8P8P'"Y88PI8 YY88888P8P      `Y8P"Y8888P"   8P'"Y88P"' 888P"Y888
                            I8                                                    
                            I8                                                    
                            I8    Advanced scanning tool for SSL/TLS certificate details.
                            I8                        by ~/.manojxshrestha       
                            I8                                                    
                            I8                                                             
    """)
    print("Usage: python sslprobe.py --cidr <CIDR> [--ports <PORTS>] [--output <FILE>] [--format <json|csv|html>] [--rate <RATE>]")
    print("Example: python sslprobe.py --cidr 10.100.100.0/24 --ports 443,8443 --output results.html --format html")
    print("-" * 80)
    print("WARNING: Ensure you have proper authorization before scanning. Unauthorized scanning may be illegal.")

def get_subject_alt_names(peer_cert):
    """Extract Subject Alternative Names (SANs) from the certificate."""
    dns_names = []
    general_names = SubjectAltName()
    try:
        for i in range(peer_cert.get_extension_count()):
            ext = peer_cert.get_extension(i)
            if ext.get_short_name() == b"subjectAltName":
                ext_data = ext.get_data()
                decoded = der_decoder.decode(ext_data, asn1Spec=general_names)
                for name in decoded[0]:
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        dns_names.append(str(component.getComponent()))
    except Exception as e:
        logger.debug(f"Failed to parse SAN: {e}")
    return dns_names

@retry(stop_max_attempt_number=3, wait_fixed=1000)
async def fetch_certificate_details(ip_addr, port, validate_cert=False):
    """Fetch SSL/TLS certificate details asynchronously."""
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
    if validate_cert:
        ssl_context.verify_mode = ssl.CERT_REQUIRED
        ssl_context.load_default_certs()
    else:
        ssl_context.verify_mode = ssl.CERT_NONE
    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(f"https://{ip_addr}:{port}", ssl=ssl_context, timeout=2) as resp:
                cert = resp.connection.transport.get_extra_info('peercert')
                name = cert.get('subject', ((('commonName', ''),),))[0][1]
                issuer = cert.get('issuer', ((('organizationName', ''),),))[0][1]
                expiry = cert.get('notAfter')
                alt_names = get_subject_alt_names(SSL.crypto.X509.from_cryptography(cert))
                if not alt_names:
                    alt_names.append(name)
                return {
                    "domains": alt_names,
                    "issuer": issuer,
                    "expiry": expiry
                }
        except Exception as e:
            logger.debug(f"Failed to retrieve certificate from {ip_addr}:{port}: {e}")
            return None

async def scan_host(host, port, validate_cert):
    """Scan a single host and port for SSL/TLS certificate details."""
    try:
        result = await fetch_certificate_details(host, port, validate_cert)
        return host, port, result
    except Exception as e:
        logger.error(f"Error scanning {host}:{port}: {e}")
        return host, port, None

def initialize_database():
    """Initialize the SQLite database for storing results."""
    db_path = os.path.join(RESULTS_DIR, 'sslprobe.db')
    try:
        conn = sqlite3.connect(db_path)
        conn.execute('''CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT,
            port INTEGER,
            domains TEXT,
            issuer TEXT,
            expiry TEXT,
            scanned_at TIMESTAMP
        )''')
        return conn
    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database at {db_path}: {e}")
        sys.exit(1)

def save_to_database(conn, ip, port, result):
    """Save scan results to the database."""
    if result:
        try:
            conn.execute('''INSERT INTO results (ip, port, domains, issuer, expiry, scanned_at)
                            VALUES (?, ?, ?, ?, ?, ?)''',
                         (ip, port, ','.join(result['domains']), result['issuer'], result['expiry'], datetime.now()))
            conn.commit()
        except sqlite3.Error as e:
            logger.error(f"Failed to save to database: {e}")

def filter_wildcards(domains, exclude_wildcards):
    """Filter out wildcard domains if specified."""
    if exclude_wildcards:
        return [d for d in domains if not d.startswith('*.')]
    return domains

def save_results_to_file(results, output_file, output_format, exclude_wildcards):
    """Save scan results to a file in the specified format."""
    if not output_file:
        return
    output_path = os.path.join(RESULTS_DIR, output_file)
    filtered_results = [
        {
            "ip": ip,
            "port": port,
            "domains": filter_wildcards(r['domains'], exclude_wildcards),
            "issuer": r['issuer'],
            "expiry": r['expiry']
        }
        for ip, port, r in results if r
    ]
    try:
        if output_format == "json":
            with open(output_path, 'w') as f:
                json.dump(filtered_results, f, indent=2)
        elif output_format == "csv":
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Port", "Domains", "Issuer", "Expiry"])
                for r in filtered_results:
                    writer.writerow([r['ip'], r['port'], ",".join(r['domains']), r['issuer'], r['expiry']])
        elif output_format == "html":
            template_path = os.path.join(os.path.dirname(__file__), 'report_template.html')
            with open(template_path, 'r') as f:
                template = Template(f.read())
            with open(output_path, 'w') as f:
                f.write(template.render(results=filtered_results, scan_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
        logger.info(f"Results saved to {output_path}")
    except Exception as e:
        logger.error(f"Failed to save results to {output_path}: {e}")

def validate_cidr(cidr):
    """Validate the provided CIDR range and warn if large."""
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        num_ips = sum(1 for _ in network.hosts()) + 2  # Include network and broadcast
        if num_ips > 1000:
            logger.warning(f"Large CIDR range ({num_ips} IPs). Scan may take significant time. Consider a smaller range for testing.")
        return True
    except ValueError:
        logger.error("Invalid CIDR range. Example: 10.100.100.0/24")
        return False

def load_config(config_file):
    """Load configuration from a YAML file."""
    if config_file:
        try:
            with open(config_file, 'r') as f:
                config = yaml.safe_load(f)
                return config or {}
        except Exception as e:
            logger.error(f"Failed to load config file {config_file}: {e}")
            return {}
    return {}

def check_command_syntax(args):
    """Check for common command syntax errors."""
    if '--cidr' in sys.argv and sys.argv[sys.argv.index('--cidr') + 1].endswith('--'):
        logger.error("Syntax error: No space between --cidr value and next argument. Example: --cidr 10.100.100.0/24 --ports 443")
        sys.exit(1)

async def main():
    """Main function to parse arguments and execute the scan."""
    check_virtual_env()
    check_dependencies()
    parser = argparse.ArgumentParser(description="SSLProbe: Extract hostnames and details from SSL/TLS certificates")
    parser.add_argument("--cidr", help="CIDR range to scan (e.g., 10.100.100.0/24)")
    parser.add_argument("--ports", default="443", help="Comma-separated ports to scan (e.g., 443,8443)")
    parser.add_argument("--output", help="Output file for results")
    parser.add_argument("--format", choices=["json", "csv", "html"], default="json", help="Output format (json, csv, html)")
    parser.add_argument("--rate", type=int, default=1000, help="Scan rate (packets per second, default: 1000)")
    parser.add_argument("--validate", action="store_true", help="Validate certificates against trusted CAs")
    parser.add_argument("--no-wildcards", action="store_true", help="Exclude wildcard domains from results")
    parser.add_argument("--config", help="YAML configuration file")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose logging")
    args = parser.parse_args()

    check_command_syntax(args)

    config = load_config(args.config)
    args.cidr = args.cidr or config.get('cidr')
    args.ports = args.ports or config.get('ports', '443')
    args.output = args.output or config.get('output')
    args.format = args.format or config.get('format', 'json')
    args.rate = args.rate or config.get('rate', 1000)
    args.validate = args.validate or config.get('validate', False)
    args.no_wildcards = args.no_wildcards or config.get('no_wildcards', False)

    if not args.cidr:
        logger.error("CIDR range is required. Specify via --cidr or config file.")
        sys.exit(1)

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    display_banner()
    if not validate_cidr(args.cidr):
        sys.exit(1)

    ports = [int(p) for p in args.ports.split(',')]
    logger.info(f"Starting scan on {args.cidr} for ports {args.ports} at rate {args.rate}")

    # Initialize database
    db_conn = initialize_database()

    mas = masscan.PortScanner()
    try:
        mas.scan(args.cidr, ports=','.join(map(str, ports)), arguments=f'--rate {args.rate}')
    except Exception as e:
        logger.error(f"Masscan failed: {e}")
        db_conn.close()
        sys.exit(1)

    results = []
    tasks = [(host, port) for host in mas.all_hosts for port in ports]
    for task in tqdm(tasks, desc="Scanning", unit="host"):
        host, port = task
        result = await scan_host(host, port, args.validate)
        results.append(result)
        save_to_database(db_conn, host, port, result[2])
        if result[2]:
            logger.info(f"{host}:{port}: {','.join(result[2]['domains'])} (Issuer: {result[2]['issuer']}, Expiry: {result[2]['expiry']})")
        else:
            logger.info(f"{host}:{port}: fail")

    db_conn.close()

    if args.output:
        save_results_to_file(results, args.output, args.format, args.no_wildcards)

    logger.info(f"Scan completed. Found {sum(1 for _, _, r in results if r)} successful extractions.")

if __name__ == "__main__":
    asyncio.run(main())
