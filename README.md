# SSLProbe

**SSLProbe** is an advanced SSL/TLS scanning tool that quickly scans IP ranges, extracts detailed certificate information, and generates comprehensive reports. It uses `masscan` for high-speed port scanning and supports asynchronous certificate retrieval. Results can be saved in **JSON, CSV, or HTML** formats.

> ⚠️ **Disclaimer:** Always obtain explicit permission before scanning any network. Unauthorized scanning may be illegal.

---

## 🚀 Features

* 🔍 Fast scanning of CIDR IP ranges using `masscan`.
* 📜 Extracts SSL/TLS certificate details:

  * Domains
  * Issuer
  * Expiry Date
* ✅ Supports certificate validation against trusted CAs.
* 🚫 Option to exclude wildcard domains with `--no-wildcards`.
* 💾 Saves results to:

  * SQLite database
  * JSON, CSV, or HTML reports
* ⚙️ Fully configurable via YAML files.
* 📊 Real-time progress bar with `tqdm` and verbose logging.
* 🐍 Follows **PEP 668**: recommends using Python virtual environments.

---

## 📦 Prerequisites

### System Dependencies

* **masscan**: High-speed port scanner.

  #### Install on Debian/Ubuntu:

  ```bash
  sudo apt-get update
  sudo apt-get install masscan
  ```

  #### Verify installation:

  ```bash
  masscan --version
  ```

### Python Dependencies

```bash
Python 3.8+
```

---

## ⚙️ Installation

# Clone the repository
```bash
git clone https://github.com/manojxshrestha/sslprobe.git
cd sslprobe
```

# Create and activate a virtual environment
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

# Install Python Packages Manually
```bash
pip install python-masscan==0.1.6
pip install ndg-httpsclient==0.5.1
pip install pyasn1==0.6.1
pip install retrying==1.3.4
pip install aiohttp==3.10.5
pip install tqdm==4.66.5
pip install pyyaml==6.0.2
pip install jinja2==3.1.4
```

Make sure `masscan` is installed (see prerequisites).

---

## 🛠️ Usage

You may need to run the script with `sudo` if `masscan` requires elevated privileges.

```bash
sudo ./venv/bin/python sslprobe.py --cidr <CIDR> \
    [--ports <PORTS>] \
    [--output <FILE>] \
    [--format <json|csv|html>] \
    [--rate <RATE>] \
    [--validate] \
    [--no-wildcards] \
    [--config <FILE>] \
    [--verbose]
```

### Example

```bash
sudo ./venv/bin/python sslprobe.py --cidr 93.184.216.34/32 --ports 443 --output report.html --format html --rate 500 --verbose
```

---

### Custom Scan

```bash
sudo ./venv/bin/python sslprobe.py  --cidr 93.184.216.34/32 --ports 443,8443,465,636,993,995 --output exposed_servers.html --format html --rate 1000 --no-wildcards --verbose
```

---

### Manual Certificate Parsing if SSLProbe Fails

```bash
sudo masscan 93.184.216.34/32 -p443,8443,465,636,993,995 --rate 1000 -oL open_ports.txt
```

---

## ⚡ Command Options

| Option           | Description                                      |
| ---------------- | ------------------------------------------------ |
| `--cidr`         | CIDR range to scan (e.g., 10.100.100.0/24)       |
| `--ports`        | Comma-separated list of ports (default: 443)     |
| `--output`       | Output file name (saved in the `results` folder) |
| `--format`       | Output format: `json`, `csv`, or `html`          |
| `--rate`         | Scan rate in packets per second (default: 1000)  |
| `--validate`     | Validate certificates against trusted CAs        |
| `--no-wildcards` | Exclude wildcard domains                         |
| `--config`       | YAML configuration file                          |
| `--verbose`      | Enable detailed logging                          |

---

## 📂 Outputs

* **Files:** Saved in the `results` folder.
* **Database:** SQLite DB at `results/sslprobe.db`
* **HTML Report:** View in any browser at `results/report.html`
* **Logs:** Detailed logs at `results/sslprobe.log`

### Query the Database

```bash
sqlite3 results/sslprobe.db "SELECT ip, port, domains, issuer, expiry FROM results"
```

---

## ⚙️ Configuration

You can create a `config.yaml` file to store default settings:

```yaml
cidr:
ports: 443,8443
output: report.html
format: html
rate: 1000
validate: true
no_wildcards: true
```

---

## 📝 Notes

* ✅ Always use a **virtual environment** to avoid system Python conflicts (PEP 668).
* 🔐 Make sure you have **write permissions** to the `results` folder:

  ```bash
  chmod -R 775 results
  chown -R $(whoami):$(whoami) results
  ```
* 🧪 **Test with a known target** before large scans:

  ```bash
  sudo ./venv/bin/python sslprobe.py --cidr 93.184.216.34/32 --ports 443 --output report.html --format html --verbose
  ```

---

## 🤝 Contributing

Contributions are welcome! Please open an issue or submit a pull request on [GitHub](https://github.com/manojxshrestha/sslprobe).
