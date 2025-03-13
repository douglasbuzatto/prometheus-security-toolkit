# Prometheus Security Toolkit

A toolkit for security analysis of exposed Prometheus servers.

## Requirements

- Python 3.8 or newer (tested with Python 3.12.4)
- Operating Systems: Windows 10/11, Linux, macOS
- Required Python packages:
  ```
  requests>=2.25.0
  concurrent.futures (included in Python standard library)
  argparse (included in Python standard library)
  json (included in Python standard library)
  socket (included in Python standard library)
  re (included in Python standard library)
  zipfile (included in Python standard library)
  datetime (included in Python standard library)
  logging (included in Python standard library)
  ```

## Installation

```bash
# Clone this repository
git clone https://github.com/vago00/prometheus-security-toolkit.git
cd prometheus-security-toolkit

# Install required dependencies
pip install requests
```

## Included Tools

The toolkit contains the following tools:

### 1. Prometheus Massacre Ultimate

Advanced tool for collecting and analyzing data from exposed Prometheus servers.

#### Basic Usage

```bash
python prometheus_massacre_ultimate.py --url http://your-prometheus:9090
```

#### Complete Options

| Option | Description |
|-------|-----------|
| `--url` | Prometheus target URL (ex: http://your-prometheus:9090) |
| `--stealth` | Stealth mode (1 req/sec) to avoid detection |
| `--massacre` | Massacre mode (maximum parallelism) for aggressive collection |
| `--depth` | Analysis depth (1-5), where 5 is the deepest |
| `--output` | Custom output directory for results |

#### Usage Examples

Basic analysis:
```bash
python prometheus_massacre_ultimate.py --url http://your-prometheus:9090
```

Stealthy analysis:
```bash
python prometheus_massacre_ultimate.py --url http://your-prometheus:9090 --stealth
```

Deep and aggressive analysis:
```bash
python prometheus_massacre_ultimate.py --url http://your-prometheus:9090 --massacre --depth 5
```

Analysis with custom directory:
```bash
python prometheus_massacre_ultimate.py --url http://your-prometheus:9090 --output prometheus_results
```

### 2. DoS Vulnerability Checker

Tool that checks if a Prometheus instance is vulnerable to denial of service attacks.

#### Basic Usage

```bash
python prometheus_ddos_vulnerability_checker.py -u http://your-prometheus:9090
```

#### Complete Options

| Option | Description |
|-------|-----------|
| `-u, --url` | Prometheus server URL (required) |
| `-t, --timeout` | Request timeout in seconds (default: 10) |
| `-c, --concurrency` | Number of concurrent tests (default: 3) |
| `-p, --port-timeout` | Port check timeout (default: 3.0) |
| `-v, --verbose` | Verbose mode with more information |
| `--no-banner` | Don't show the start banner |
| `--no-color` | Disable colors in output |
| `--log-file` | File to save logs (ex: prometheus_check.log) |
| `--username` | Username for basic authentication |
| `--password` | Password for basic authentication |
| `--token` | Authentication token |
| `--ignore-ssl` | Ignore SSL certificate verification |
| `--rate-limit-test` | Test for rate limiting implementation |
| `--output` | Output file for the JSON report |

#### Usage Examples

Basic check:
```bash
python prometheus_ddos_vulnerability_checker.py -u http://your-prometheus:9090
```

Check with authentication:
```bash
python prometheus_ddos_vulnerability_checker.py -u http://your-prometheus:9090 --username admin --password password
```

Complete check with rate limiting test:
```bash
python prometheus_ddos_vulnerability_checker.py -u http://your-prometheus:9090 --rate-limit-test --verbose
```

### 3. Dump Analyzer

Tool for advanced analysis of memory dumps looking for sensitive data.

#### Basic Usage

```bash
python dump_analise_advanced.py --dir directory_with_dumps
```

#### Complete Options

| Option | Description |
|-------|-----------|
| `--dir` | Directory containing dumps (.dump, pprof) [Required] |
| `--add-pattern` | Add custom regex pattern for search (can be used multiple times) |

#### Usage Examples

Basic dump analysis:
```bash
python dump_analise_advanced.py --dir ./prometheus_massacre_20250310_123456
```

Analysis with custom patterns:
```bash
python dump_analise_advanced.py --dir ./prometheus_massacre_20250310_123456 --add-pattern "password: \S+" --add-pattern "api_token: \S+"
```

## What Each Tool Does

### Prometheus Massacre Ultimate
This tool collects data from a Prometheus server through multiple endpoints, analyzing the responses for sensitive information such as:
- Credentials and access tokens
- API keys and secrets
- Internal IPs and hostnames
- Internal service URLs
- Infrastructure configuration and details

The depth of analysis defines how much the tool will explore:
- **Level 1**: Basic collection of standard endpoints
- **Levels 2-3**: Collects endpoints and executes PromQL queries
- **Levels 4-5**: Complete analysis with search for other services and exporters

### DoS Vulnerability Checker
This tool checks if a Prometheus instance is susceptible to denial of service attacks by examining:
- Vulnerable endpoints that consume many resources (ex: heap profiling)
- Potentially heavy PromQL queries
- Public exposure of the server
- Rate limiting implementation
- Vulnerabilities in federation endpoints

The tool generates a risk score from 0 to 10 and provides specific recommendations to mitigate detected vulnerabilities, without performing actual attacks on the target.

### Dump Analyzer
This tool examines memory dump files (.dump, pprof) extracted during a Prometheus attack. It looks for:
- API keys and tokens
- Passwords and credentials
- Emails and URLs
- Custom patterns defined by the user

## Results

### Prometheus Massacre Ultimate
The tool creates a directory with the following results:
- Dumps of all accessed endpoints
- Files with leaks marked as "LEAKS_*"
- Analysis of JSON results
- Final report "_RELATORIO_FINAL.txt"

### DoS Vulnerability Checker
The tool generates:
- Detailed report with vulnerability index
- List of all vulnerable endpoints
- Specific security recommendations
- JSON file with all results for later analysis

### Dump Analyzer
The tool creates:
- A timestamp subdirectory within the specified directory
- A JSON file with all leaks found

## Compatibility Notes

- **Windows Users**: The toolkit has been tested and confirmed working on Windows 11 with Python 3.12.4.
- **Linux/macOS Users**: All tools should work on Linux and macOS without any modifications.
- **Python Versions**: Compatible with Python 3.8 and newer. If using older versions, some features might require minor adjustments.
- **Terminal Colors**: For Windows users, terminal colors should work in modern terminals (Windows Terminal, PowerShell). If you experience issues with colors, use the `--no-color` option.

## Security Warning

⚠️ **IMPORTANT**: These tools should be used ONLY for educational, research, and authorized environments. Use against systems without express authorization is illegal and unethical.

## Responsible Use

- Use only on your own systems or with explicit permission
- Stealth mode should be used to minimize impact on systems
- Do not share sensitive data obtained from analysis

## License

This project is for educational and research purposes only. Use responsibly.
