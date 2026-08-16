# Security Auditor

A Python-based security auditing tool that combines **File Integrity Monitoring (FIM)** with a basic **TCP port scanner**.

## Features

### File Integrity Monitoring
- Creates a SHA-256 baseline of files in a directory.
- Detects added, modified, and deleted files.
- Handles inaccessible files separately.
- Validates the baseline structure.
- Detects corrupted or incompatible baseline files.
- Excludes the baseline itself from monitoring.
- Does not follow symbolic-link directories.
- Writes the baseline atomically.
- Provides useful exit codes for scripting and CI.

### TCP Port Scanner
- Scans TCP ports on a specified target.
- Supports ports `1-65535`.
- Configurable timeout.
- Uses bounded concurrent scanning.
- Reports open ports.
- Attempts standard TCP service identification.
- Handles normal connection failures separately from unexpected errors.

### Reporting
- Human-readable terminal report.
- Optional JSON report.
- Audit statuses: `OK`, `CHANGED`, `WARNING`, and `ERROR`.

## Project Structure

```text
security-auditor/
├── auditor.py
├── file_monitor.py
├── network_scanner.py
├── README.md
└── .gitignore
```

## Requirements

- Python 3.10+ recommended.
- No third-party packages are required by the current implementation.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/security-auditor.git
cd security-auditor
```

Check Python:

```bash
python --version
```

On some Linux systems:

```bash
python3 --version
```

## Usage

### Create a baseline

```bash
python auditor.py --dir ./test_directory --create-baseline
```

This creates `baseline.json` inside the monitored directory.

### Check file integrity

```bash
python auditor.py --dir ./test_directory --check
```

If nothing changed:

```text
Audit Status: OK
```

If files were added, modified, or deleted:

```text
Audit Status: CHANGED
```

### Scan TCP ports

Default target is localhost and the default range is `1-1024`:

```bash
python auditor.py --dir ./test_directory --scan-ports
```

Custom target:

```bash
python auditor.py --dir ./test_directory --scan-ports --target 192.168.1.10
```

Custom port range:

```bash
python auditor.py --dir ./test_directory --scan-ports --start-port 1 --end-port 65535
```

Custom timeout and worker count:

```bash
python auditor.py --dir ./test_directory --scan-ports --timeout 0.3 --workers 100
```

### Generate a JSON report

```bash
python auditor.py --dir ./test_directory --check --json-report report.json
```

## Example Workflow

Create a test directory:

```bash
mkdir test_directory
```

Create a file:

```bash
echo "hello" > test_directory/test.txt
```

Create the baseline:

```bash
python auditor.py --dir test_directory --create-baseline
```

Modify the file:

```bash
echo "modified" > test_directory/test.txt
```

Run the integrity check:

```bash
python auditor.py --dir test_directory --check
```

The tool should report `test.txt` as modified.

## Exit Codes

| Exit code | Meaning |
|---:|---|
| `0` | Successful audit / no integrity changes |
| `1` | Warning or error |
| `2` | Integrity changes detected |
| `130` | Audit cancelled with Ctrl+C |

## Security Considerations

This project is intended for defensive and authorized security auditing.

### Baseline trust

The baseline is stored as JSON. If an attacker can modify both the monitored files and the baseline, they may be able to replace the expected hashes.

The current baseline therefore should **not** be considered a tamper-proof security control.

For stronger protection, future versions could use:

- HMAC with securely stored key material
- Digital signatures
- A trusted remote baseline
- Write-protected or access-controlled storage

### Port scanning

Only scan systems you own or have explicit authorization to test.

This is a basic TCP connection scanner and is not intended to replace mature tools such as Nmap.

## Limitations

The current implementation does not provide:

- Full OS/service fingerprinting
- UDP scanning
- SYN/raw-packet scanning
- Vulnerability detection
- Malware detection
- Cryptographically signed baselines
- SIEM integration
- Distributed monitoring
- Real-time filesystem event monitoring

## Roadmap

- [ ] HMAC-protected baselines
- [ ] Digital signature support
- [ ] HTML reports
- [ ] CSV reports
- [ ] Email alerts
- [ ] SIEM integration
- [ ] Configuration file support
- [ ] File exclusion patterns
- [ ] Real-time monitoring
- [ ] Unit tests
- [ ] GitHub Actions CI
- [ ] Service/version fingerprinting
- [ ] IPv6 scanning
- [ ] UDP scanning

## Disclaimer

This project is provided for educational, defensive-security, and authorized auditing purposes.

Do not use the network-scanning functionality against systems or networks without appropriate authorization.

## License

This project is licensed under the MIT License. See `LICENSE` for details.
