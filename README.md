# CrimsonEye Audit Tool

A lightweight Python security auditing utility that combines **File Integrity Monitoring (FIM)** with a **concurrent TCP connect scanner**.

CrimsonEye is designed for defensive security auditing, learning, and authorized testing. The current implementation uses only the Python standard library.

## Features

### File Integrity Monitoring

CrimsonEye can create and verify a SHA-256 baseline for files under a selected directory.

It can report:

- Added files
- Modified files
- Deleted files
- Files that could not be hashed
- Missing or corrupted baseline files
- Invalid or incompatible baseline structure

The baseline stores:

- Schema version
- Hash algorithm
- Audited directory
- SHA-256 hashes for successfully read files

The baseline itself is excluded from the monitored file set.

The file monitor also avoids traversing symbolic-link directories and skips symbolic-link files.

### TCP Port Scanning

CrimsonEye includes a basic TCP connect scanner.

Current capabilities:

- Scan a selected target
- Scan any TCP port range from `1` to `65535`
- Configurable timeout
- Configurable worker count
- Bounded concurrent scanning
- Report open TCP ports
- Attempt standard TCP service-name lookup for open ports
- Report unexpected scan errors separately

This is a **TCP connect scanner**, not a SYN/raw-packet scanner.

## Project Structure

```text
CrimsonEye-Audit-Tool/
├── auditor.py
├── file_monitor.py
├── network_scanner.py
├── README.md
└── .gitignore
```

## Requirements

- Python **3.10+** recommended
- No third-party Python packages are required

The current implementation uses Python standard-library modules including:

```text
argparse
concurrent.futures
datetime
hashlib
json
os
pathlib
socket
tempfile
```

## Installation

Clone the repository:

```bash
git clone https://github.com/purigauravkumar/CrimsonEye-Audit-Tool.git
cd CrimsonEye-Audit-Tool
```

Check your Python version:

```bash
python --version
```

On systems where `python` maps differently:

```bash
python3 --version
```

## Usage

Run:

```bash
python auditor.py --help
```

### Create a File Integrity Baseline

```bash
python auditor.py --dir ./test_directory --create-baseline
```

By default, the baseline is stored as:

```text
./test_directory/baseline.json
```

Use a custom baseline path:

```bash
python auditor.py --dir ./test_directory --create-baseline --baseline-file my-baseline.json
```

### Check File Integrity

```bash
python auditor.py --dir ./test_directory --check
```

Possible statuses include:

```text
OK
CHANGED
WARNING
ERROR
```

`CHANGED` means files were added, modified, or deleted.

`WARNING` means the audit could not fully verify all files, for example because some files could not be read.

`ERROR` indicates a baseline or audit error that prevented a normal integrity check.

### TCP Port Scan

The default target is:

```text
127.0.0.1
```

The default range is:

```text
1-1024
```

Run:

```bash
python auditor.py --dir ./test_directory --scan-ports
```

Scan a specific host:

```bash
python auditor.py --dir ./test_directory --scan-ports --target 192.168.1.10
```

Scan a custom range:

```bash
python auditor.py --dir ./test_directory --scan-ports --start-port 1 --end-port 65535
```

Change the timeout:

```bash
python auditor.py --dir ./test_directory --scan-ports --timeout 0.3
```

Change the worker count:

```bash
python auditor.py --dir ./test_directory --scan-ports --workers 100
```

### Run FIM and Port Scan Together

```bash
python auditor.py --dir ./test_directory --check --scan-ports
```

### Generate a JSON Report

```bash
python auditor.py --dir ./test_directory --check --json-report report.json
```

You can also combine JSON reporting with a network scan:

```bash
python auditor.py --dir ./test_directory --scan-ports --json-report report.json
```

## Example FIM Workflow

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

The report should identify `test.txt` as modified.

You can also test file addition:

```bash
echo "new file" > test_directory/new.txt
python auditor.py --dir test_directory --check
```

And deletion:

```bash
rm test_directory/new.txt
python auditor.py --dir test_directory --check
```

On Windows PowerShell, use the equivalent file creation and removal commands.

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Successful execution / no integrity changes |
| `1` | Warning or error |
| `2` | File integrity changes detected |
| `130` | User cancelled the audit with `Ctrl+C` |

These codes make the tool suitable for basic scripting and future CI integration.

## Security Design Notes

### SHA-256 Baseline

The file monitor uses SHA-256 to detect content changes.

The baseline is validated before use, including:

- Schema version
- Audited root directory
- File-entry types
- SHA-256 digest format

### Atomic Baseline Write

Baseline creation writes to a temporary file, flushes it, calls `fsync()`, and replaces the destination using `os.replace()`.

This reduces the chance of leaving a partially written baseline if the write is interrupted.

### Baseline Trust Limitation

The baseline is stored locally as a JSON file.

An attacker with sufficient permissions to modify both the monitored files and the baseline could potentially replace the expected hashes.

Therefore, the current baseline should **not** be treated as a tamper-proof security control.

For stronger protection, future versions could add:

- HMAC-protected baselines
- Digital signatures
- Remote or trusted baseline storage
- Stronger filesystem access controls

## Network Scanning Scope

The network component performs ordinary TCP connection attempts.

It does **not** currently provide:

- UDP scanning
- SYN/raw-packet scanning
- OS fingerprinting
- Full service/version fingerprinting
- Vulnerability detection
- Exploit testing
- Packet capture

Standard service-name lookup may identify names such as `ssh`, `http`, or `https` based on the port number. It does not prove which software or version is actually running.

## Limitations

Current limitations include:

- Local JSON baseline is not cryptographically authenticated
- No real-time filesystem event monitoring
- No UDP scanner
- No raw-packet/SYN scanner
- No vulnerability assessment engine
- No malware detection
- No centralized SIEM integration
- No distributed monitoring
- No full service/banner fingerprinting
- No built-in HTML/PDF report generation

## Roadmap

- [ ] HMAC-protected baseline
- [ ] Digital signature support
- [ ] Real-time filesystem monitoring
- [ ] File exclusion patterns
- [ ] HTML reporting
- [ ] CSV reporting
- [ ] Unit-test suite
- [ ] GitHub Actions CI
- [ ] Improved service/banner detection
- [ ] IPv6 support
- [ ] UDP scanning
- [ ] SIEM integration
- [ ] Alerting and notifications

## Responsible Use

Use CrimsonEye only on:

- Systems you own
- Lab environments
- Networks where you have explicit permission to perform security testing

Do not scan third-party systems without authorization.

## License

No explicit license file is currently included in the repository.

If you want others to freely reuse and modify the project, add an appropriate open-source license such as the MIT License.
