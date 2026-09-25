# Serverless Function Security Auditor

A lightweight, defensive, command-line security auditing tool in Python designed to inspect serverless function source code and configuration files (such as AWS Lambda and Azure Functions) for critical vulnerabilities, excessive permissions, and insecure coding patterns.

---

## 📌 Features

### Phase 1: Static Configuration & Secret Auditing
1. **Hardcoded Secret Detection (`scanners/secret_scanner.py`)**:
   - Detects API keys, passwords, database credentials, AWS access keys (`AKIA...`), AWS secret access keys, and bearer tokens.
   - Evaluates variable assignments containing actual values to reduce noise.
   - Labels findings as *"Possible hardcoded secret"*.
2. **AWS IAM Policy Analysis (`scanners/iam_scanner.py`)**:
   - Analyzes JSON policy templates for excessive privileges and least-privilege violations.
   - Detects Full Admin Wildcards (`Action: "*"` + `Resource: "*"`), Privilege Escalation (`iam:*`), and Service Wildcards (`s3:*`, `dynamodb:*`, `lambda:*`).

### Phase 2: AST Code Analysis & Injection Detection
1. **Abstract Syntax Tree (AST) Analysis (`analyzers/ast_analyzer.py`)**:
   - Uses Python's built-in `ast` module to analyze Python code without executing it.
   - Tracks data flow from external serverless inputs through variable assignments and string operations.
2. **Serverless Event Input Detection (`scanners/event_scanner.py`)**:
   - Detects untrusted entry points: `event["username"]`, `event.get("host")`, `request.args`, etc.
   - Emits informational `LOW` severity findings to encourage validation.
3. **Dangerous Sink & Injection Detection (`scanners/injection_scanner.py`)**:
   - **Command Injection (`CRITICAL`)**: External input flowing into `os.system()`, `os.popen()`, or `subprocess.run()`.
   - **SQL Injection (`HIGH`)**: External input concatenated (`+` or f-strings) into SQL queries executed by `cursor.execute()`.
   - **Unsafe Input Handling (`MEDIUM`)**: External input reaching filesystem calls (`open()`) without path sanitization.

---

## 📂 Project Structure

```text
serverless-security-auditor/
│
├── scanner.py                  # CLI entry point, scan coordinator & reporter
│
├── analyzers/
│   ├── __init__.py             # Exports AST analyzer components
│   └── ast_analyzer.py         # AST parser, source extractor, and taint tracker
│
├── scanners/
│   ├── __init__.py             # Exports all scanner modules
│   ├── secret_scanner.py       # Regex-based scanner for secrets & credentials (Phase 1)
│   ├── iam_scanner.py          # Static JSON analyzer for AWS IAM policies (Phase 1)
│   ├── event_scanner.py        # Serverless input detector (Phase 2)
│   └── injection_scanner.py    # Source-to-sink injection vulnerability scanner (Phase 2)
│
├── models/
│   ├── __init__.py             # Exports data models
│   └── finding.py              # Structured Finding dataclass & Severity enum
│
├── demo/
│   ├── safe_function.py        # Secure Lambda handler using environment variables
│   ├── vulnerable_function.py  # Function with fake credentials
│   ├── injection_function.py   # Function with injection vulnerabilities & safe patterns
│   └── policy.json             # Insecure IAM policy with wildcard actions & resources
│
├── tests/
│   ├── __init__.py
│   ├── test_secrets.py         # Unit tests for secret scanner logic
│   ├── test_iam.py             # Unit tests for IAM policy analysis
│   ├── test_event.py           # Unit tests for serverless event detection
│   └── test_injection.py       # Unit tests for SQLi, Command Injection & safe patterns
│
├── requirements.txt            # Optional dependencies (e.g., pytest)
└── README.md                   # Project documentation
```

---

## ⚙️ Installation & Prerequisites

- **Python**: Version 3.11 or newer (Python 3.14+ supported).
- **Core Dependencies**: None required! The scanner relies 100% on Python standard libraries (`ast`, `dataclasses`, `re`, `json`, `argparse`, `pathlib`, `unittest`).

### Optional: Install `pytest` for testing

```bash
pip install -r requirements.txt
```

---

## 🚀 How to Run the Scanner

Navigate to the project root directory:

```bash
cd serverless-security-auditor
```

### 1. Scan the built-in Demo suite

```bash
python scanner.py demo
```

### 2. Scan a specific file

```bash
python scanner.py demo/safe_function.py
```

### 3. Scan an external serverless project

```bash
python scanner.py C:/path/to/your/serverless-project
```

### 4. Export findings in structured JSON format

```bash
python scanner.py demo --format json
```

---

## 🧪 Running Unit Tests

Run the full test suite across all Phase 1 and Phase 2 tests using Python's built-in `unittest` runner:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Or using `pytest`:

```bash
pytest -v
```

---

## 🔮 Phase 3 Roadmap & Future Extensions

In future phases, the auditor can be expanded into an enterprise platform:
1. **Interactive HTML & Executive Reporting**: Generating styled HTML dashboards with compliance matrices and severity graphs.
2. **Direct Cloud Integration**: Pulling live Lambda functions and IAM roles via AWS Boto3 / Azure SDK to scan deployed infrastructure directly.
3. **AI-Assisted Remediation Suggestions**: Integrating local LLMs to generate pull requests and sanitized code fixes automatically.
