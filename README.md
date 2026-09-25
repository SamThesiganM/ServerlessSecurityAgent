# Serverless Function Security Auditor

A lightweight, defensive security auditing tool and interactive web dashboard designed to inspect serverless function source code and configuration files (such as AWS Lambda and Azure Functions) for critical vulnerabilities, excessive IAM permissions, and insecure coding patterns.

---

## 🔒 Security Notice (Static Analysis Only)

**Uploaded code is NEVER executed, compiled, or deployed.**  
The auditor strictly performs offline static Abstract Syntax Tree (AST) inspection, regular-expression heuristics, and JSON policy structure evaluation. Uploaded ZIP files are extracted to isolated temporary directories for static analysis only and immediately discarded.

---

## 📌 Features

### Phase 1: Static Configuration & Secret Auditing
1. **Hardcoded Secret Detection (`scanners/secret_scanner.py`)**:
   - Detects API keys, passwords, database credentials, AWS access keys (`AKIA...`), AWS secret access keys, and bearer tokens.
   - Evaluates variable assignments containing actual values to reduce false positives.
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

### Web Dashboard: Streamlit Application (`app.py`)
- Interactive web interface for both desktop and cloud usage.
- One-click demo audit on built-in serverless functions.
- Secure ZIP upload for auditing arbitrary serverless project folders.
- Severity filtering (`All`, `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- Actionable security recommendations and audited file listings.

---

## 📂 Project Structure

```text
serverless-security-auditor/
│
├── app.py                      # Streamlit interactive web dashboard
├── scanner.py                  # CLI entry point, scan coordinator & reporter
│
├── analyzers/                  # AST Syntax & Data-Flow Analysis
│   ├── __init__.py             # Exports AST analyzer components
│   └── ast_analyzer.py         # AST parser, source extractor, and taint tracker
│
├── scanners/                   # Specialized Security Detections
│   ├── __init__.py             # Exports all scanner modules
│   ├── secret_scanner.py       # Regex-based scanner for secrets & credentials (Phase 1)
│   ├── iam_scanner.py          # Static JSON analyzer for AWS IAM policies (Phase 1)
│   ├── event_scanner.py        # Serverless input detector (Phase 2)
│   └── injection_scanner.py    # Source-to-sink injection vulnerability scanner (Phase 2)
│
├── models/                     # Shared Finding Data Models
│   ├── __init__.py             # Exports data models
│   └── finding.py              # Structured Finding dataclass & Severity enum
│
├── demo/                       # Benchmark Demonstration Files (Fake Test Data Only)
│   ├── safe_function.py        # Secure Lambda handler using environment variables
│   ├── vulnerable_function.py  # Function with fake credentials
│   ├── injection_function.py   # Function with injection vulnerabilities & safe patterns
│   └── policy.json             # Insecure IAM policy with wildcard actions & resources
│
├── tests/                      # Automated Unit Test Suite (26 Passing Tests)
│   ├── __init__.py
│   ├── test_secrets.py         # Unit tests for secret scanner logic
│   ├── test_iam.py             # Unit tests for IAM policy analysis
│   ├── test_event.py           # Unit tests for serverless event detection
│   └── test_injection.py       # Unit tests for SQLi, Command Injection & safe patterns
│
├── .github/workflows/          # CI/CD Workflows
│   └── security-audit.yml      # GitHub Actions automated test & audit pipeline
│
├── .gitignore                  # Excludes venv/, __pycache__/, .env*, and caches
├── requirements.txt            # Project dependencies (Streamlit, pytest)
└── README.md                   # Project documentation
```

---

## ⚙️ Installation & Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/SamThesiganM/ServerlessSecurityAgent.git
   cd ServerlessSecurityAgent
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🌐 Running the Streamlit Web Application

### Local Web App
Launch the interactive Streamlit dashboard locally:

```bash
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### Deploying to Streamlit Community Cloud
1. Fork or push this repository to your GitHub account.
2. Sign in to [Streamlit Community Cloud](https://share.streamlit.io/).
3. Click **New app**.
4. Select your repository: `SamThesiganM/ServerlessSecurityAgent`.
5. Set the branch to `main` and main file path to `app.py`.
6. Click **Deploy!**

---

## 🚀 Running the Command-Line Scanner

The original command-line interface remains fully functional:

```bash
# 1. Scan the built-in demo suite
python scanner.py demo

# 2. Scan a specific file
python scanner.py demo/safe_function.py

# 3. Scan an external serverless project folder
python scanner.py C:/path/to/your/serverless-project

# 4. Export findings as structured JSON
python scanner.py demo --format json

# 5. Strict mode (exit with code 1 if Critical/High findings are present)
python scanner.py demo --strict
```

---

## 🧪 Running Unit Tests

Run the complete automated test suite (26 passing tests) using Python's built-in `unittest` runner:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

Or using `pytest`:

```bash
pytest -v
```
