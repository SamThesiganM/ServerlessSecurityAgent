"""
demo/injection_function.py
Demonstrates vulnerable vs. safe serverless patterns for Phase 2 AST analysis.
NOTE: These code examples are static analysis targets using FAKE test data.
They are never executed by the scanner.
"""

import os
import subprocess


# ============================================================================
# VULNERABLE EXAMPLES
# ============================================================================

def vulnerable_sql_handler(event, context):
    """
    VULNERABLE: Direct string concatenation of untrusted event input into SQL query.
    Expected Detection: Potential SQL Injection (HIGH)
    """
    username = event["username"]
    # Unsafe dynamic SQL query construction
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)
    return {"status": "query executed"}


def vulnerable_command_handler(event, context):
    """
    VULNERABLE: Direct concatenation of untrusted event input into operating system command.
    Expected Detection: Potential Command Injection (CRITICAL)
    """
    host = event.get("host")
    # Unsafe command construction
    command = "ping " + host
    os.system(command)
    return {"status": "ping sent"}


def vulnerable_file_handler(event, context):
    """
    VULNERABLE: Untrusted event input used directly in file path without sanitization.
    Expected Detection: Potential Unsafe Input Handling (MEDIUM)
    """
    user_id = event["user_id"]
    with open("/tmp/" + user_id, "w") as f:
        f.write("user session data")
    return {"status": "file written"}


# ============================================================================
# SAFE EXAMPLES (BEST PRACTICES)
# ============================================================================

def safe_sql_handler(event, context):
    """
    SAFE: Uses parameterized queries (placeholders).
    Untrusted input is passed as a query parameter, not concatenated into SQL string.
    Expected: NO SQL injection finding.
    """
    user_id = event["user_id"]
    # The database driver safely escapes the parameter
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    return {"status": "safe query executed"}


def safe_command_handler(event, context):
    """
    SAFE: Uses safe APIs with hardcoded/validated arguments, avoiding shell execution.
    Expected: NO command injection finding.
    """
    # Safe API: arguments passed as a list, shell is disabled by default
    subprocess.run(["ping", "-c", "1", "127.0.0.1"])
    return {"status": "safe ping executed"}
