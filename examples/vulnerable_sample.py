"""A deliberately insecure Python file used to demonstrate Python security_scan.

It contains NO real secrets — only code patterns Bandit flags. Scan it directly:
no build step is needed for Python.
"""

import hashlib
import subprocess


def weak_hash(data: bytes) -> str:
    # MD5 is broken for security use. (Bandit B303)
    return hashlib.md5(data).hexdigest()


def run(user_input: str) -> None:
    # Passing user input to a shell invites command injection. (Bandit B602)
    subprocess.call(user_input, shell=True)
