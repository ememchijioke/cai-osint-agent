"""
tls_checker.py

Performs a basic TLS certificate check for HTTPS services.
"""

import socket
import ssl
from datetime import datetime


def run_tls_check(target: str, port: int = 443, timeout: int = 10) -> dict:
    """
    Retrieve basic TLS certificate information.

    Args:
        target: authorized target
        port: TLS port, default 443
        timeout: socket timeout

    Returns:
        dictionary containing TLS certificate data
    """
    result = {
        "target": target,
        "port": port,
        "success": False,
        "certificate": {},
        "error": None,
    }

    try:
        context = ssl.create_default_context()

        with socket.create_connection((target, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=target) as secure_sock:
                cert = secure_sock.getpeercert()

        result["success"] = True
        result["certificate"] = parse_certificate(cert)

    except socket.timeout:
        result["error"] = "TLS connection timed out."

    except ConnectionRefusedError:
        result["error"] = "TLS connection refused."

    except ssl.SSLError as error:
        result["error"] = f"TLS/SSL error: {error}"

    except Exception as error:
        result["error"] = str(error)

    return result


def parse_certificate(cert: dict) -> dict:
    """
    Extract readable information from certificate dictionary.
    """
    parsed = {
        "subject": cert.get("subject", []),
        "issuer": cert.get("issuer", []),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "serial_number": cert.get("serialNumber"),
        "subject_alt_names": cert.get("subjectAltName", []),
        "is_expired": None,
    }

    not_after = cert.get("notAfter")

    if not_after:
        try:
            expiry_date = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            parsed["is_expired"] = expiry_date < datetime.utcnow()
        except Exception:
            parsed["is_expired"] = None

    return parsed