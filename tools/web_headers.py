"""
web_headers.py

Collects basic HTTP response headers from an authorized target.
"""

import requests


def run_web_headers(target: str, timeout: int = 10) -> dict:
    """
    Check HTTP and HTTPS headers.

    Args:
        target: authorized domain or host
        timeout: request timeout

    Returns:
        dictionary containing HTTP/HTTPS header results
    """
    result = {
        "target": target,
        "success": False,
        "http": None,
        "https": None,
        "error": None,
    }

    http_result = fetch_headers(f"http://{target}", timeout)
    https_result = fetch_headers(f"https://{target}", timeout)

    result["http"] = http_result
    result["https"] = https_result

    if http_result["success"] or https_result["success"]:
        result["success"] = True
    else:
        result["error"] = "Could not fetch HTTP or HTTPS headers."

    return result


def fetch_headers(url: str, timeout: int) -> dict:
    """
    Fetch headers for one URL.
    """
    response_data = {
        "url": url,
        "success": False,
        "status_code": None,
        "headers": {},
        "error": None,
    }

    try:
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            verify=True,
        )

        response_data["success"] = True
        response_data["status_code"] = response.status_code
        response_data["final_url"] = response.url
        response_data["headers"] = dict(response.headers)

    except requests.exceptions.SSLError:
        response_data["error"] = "SSL certificate verification failed."

    except requests.exceptions.ConnectionError:
        response_data["error"] = "Connection failed."

    except requests.exceptions.Timeout:
        response_data["error"] = "Request timed out."

    except Exception as error:
        response_data["error"] = str(error)

    return response_data