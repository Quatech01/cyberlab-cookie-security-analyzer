import argparse
import json
import sys
import httpx


def parse_cookie_flags(header_value: str) -> dict:
    """Parse a Set-Cookie header value and return a dict of security-relevant flags."""
    parts = [p.strip() for p in header_value.split(";")]
    # The first part is always name=value
    name = parts[0].split("=", 1)[0].strip() if parts else "unknown"

    flags = {
        "name": name,
        "httponly": False,
        "secure": False,
        "samesite": None,
    }

    for part in parts[1:]:
        lower = part.lower().strip()
        if lower == "httponly":
            flags["httponly"] = True
        elif lower == "secure":
            flags["secure"] = True
        elif lower.startswith("samesite="):
            flags["samesite"] = lower.split("=", 1)[1].strip()

    return flags


def analyze_cookie(flags: dict, endpoint: str) -> list:
    """Return a list of security findings for a single parsed cookie."""
    findings = []
    name = flags["name"]

    if not flags["httponly"]:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "MISSING_HTTPONLY",
            "evidence": (
                f"Cookie '{name}' does not have the HttpOnly flag. "
                "JavaScript executing on the page — including injected scripts from XSS — "
                "can read this cookie via document.cookie and exfiltrate the session token."
            ),
            "severity": "HIGH",
        })

    if not flags["secure"]:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "MISSING_SECURE",
            "evidence": (
                f"Cookie '{name}' does not have the Secure flag. "
                "The cookie will be sent over plain HTTP connections as well as HTTPS, "
                "making it readable to any network observer on the same path."
            ),
            "severity": "HIGH",
        })

    if flags["samesite"] is None:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "MISSING_SAMESITE",
            "evidence": (
                f"Cookie '{name}' has no SameSite attribute. "
                "Without SameSite, the browser includes this cookie in all cross-site requests, "
                "leaving the session exposed to cross-site request forgery (CSRF) attacks."
            ),
            "severity": "MEDIUM",
        })
    elif flags["samesite"] == "none" and not flags["secure"]:
        findings.append({
            "endpoint": endpoint,
            "vulnerability_type": "INSECURE_SAMESITE_NONE",
            "evidence": (
                f"Cookie '{name}' sets SameSite=None without the Secure flag. "
                "RFC 6265bis §8.8 requires that SameSite=None cookies always carry the Secure attribute. "
                "Modern browsers (Chrome 80+, Firefox, Safari) silently reject this cookie, "
                "meaning it will never be stored — a misconfiguration that breaks authentication."
            ),
            "severity": "HIGH",
        })

    return findings


def scan(target: str) -> dict:
    """Probe the target's cookie endpoints and return structured findings."""
    all_findings = []
    endpoints_scanned = 0

    try:
        with httpx.Client(follow_redirects=False) as client:
            try:
                targets_resp = client.get(f"{target}/targets", timeout=5.0)
                targets_resp.raise_for_status()
                endpoint_list = targets_resp.json().get("endpoints", [])
            except httpx.ConnectError:
                return {
                    "target": target,
                    "findings": [],
                    "summary": (
                        f"Unable to connect to {target}. "
                        "Ensure the demo server is running before scanning."
                    ),
                }

            for ep in endpoint_list:
                path = ep.get("path", "")
                if not path:
                    continue
                endpoints_scanned += 1
                try:
                    resp = client.get(f"{target}{path}", timeout=5.0)
                    # Collect all Set-Cookie headers (httpx preserves duplicates via multi_items)
                    cookie_headers = [
                        v for k, v in resp.headers.multi_items()
                        if k.lower() == "set-cookie"
                    ]
                    for cookie_header in cookie_headers:
                        flags = parse_cookie_flags(cookie_header)
                        findings = analyze_cookie(flags, path)
                        all_findings.extend(findings)
                except httpx.ConnectError:
                    pass
                except Exception:
                    pass

    except Exception as exc:
        return {
            "target": target,
            "findings": [],
            "summary": f"Scan error: {exc}",
        }

    high_count = sum(1 for f in all_findings if f["severity"] == "HIGH")
    medium_count = sum(1 for f in all_findings if f["severity"] == "MEDIUM")

    by_type: dict = {}
    for f in all_findings:
        by_type[f["vulnerability_type"]] = by_type.get(f["vulnerability_type"], 0) + 1

    if all_findings:
        type_parts = ", ".join(f"{c}× {t}" for t, c in by_type.items())
        summary = (
            f"Found {len(all_findings)} cookie security issue(s) across "
            f"{endpoints_scanned} endpoint(s): "
            f"{high_count} HIGH, {medium_count} MEDIUM. "
            f"Issues: {type_parts}."
        )
    else:
        summary = (
            f"No cookie security issues found across {endpoints_scanned} endpoint(s). "
            "All cookies use HttpOnly, Secure, and a SameSite policy."
        )

    print(
        f"Cookie Security Analyzer | target={target} | "
        f"endpoints={endpoints_scanned} | findings={len(all_findings)}",
        file=sys.stderr,
    )
    for f in all_findings:
        print(f"  [{f['severity']}] {f['endpoint']}: {f['vulnerability_type']}", file=sys.stderr)

    return {"target": target, "findings": all_findings, "summary": summary}


def main():
    parser = argparse.ArgumentParser(description="Cookie Security Analyzer — flags insecure Set-Cookie headers")
    parser.add_argument(
        "--target",
        default="http://localhost:3000",
        help="Base URL of the target server (default: http://localhost:3000)",
    )
    args = parser.parse_args()
    result = scan(args.target)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
