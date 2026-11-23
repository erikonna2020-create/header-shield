#!/usr/bin/env python3
"""CLI tool for auditing HTTP security headers and redirect chains."""

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from urllib.parse import urljoin


SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "weight": 25,
        "recommended": "max-age=31536000; includeSubDomains",
        "reason": "Enforces HTTPS and protects against protocol downgrade attacks.",
    },
    {
        "name": "Content-Security-Policy",
        "weight": 25,
        "recommended": "default-src 'self'",
        "reason": "Mitigates XSS and data injection risks by restricting resource origins.",
    },
    {
        "name": "X-Content-Type-Options",
        "weight": 15,
        "recommended": "nosniff",
        "reason": "Prevents browsers from MIME-sniffing responses away from declared types.",
    },
    {
        "name": "X-Frame-Options",
        "weight": 15,
        "recommended": "DENY or SAMEORIGIN",
        "reason": "Helps protect against clickjacking attacks.",
    },
    {
        "name": "Referrer-Policy",
        "weight": 10,
        "recommended": "strict-origin-when-cross-origin",
        "reason": "Controls how much referrer information is sent with requests.",
    },
    {
        "name": "Permissions-Policy",
        "weight": 10,
        "recommended": "geolocation=(), microphone=(), camera=()",
        "reason": "Restricts access to sensitive browser features and APIs.",
    },
]

DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "Via"]


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def normalize_url(target: str) -> str:
    target = target.strip()
    if not target.startswith(("http://", "https://")):
        return f"https://{target}"
    return target


def fetch_with_chain(start_url: str, timeout: float = 10.0, max_redirects: int = 8) -> dict:
    opener = urllib.request.build_opener(NoRedirectHandler())
    current_url = start_url
    redirects = []
    final_status = None
    final_headers = {}

    for _ in range(max_redirects + 1):
        req = urllib.request.Request(
            current_url,
            headers={
                "User-Agent": "header-shield/1.0 (+https://github.com/erikonna2020-create/header-shield)",
                "Accept": "*/*",
            },
            method="GET",
        )
        try:
            with opener.open(req, timeout=timeout) as resp:
                final_status = resp.status
                final_headers = {k: v for k, v in resp.headers.items()}
                break
        except urllib.error.HTTPError as err:
            hdrs = {k: v for k, v in err.headers.items()}
            location = err.headers.get("Location")
            if err.code in (301, 302, 303, 307, 308) and location:
                next_url = urljoin(current_url, location)
                redirects.append(
                    {
                        "from": current_url,
                        "status": err.code,
                        "to": next_url,
                    }
                )
                current_url = next_url
                continue
            final_status = err.code
            final_headers = hdrs
            break
        except urllib.error.URLError as err:
            raise RuntimeError(f"Network error for {current_url}: {err.reason}") from err
    else:
        raise RuntimeError(f"Exceeded maximum redirects ({max_redirects})")

    return {
        "initial_url": start_url,
        "final_url": current_url,
        "status_code": final_status,
        "redirects": redirects,
        "headers": final_headers,
    }


def evaluate_headers(headers: dict) -> dict:
    lower_map = {k.lower(): (k, v) for k, v in headers.items()}
    total_score = 0
    findings = []

    for item in SECURITY_HEADERS:
        key_lower = item["name"].lower()
        present = key_lower in lower_map
        value = lower_map[key_lower][1] if present else None
        earned = item["weight"] if present else 0
        total_score += earned
        findings.append(
            {
                "header": item["name"],
                "present": present,
                "value": value,
                "score": earned,
                "max_score": item["weight"],
                "recommended": item["recommended"],
                "reason": item["reason"],
            }
        )

    info_leaks = {}
    for dh in DISCLOSURE_HEADERS:
        low = dh.lower()
        if low in lower_map:
            info_leaks[lower_map[low][0]] = lower_map[low][1]

    if total_score >= 90:
        grade = "A"
    elif total_score >= 75:
        grade = "B"
    elif total_score >= 60:
        grade = "C"
    elif total_score >= 40:
        grade = "D"
    else:
        grade = "F"

    return {
        "score": total_score,
        "max_score": 100,
        "grade": grade,
        "findings": findings,
        "information_disclosure": info_leaks,
    }


def print_human_report(report: dict) -> None:
    audit = report["audit"]
    print(f"\nTarget:    {report['final_url']} (started: {report['initial_url']})")
    print(f"Status:    {report['status_code']}")
    print(f"Redirects: {len(report['redirects'])}")
    for hop in report["redirects"]:
        print(f"  -> [{hop['status']}] {hop['from']} => {hop['to']}")
    print(f"Score:     {audit['score']}/{audit['max_score']} (Grade {audit['grade']})\n")

    print("Security Headers:")
    for f in audit["findings"]:
        mark = "[OK]" if f["present"] else "[MISSING]"
        print(f"  {mark:9} {f['header']} ({f['score']}/{f['max_score']})")
        if f["present"]:
            print(f"            Value: {f['value']}")
        else:
            print(f"            Recommended: {f['recommended']}")

    if audit["information_disclosure"]:
        print("\nBanner / Disclosure Headers:")
        for k, v in audit["information_disclosure"].items():
            print(f"  [INFO] {k}: {v}")
    print()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Audit HTTP security headers and redirect chains of a URL."
    )
    parser.add_argument("target", help="Target domain or URL (e.g. example.com)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds")
    parser.add_argument("--output", "-o", help="Save full JSON report to file")
    parser.add_argument("--json", action="store_true", help="Print raw JSON to stdout")
    args = parser.parse_args()

    url = normalize_url(args.target)
    try:
        fetched = fetch_with_chain(url, timeout=args.timeout)
    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    evaluation = evaluate_headers(fetched["headers"])
    report = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        **fetched,
        "audit": evaluation,
    }

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False))
    else:
        print_human_report(report)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
