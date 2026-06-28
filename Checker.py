import asyncio
import socket
import ssl
import re
import time
import urllib.parse
from datetime import datetime, timezone
from typing import Optional
import httpx
import whois


# ── Suspicious patterns ────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "secure", "update", "confirm",
    "banking", "paypal", "amazon", "apple", "microsoft", "google", "netflix",
    "password", "credential", "wallet", "crypto", "free", "winner", "prize",
    "urgent", "suspended", "unusual", "limited", "offer",
]

SUSPICIOUS_TLDS = [
    ".xyz", ".top", ".club", ".online", ".site", ".icu", ".gq", ".ml",
    ".cf", ".tk", ".pw", ".cc", ".su", ".ws",
]

URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
    "short.link", "rb.gy", "cutt.ly", "is.gd", "v.gd", "shorte.st",
]

PHISHING_PATTERNS = [
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",          # raw IP address
    r"[a-zA-Z0-9\-]+\.[a-zA-Z]{2,}\.[a-zA-Z]{2,}",   # double extension
    r"@",                                               # @ in URL path
    r"https?://[^/]*//",                               # double slash after host
    r"[a-z0-9\-]{30,}",                               # very long subdomain/domain
]


# ── Helpers ────────────────────────────────────────────────────────────────────

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def extract_domain(url: str) -> str:
    try:
        parsed = urllib.parse.urlparse(url)
        return parsed.netloc.lower().lstrip("www.")
    except Exception:
        return url


def check_ip_url(url: str) -> bool:
    host = urllib.parse.urlparse(url).netloc.split(":")[0]
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return bool(re.match(pattern, host))


# ── Individual checks ──────────────────────────────────────────────────────────

def check_ssl(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url)
        host = parsed.netloc.split(":")[0]
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        if parsed.scheme != "https":
            return {"valid": False, "reason": "No HTTPS — connection is unencrypted", "expiry": None}

        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((host, port), timeout=5), server_hostname=host) as s:
            cert = s.getpeercert()
            expiry_str = cert.get("notAfter", "")
            expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < 0:
                return {"valid": False, "reason": "SSL certificate has expired", "expiry": expiry_str, "days_left": days_left}
            if days_left < 14:
                return {"valid": True, "warning": f"SSL cert expires in {days_left} days", "expiry": expiry_str, "days_left": days_left}
            return {"valid": True, "expiry": expiry_str, "days_left": days_left}
    except ssl.SSLCertVerificationError:
        return {"valid": False, "reason": "SSL certificate is invalid or self-signed", "expiry": None}
    except Exception as e:
        return {"valid": False, "reason": f"SSL check failed: {str(e)}", "expiry": None}


def check_whois(domain: str) -> dict:
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return {"found": False, "reason": "No WHOIS registration found"}

        if creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days
        registrar = w.registrar or "Unknown"
        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]

        return {
            "found": True,
            "age_days": age_days,
            "creation_date": str(creation.date()),
            "expiry_date": str(expiry.date()) if expiry else "Unknown",
            "registrar": registrar,
        }
    except Exception as e:
        return {"found": False, "reason": str(e)}


async def check_redirects(url: str) -> dict:
    try:
        redirect_chain = []
        async with httpx.AsyncClient(follow_redirects=True, timeout=8) as client:
            resp = await client.get(url, headers={"User-Agent": "Mozilla/5.0"})
            history = resp.history
            for r in history:
                redirect_chain.append(str(r.url))
            final = str(resp.url)
            redirect_chain.append(final)

        return {
            "redirect_count": len(redirect_chain) - 1,
            "final_url": final,
            "chain": redirect_chain,
            "suspicious": len(redirect_chain) > 4,
        }
    except Exception as e:
        return {"redirect_count": 0, "final_url": url, "chain": [url], "suspicious": False, "error": str(e)}


def check_patterns(url: str) -> list[str]:
    warnings = []
    domain = extract_domain(url)
    full = url.lower()

    if check_ip_url(url):
        warnings.append("URL uses a raw IP address instead of a domain name")

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in full:
            warnings.append(f'Contains suspicious keyword: "{kw}"')
            break

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            warnings.append(f'Uses a high-risk TLD: "{tld}"')
            break

    for shortener in URL_SHORTENERS:
        if shortener in domain:
            warnings.append(f"URL is a shortened link via {shortener} — destination is hidden")
            break

    for pat in PHISHING_PATTERNS:
        if re.search(pat, url):
            if pat == r"@":
                warnings.append("URL contains '@' — this can be used to disguise the real destination")
            elif pat == r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}":
                pass  # already handled above
            elif "30," in pat:
                warnings.append("Unusually long domain name — common in phishing URLs")

    subdomains = domain.split(".")
    if len(subdomains) > 4:
        warnings.append(f"Many subdomain levels ({len(subdomains) - 2}) — could be masking the real domain")

    return warnings


def calculate_trust_score(ssl_result, whois_result, redirect_result, pattern_warnings) -> dict:
    score = 100
    flags = []

    # SSL
    if not ssl_result.get("valid"):
        score -= 35
        flags.append(ssl_result.get("reason", "SSL issue"))
    elif ssl_result.get("warning"):
        score -= 10
        flags.append(ssl_result["warning"])

    # WHOIS / domain age
    if not whois_result.get("found"):
        score -= 20
        flags.append("Domain registration info unavailable")
    else:
        age = whois_result.get("age_days", 9999)
        if age < 30:
            score -= 30
            flags.append(f"Domain is only {age} days old — very new")
        elif age < 180:
            score -= 15
            flags.append(f"Domain is relatively new ({age} days old)")

    # Redirects
    if redirect_result.get("suspicious"):
        score -= 20
        flags.append(f"Excessive redirects ({redirect_result['redirect_count']}) before reaching final destination")

    # Pattern warnings
    for w in pattern_warnings:
        score -= 10
        flags.append(w)

    score = max(0, score)

    if score >= 75:
        level = "SAFE"
        color = "green"
    elif score >= 45:
        level = "SUSPICIOUS"
        color = "orange"
    else:
        level = "DANGEROUS"
        color = "red"

    return {"score": score, "level": level, "color": color, "flags": flags}


# ── Main entry point ───────────────────────────────────────────────────────────

async def analyze_url(raw_url: str) -> dict:
    url = normalize_url(raw_url)
    domain = extract_domain(url)

    ssl_result, redirect_result, whois_result = await asyncio.gather(
        asyncio.to_thread(check_ssl, url),
        check_redirects(url),
        asyncio.to_thread(check_whois, domain),
    )

    pattern_warnings = check_patterns(url)
    trust = calculate_trust_score(ssl_result, whois_result, redirect_result, pattern_warnings)

    return {
        "url": url,
        "domain": domain,
        "trust": trust,
        "ssl": ssl_result,
        "whois": whois_result,
        "redirects": redirect_result,
        "pattern_warnings": pattern_warnings,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }
