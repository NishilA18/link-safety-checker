import pytest
import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from checker import (
    normalize_url,
    extract_domain,
    check_ip_url,
    check_patterns,
    calculate_trust_score,
)


# ── normalize_url ──────────────────────────────────────────────────────────────

def test_normalize_adds_https():
    assert normalize_url("example.com") == "https://example.com"

def test_normalize_keeps_http():
    assert normalize_url("http://example.com") == "http://example.com"

def test_normalize_strips_whitespace():
    assert normalize_url("  https://example.com  ") == "https://example.com"


# ── extract_domain ─────────────────────────────────────────────────────────────

def test_extract_domain_basic():
    assert extract_domain("https://www.example.com/path") == "example.com"

def test_extract_domain_no_www():
    assert extract_domain("https://example.com") == "example.com"

def test_extract_domain_subdomain():
    result = extract_domain("https://mail.google.com")
    assert "google.com" in result


# ── check_ip_url ───────────────────────────────────────────────────────────────

def test_ip_url_detected():
    assert check_ip_url("http://192.168.1.1/login") is True

def test_domain_url_not_ip():
    assert check_ip_url("https://example.com") is False


# ── check_patterns ─────────────────────────────────────────────────────────────

def test_suspicious_keyword_flagged():
    warnings = check_patterns("http://totally-legit-login.xyz/secure")
    assert any("keyword" in w.lower() or "tld" in w.lower() for w in warnings)

def test_ip_in_url_flagged():
    warnings = check_patterns("http://123.45.67.89/account/verify")
    assert any("ip" in w.lower() for w in warnings)

def test_clean_url_no_pattern_warnings():
    warnings = check_patterns("https://github.com")
    assert len(warnings) == 0


# ── calculate_trust_score ──────────────────────────────────────────────────────

def make_ssl(valid=True, days=365):
    return {"valid": valid, "days_left": days}

def make_whois(found=True, age_days=500):
    return {"found": found, "age_days": age_days}

def make_redirect(count=0, suspicious=False):
    return {"redirect_count": count, "suspicious": suspicious, "chain": [], "final_url": ""}


def test_perfect_score():
    result = calculate_trust_score(make_ssl(), make_whois(), make_redirect(), [])
    assert result["score"] == 100
    assert result["level"] == "SAFE"

def test_invalid_ssl_lowers_score():
    result = calculate_trust_score(make_ssl(valid=False), make_whois(), make_redirect(), [])
    assert result["score"] <= 65

def test_new_domain_lowers_score():
    result = calculate_trust_score(make_ssl(), make_whois(age_days=10), make_redirect(), [])
    assert result["score"] <= 70

def test_many_flags_dangerous():
    result = calculate_trust_score(
        make_ssl(valid=False),
        make_whois(found=False),
        make_redirect(count=6, suspicious=True),
        ["flag1", "flag2", "flag3"],
    )
    assert result["level"] == "DANGEROUS"
    assert result["score"] < 45

def test_score_never_negative():
    result = calculate_trust_score(
        make_ssl(valid=False),
        make_whois(found=False),
        make_redirect(suspicious=True),
        ["f1", "f2", "f3", "f4", "f5", "f6"],
    )
    assert result["score"] >= 0
