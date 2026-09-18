"""
feature_extractor.py

Extracts a small set of phishing-related features directly from a URL
STRING ONLY — no network calls, no page fetch, no WHOIS lookups.

Why URL-only? A browser extension needs an answer in milliseconds, and must
work even if the page is slow, broken, or blocking automated requests.
Trading a bit of accuracy for speed and reliability is a deliberate,
documented design choice — not an oversight.

Each function below returns a value in {-1, 0, 1}, matching the encoding
used in the original UCI "Phishing Websites" dataset:
    -1 -> looks like a phishing signal
     1 -> looks like a legitimate signal
     0 -> ambiguous / in-between (only some features use this)
"""

import re
from urllib.parse import urlparse

# A short, non-exhaustive list of known URL-shortening services.
# In a real product you'd want a longer, maintained list.
KNOWN_SHORTENERS = {
    "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd",
    "buff.ly", "adf.ly", "bit.do", "cutt.ly", "rb.gy",
}


def having_ip_address(url: str) -> int:
    """-1 if the URL's host is a raw IP address (e.g. http://192.168.0.1/login).
    Legitimate sites almost always use a domain name, not a bare IP."""
    host = urlparse(url).hostname or ""
    ipv4_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    if re.match(ipv4_pattern, host):
        return -1
    return 1


def url_length(url: str) -> int:
    """Thresholds commonly cited in the original phishing-features literature
    (Mohammad et al.): short URLs tend to be legitimate, very long ones
    tend to be phishing (often used to hide the real destination)."""
    length = len(url)
    if length < 54:
        return 1
    elif length <= 75:
        return 0
    else:
        return -1


def shortening_service(url: str) -> int:
    """-1 if the domain is a known URL shortener. Shorteners hide the real
    destination, which is a common phishing tactic."""
    host = (urlparse(url).hostname or "").lower()
    return -1 if host in KNOWN_SHORTENERS else 1


def having_at_symbol(url: str) -> int:
    """-1 if '@' appears in the URL. Browsers ignore everything before an
    '@' when resolving the host, so 'trusted.com@evil.com' actually goes
    to evil.com — a classic trick."""
    return -1 if "@" in url else 1


def double_slash_redirecting(url: str) -> int:
    """-1 if '//' appears anywhere after the protocol, which can indicate
    a redirect trick embedded in the path."""
    protocol_end = url.find("://")
    rest = url[protocol_end + 3:] if protocol_end != -1 else url
    return -1 if "//" in rest else 1


def prefix_suffix(url: str) -> int:
    """-1 if the domain contains a hyphen (e.g. paypal-secure-login.com).
    Legitimate brand domains rarely use hyphens; phishing domains often
    add them to impersonate a brand while using a different actual domain."""
    host = urlparse(url).hostname or ""
    return -1 if "-" in host else 1


def having_sub_domain(url: str) -> int:
    """Counts dots in the hostname (excluding a leading 'www') as a rough
    proxy for number of subdomains. More subdomains = more suspicious,
    since phishing sites often chain subdomains to imitate a brand
    (e.g. paypal.com.verify-account.example.net)."""
    host = urlparse(url).hostname or ""
    if host.startswith("www."):
        host = host[4:]
    dot_count = host.count(".")
    if dot_count <= 1:
        return 1
    elif dot_count == 2:
        return 0
    else:
        return -1


def having_port(url: str) -> int:
    """-1 if the URL explicitly specifies a non-standard port. Legitimate
    sites almost always run on the default port for their protocol."""
    parsed = urlparse(url)
    port = parsed.port
    if port is not None and port not in (80, 443):
        return -1
    return 1


def https_token(url: str) -> int:
    """-1 if the literal word 'https' appears in the DOMAIN part of the
    URL (not the protocol) — e.g. https-paypal-login.com. This is a trick
    to make a URL *look* secure at a glance."""
    host = urlparse(url).hostname or ""
    return -1 if "https" in host else 1


def uses_https(url: str) -> int:
    """Approximates the original dataset's 'SSLfinal_State' feature, which
    actually validated the SSL certificate over the network. Here we only
    check the URL scheme — a much weaker signal, since a phishing site can
    easily also use HTTPS. This is a known, documented simplification."""
    return 1 if url.lower().startswith("https://") else -1


# The exact order matters — it MUST match the column order the model was
# trained on. FEATURE_NAMES here is the single source of truth for that order.
FEATURE_NAMES = [
    "having_ip_address",
    "url_length",
    "shortining_service",
    "having_at_symbol",
    "double_slash_redirecting",
    "prefix_suffix",
    "having_sub_domain",
    "port",
    "https_token",
    "uses_https",
]

FEATURE_FUNCTIONS = [
    having_ip_address,
    url_length,
    shortening_service,
    having_at_symbol,
    double_slash_redirecting,
    prefix_suffix,
    having_sub_domain,
    having_port,
    https_token,
    uses_https,
]


def extract_features(url: str) -> list:
    """Runs every feature function on the given URL and returns the
    resulting values as a list, in FEATURE_NAMES order — ready to hand
    straight to the trained model."""
    return [func(url) for func in FEATURE_FUNCTIONS]


def extract_features_dict(url: str) -> dict:
    """Same as extract_features, but as a dict — handy for debugging/printing."""
    return dict(zip(FEATURE_NAMES, extract_features(url)))


if __name__ == "__main__":
    # Quick manual sanity check when running this file directly:
    # python feature_extractor.py
    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login/verify",
        "http://paypal-secure-login.tk/account@confirm",
    ]
    for u in test_urls:
        print(u)
        print(extract_features_dict(u))
        print()
