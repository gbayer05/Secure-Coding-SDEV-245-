#Gentry Bayer, Secure Coding Project   
# Secure Coding Project - Password Hasher Implementation
# September 27, 2026 


import ipaddress, socket
from urllib.parse import urlparse
import requests

ALLOWED_HOSTS = {"api.example.com", "docs.example.com"}   # allow-list is the primary control
MAX_BYTES = 1_000_000

def _is_public_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return not (addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_reserved or addr.is_multicast or addr.is_unspecified)

def validate_url(url: str) -> str:
    p = urlparse(url)
    if p.scheme != "https":
        raise ValueError("Only https:// URLs are allowed")
    if not p.hostname or p.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host is not on the allow-list")
    # Defense in depth: every resolved address must be public (blocks 127.0.0.1,
    # 10.x, 169.254.169.254 cloud metadata, etc.)
    for info in socket.getaddrinfo(p.hostname, p.port or 443, proto=socket.IPPROTO_TCP):
        if not _is_public_ip(info[4][0]):
            raise ValueError("Host resolves to a non-public address")
    return url

def safe_fetch(url: str) -> str:
    url = validate_url(url)
    r = requests.get(url, timeout=(3, 5), allow_redirects=False, stream=True)  # no redirects
    r.raise_for_status()
    body = r.raw.read(MAX_BYTES + 1, decode_content=True)     # cap response size
    if len(body) > MAX_BYTES:
        raise ValueError("Response too large")
    return body.decode(r.encoding or "utf-8", errors="replace")

if __name__ == "__main__":
    try:
        print(safe_fetch(input("Enter URL: ")))
    except (ValueError, requests.RequestException) as e:
        print(f"Request blocked or failed: {e}")
