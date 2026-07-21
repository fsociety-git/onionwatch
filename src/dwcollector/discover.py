from __future__ import annotations
import re
from urllib.parse import urljoin, urlsplit, urlunsplit
from selectolax.parser import HTMLParser

_ONION_RE = re.compile(r"\b([a-z2-7]{16}|[a-z2-7]{56})\.onion\b", re.IGNORECASE)

def onion_host(url: str) -> str | None:
    host = urlsplit(url).netloc.lower() or url.lower()
    m = _ONION_RE.search(host)
    return m.group(0).lower() if m else None

def normalize_url(url: str) -> str:
    parts = urlsplit(url if "://" in url else "http://" + url)
    scheme = parts.scheme or "http"
    netloc = parts.netloc.lower()
    # collapse ../ and . segments
    segments: list[str] = []
    for seg in parts.path.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if segments:
                segments.pop()
        else:
            segments.append(seg)
    path = "/" + "/".join(segments)
    return urlunsplit((scheme, netloc, path, parts.query, ""))

def extract_onion_links(html: str, base_url: str) -> set[str]:
    found: set[str] = set()
    tree = HTMLParser(html)
    for node in tree.css("a[href]"):
        href = node.attributes.get("href") or ""
        absolute = urljoin(base_url, href)
        if onion_host(absolute):
            found.add(normalize_url(absolute))
    # raw-text mentions not inside hrefs
    for m in _ONION_RE.finditer(html):
        found.add(normalize_url("http://" + m.group(0).lower()))
    return found

def visible_text(html: str) -> str:
    tree = HTMLParser(html)
    for tag in tree.css("script, style"):
        tag.decompose()
    body = tree.body or tree.root
    return re.sub(r"\s+", " ", body.text(separator=" ")).strip() if body else ""
