from dwcollector.discover import (
    normalize_url, onion_host, extract_onion_links, visible_text,
)

ONION = "http://abcdefghij234567.onion"

def test_onion_host():
    assert onion_host(f"{ONION}/path") == "abcdefghij234567.onion"
    assert onion_host("https://example.com/") is None

def test_normalize_url():
    assert normalize_url(f"{ONION}/A/../b#frag") == f"{ONION}/b"
    assert normalize_url(f"{ONION}") == f"{ONION}/"

def test_extract_onion_links_from_href_and_text():
    html = f'''
      <a href="/dir">rel</a>
      <a href="{ONION}/x">abs</a>
      <a href="https://clearnet.com">skip</a>
      raw mention: qwertyuiopasdfgh.onion/page
    '''
    links = extract_onion_links(html, ONION + "/")
    assert f"{ONION}/dir" in links
    assert f"{ONION}/x" in links
    assert any("qwertyuiopasdfgh.onion" in u for u in links)
    assert all(".onion" in u for u in links)

def test_visible_text_strips_tags():
    txt = visible_text("<html><body><h1>Bitcoin</h1><p>market</p></body></html>")
    assert "Bitcoin" in txt and "market" in txt
    assert "<" not in txt
