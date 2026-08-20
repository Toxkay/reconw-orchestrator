import pytest
from pathlib import Path

from reconw.tools.parser import (
    canonicalize_hostname,
    canonicalize_url,
    parse_dnsx_output,
    parse_httpx_output,
    parse_katana_output,
    parse_subfinder_output,
)


def test_canonicalize_hostname():
    host, root, key = canonicalize_hostname("  HTTPS://Sub.Example.COM:8080/path/test  ")
    assert host == "sub.example.com"
    assert root == "example.com"
    assert key == "sub.example.com"

    host2, root2, key2 = canonicalize_hostname("admin.staging.co.uk.")
    assert host2 == "admin.staging.co.uk"
    assert root2 == "staging.co.uk"
    assert key2 == "admin.staging.co.uk"


def test_canonicalize_url():
    norm1, key1 = canonicalize_url("HTTP://EXAMPLE.COM:80/api/v1/users/?id=2&action=view#section1")
    assert norm1 == "http://example.com/api/v1/users?action=view&id=2"
    assert len(key1) == 16

    norm2, key2 = canonicalize_url("http://example.com/api/v1/users?id=2&action=view")
    assert norm1 == norm2
    assert key1 == key2


def test_parse_subfinder_output_ndjson():
    raw_ndjson = (
        '{"host": "api.example.com", "input": "example.com", "sources": ["crtsh", "virustotal"]}\n'
        '{"host": "dev.example.com", "input": "example.com", "sources": ["alienvault"]}\n'
        '{"host": "api.example.com", "input": "example.com", "sources": ["shodan"]}\n'
    )
    assets = parse_subfinder_output(raw_ndjson)
    assert len(assets) == 2
    assert assets[0].hostname == "api.example.com"
    assert assets[0].root_domain == "example.com"
    assert "crtsh" in assets[0].sources
    assert assets[1].hostname == "dev.example.com"


def test_parse_subfinder_output_plaintext():
    raw_lines = "api.example.com\ndev.example.com\n"
    assets = parse_subfinder_output(raw_lines)
    assert len(assets) == 2
    assert assets[0].hostname == "api.example.com"
    assert assets[1].hostname == "dev.example.com"


def test_parse_dnsx_output():
    raw_dnsx = (
        '{"host": "api.example.com", "a": ["93.184.216.34"], "aaaa": ["2606:2800:220:1:248:1893:25c8:1946"], "status_code": "NOERROR"}\n'
        '{"host": "mail.example.com", "cname": ["cname.google.com"], "status_code": "NOERROR"}\n'
    )
    results = parse_dnsx_output(raw_dnsx)
    assert len(results) == 2
    assert results[0].hostname == "api.example.com"
    assert results[0].is_resolved is True
    assert len(results[0].records) == 2
    assert results[0].records[0].record_type == "A"
    assert results[0].records[0].value == "93.184.216.34"
    assert results[0].records[1].record_type == "AAAA"
    assert results[1].hostname == "mail.example.com"
    assert results[1].records[0].record_type == "CNAME"
    assert results[1].records[0].value == "cname.google.com"


def test_parse_httpx_output():
    raw_httpx = (
        '{"url": "https://api.example.com", "title": "API Gateway", "tech": ["Cloudflare", "Nginx"], "status_code": 200, "content_length": 1420, "screenshot_path": "./screenshots/api.png"}\n'
        '{"url": "http://dev.example.com:8080/login", "title": "Dev Login", "tech": "React,Express", "status_code": 401, "content_length": 350}\n'
    )
    endpoints = parse_httpx_output(raw_httpx)
    assert len(endpoints) == 2
    assert endpoints[0].url == "https://api.example.com"
    assert endpoints[0].hostname == "api.example.com"
    assert endpoints[0].status_code == 200
    assert endpoints[0].content_length == 1420
    assert endpoints[0].title == "API Gateway"
    assert "Cloudflare" in endpoints[0].tech_stack
    assert "Nginx" in endpoints[0].tech_stack
    assert endpoints[0].screenshot_path == "./screenshots/api.png"

    assert endpoints[1].url == "http://dev.example.com:8080/login"
    assert endpoints[1].status_code == 401
    assert "React" in endpoints[1].tech_stack
    assert "Express" in endpoints[1].tech_stack


def test_parse_katana_output():
    raw_katana = (
        '{"request": {"endpoint": "https://example.com/api/v1/users", "tag": "script", "source": "https://example.com/main.js"}}\n'
        '{"url": "https://example.com/dashboard"}\n'
    )
    urls = parse_katana_output(raw_katana)
    assert len(urls) == 2
    assert urls[0].url == "https://example.com/api/v1/users"
    assert urls[0].tag == "script"
    assert urls[0].source_endpoint == "https://example.com/main.js"
    assert urls[1].url == "https://example.com/dashboard"
