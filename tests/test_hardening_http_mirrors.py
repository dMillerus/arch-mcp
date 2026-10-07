# SPDX-License-Identifier: GPL-3.0-only OR MIT
"""Hardening tests: HTTP transport defaults and mirror-speed SSRF guard."""

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from arch_ops_server import mirrors
from arch_ops_server.mirrors import test_mirror_speed as mirror_speed


@pytest.fixture
def mirrorlist(tmp_path, monkeypatch):
    f = tmp_path / "mirrorlist"
    f.write_text("Server = https://mirror.good.example/archlinux/$repo/os/$arch\n")
    monkeypatch.setattr(mirrors, "MIRRORLIST_PATH", str(f))
    monkeypatch.setattr(mirrors, "IS_ARCH", True)
    return f


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:1/",
    "file:///etc/passwd",
    "ftp://mirror.good.example/x",
    "https://evil.example/",
])
async def test_rejected_urls_make_no_request(mirrorlist, url):
    with patch("httpx.AsyncClient") as client:
        result = await mirror_speed(url)
    assert "error" in result
    client.assert_not_called()


async def test_listed_host_accepted_and_no_redirects(mirrorlist):
    resp = MagicMock(status_code=200)
    with patch("httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.head = AsyncMock(return_value=resp)
        result = await mirror_speed("https://mirror.good.example/archlinux/$repo/os/$arch")
    assert "error" not in result
    assert result["tested_count"] == 1
    assert client.call_args.kwargs["follow_redirects"] is False


def test_http_defaults(monkeypatch):
    from arch_ops_server import http_server
    monkeypatch.delenv("ARCH_OPS_HOST", raising=False)
    monkeypatch.delenv("ARCH_OPS_PORT", raising=False)
    assert http_server.resolve_bind() == ("127.0.0.1", 8220)
    sig = inspect.signature(http_server.run_http_server)
    assert sig.parameters["host"].default is None
    assert sig.parameters["port"].default is None
    monkeypatch.setenv("ARCH_OPS_PORT", "9000")
    assert http_server.resolve_bind()[1] == 9000


def test_cors_no_credentials_no_wildcard(monkeypatch):
    from arch_ops_server import http_server
    if not http_server.STARLETTE_AVAILABLE:
        pytest.skip("starlette unavailable")
    monkeypatch.delenv("CORS_ORIGINS", raising=False)
    app = http_server.create_app()
    cors = [m for m in app.user_middleware if m.cls.__name__ == "CORSMiddleware"][0]
    assert not cors.kwargs.get("allow_credentials", False)
    assert cors.kwargs["allow_origins"] == []


async def test_default_path_follows_redirects(mirrorlist):
    resp = MagicMock(status_code=200)
    with patch("httpx.AsyncClient") as client:
        client.return_value.__aenter__.return_value.head = AsyncMock(return_value=resp)
        await mirror_speed()
    assert client.call_args.kwargs["follow_redirects"] is True


@pytest.fixture
def tc():
    from arch_ops_server import http_server
    if not http_server.STARLETTE_AVAILABLE:
        pytest.skip("starlette unavailable")
    from starlette.testclient import TestClient
    return TestClient(http_server.create_app(), raise_server_exceptions=False)


def test_bad_host_rejected(tc):
    r = tc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Host": "evil.example"})
    assert r.status_code == 403


def test_non_json_content_type_rejected(tc):
    r = tc.post("/mcp", content=b"{}", headers={"Content-Type": "text/plain",
                                                  "Host": "localhost"})
    assert r.status_code == 415


def test_no_wildcard_acao_on_mcp_post(tc):
    r = tc.post("/mcp", json={"jsonrpc": "2.0", "id": 1, "method": "ping"},
                headers={"Host": "127.0.0.1:8220"})
    assert r.status_code == 200
    assert r.headers.get("access-control-allow-origin") != "*"
