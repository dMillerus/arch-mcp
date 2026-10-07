# SPDX-License-Identifier: GPL-3.0-only OR MIT
"""Tests for the read-only gate (safety.py + server.py wiring)."""

import json
from unittest.mock import AsyncMock, patch

import pytest

import importlib

server = importlib.import_module("arch_ops_server.server")
from arch_ops_server.safety import (
    MIXED_TOOLS, READ_TOOLS, WRITE_TOOLS, check_allowed, readonly_enabled,
)


async def _names():
    return {t.name for t in await server.list_tools()}


async def test_default_is_readonly(monkeypatch):
    monkeypatch.delenv("ARCH_OPS_READONLY", raising=False)
    assert readonly_enabled() is True
    assert check_allowed("remove_packages", {}) is not None


async def test_readonly_list_tools(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "1")
    tools = await server.list_tools()
    names = {t.name for t in tools}
    assert len(tools) == 20
    assert names.isdisjoint(WRITE_TOOLS)
    by_name = {t.name: t for t in tools}
    for tool, allowed in MIXED_TOOLS.items():
        assert set(by_name[tool].inputSchema["properties"]["action"]["enum"]) == set(allowed)


async def test_narrowing_does_not_mutate_shared_schema(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "1")
    await server.list_tools()
    monkeypatch.setenv("ARCH_OPS_READONLY", "0")
    by_name = {t.name: t for t in await server.list_tools()}
    assert "remove" in by_name["manage_orphans"].inputSchema["properties"]["action"]["enum"]


async def test_call_remove_packages_refused(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "1")
    with patch("arch_ops_server.server.remove_packages", new=AsyncMock()) as m:
        out = await server.call_tool("remove_packages", {"packages": "firefox"})
    m.assert_not_awaited()
    body = json.loads(out[0].text)
    assert body["readonly"] is True
    assert body["error"] is True and body["type"] == "ReadOnly"
    assert "ARCH_OPS_READONLY=0" in body["message"]


async def test_install_refused(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "1")
    with patch("arch_ops_server.server.install_package_secure", new=AsyncMock()) as m:
        out = await server.call_tool("install_package_secure", {"package_name": "yay"})
    m.assert_not_awaited()
    assert json.loads(out[0].text)["readonly"] is True


@pytest.mark.parametrize("tool,args", [
    ("manage_orphans", {"action": "remove"}),
    ("manage_orphans", {"action": "remove", "dry_run": True}),
    ("manage_orphans", {"action": "list", "dry_run": False}),
    ("manage_install_reason", {"action": "mark_explicit", "package_name": "x"}),
    ("manage_install_reason", {"action": "mark_dependency", "package_name": "x"}),
    ("manage_orphans", {}),
])
async def test_mixed_refused(monkeypatch, tool, args):
    monkeypatch.setenv("ARCH_OPS_READONLY", "1")
    out = await server.call_tool(tool, args)
    assert json.loads(out[0].text)["readonly"] is True


@pytest.mark.parametrize("tool,args", [
    ("manage_orphans", {"action": "list"}),
    ("manage_orphans", {"action": "list", "dry_run": True}),
    ("manage_install_reason", {"action": "list"}),
    ("search_archwiki", {"query": "x"}),
])
def test_allowed_in_readonly(monkeypatch, tool, args):
    monkeypatch.setenv("ARCH_OPS_READONLY", "1")
    assert check_allowed(tool, args) is None


@pytest.mark.parametrize("flag", ["1", "0"])
def test_unknown_tool_fails_closed(monkeypatch, flag):
    monkeypatch.setenv("ARCH_OPS_READONLY", flag)
    assert check_allowed("no_such_tool", None) is not None


async def test_unclassified_listed_tool_refused(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "0")
    monkeypatch.setattr("arch_ops_server.safety.READ_TOOLS", frozenset(READ_TOOLS - {"search_archwiki"}))
    assert "search_archwiki" in await _names()
    out = await server.call_tool("search_archwiki", {"query": "x"})
    body = json.loads(out[0].text)
    assert body["error"] is True and body["type"] == "ReadOnly"


async def test_writable_mode(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "0")
    names = await _names()
    assert len(names) == 22
    assert WRITE_TOOLS <= names
    assert check_allowed("remove_packages", {"packages": "x"}) is None
    assert check_allowed("manage_orphans", {"action": "remove", "dry_run": False}) is None


async def test_classification_complete(monkeypatch):
    monkeypatch.setenv("ARCH_OPS_READONLY", "0")
    names = await _names()
    groups = [set(WRITE_TOOLS), set(MIXED_TOOLS), set(READ_TOOLS)]
    for i, a in enumerate(groups):
        for b in groups[i + 1:]:
            assert a.isdisjoint(b)
    assert set().union(*groups) == names
