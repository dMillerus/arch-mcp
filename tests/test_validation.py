# SPDX-License-Identifier: GPL-3.0-only OR MIT
"""Tests for package-name validation and hardened argv construction."""

import asyncio
import subprocess
from unittest.mock import AsyncMock, patch

import pytest

from arch_ops_server import aur, pacman
from arch_ops_server.utils import run_command
from arch_ops_server.validation import PKG_RE, validate_package_names

BAD = ["-Rdd", "--overwrite=*", ".x", "", "a b"]
GOOD = ["linux-zen", "lib32-gcc-libs", "zfs-linux", "python-pip", "gtk2+extra", "nvidia"]


@pytest.mark.parametrize("name", BAD)
def test_pkg_re_rejects(name):
    assert not PKG_RE.match(name)
    with pytest.raises(ValueError):
        validate_package_names(name)


@pytest.mark.parametrize("name", GOOD)
def test_pkg_re_accepts(name):
    assert PKG_RE.match(name)
    assert validate_package_names(name) == [name]


def test_validate_list_names_bad_entry():
    with pytest.raises(ValueError, match="--overwrite"):
        validate_package_names(["nvidia", "--overwrite=*"])
    with pytest.raises(ValueError):
        validate_package_names([])


def _patched():
    return (
        patch("arch_ops_server.pacman.IS_ARCH", True),
        patch("arch_ops_server.pacman.check_command_exists", return_value=True),
        patch("arch_ops_server.pacman.run_command", new_callable=AsyncMock),
    )


async def _call(fn, *args, **kw):
    a, b, c = _patched()
    with a, b, c as mock_run:
        mock_run.return_value = (0, "ok", "")
        result = await fn(*args, **kw)
        return result, mock_run


@pytest.mark.asyncio
@pytest.mark.parametrize("bad", ["-Rdd", "--overwrite=*"])
@pytest.mark.parametrize("fn,arg", [
    (pacman.remove_package, "x"),
    (pacman.remove_packages, "x"),
    (pacman.mark_as_explicit, "x"),
    (pacman.mark_as_dependency, "x"),
    (pacman.remove_packages_batch, ["x"]),
    (pacman.verify_package_integrity, "x"),
    (pacman.list_package_files, "x"),
])
async def test_bad_name_rejected_without_running(fn, arg, bad):
    arg = [bad] if isinstance(arg, list) else bad
    result, mock_run = await _call(fn, arg)
    assert result.get("error")
    mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_remove_packages_list_with_one_bad_name():
    result, mock_run = await _call(pacman.remove_packages, ["nvidia", "-Rdd"])
    assert result.get("error")
    mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_install_bad_name_rejected():
    with patch("arch_ops_server.aur.run_command", new_callable=AsyncMock) as m:
        result = await aur.install_package_secure("--overwrite=*")
    assert result.get("error")
    m.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("fn,args,prefix", [
    (pacman.remove_package, ("linux-zen",), ["sudo", "-n", "pacman", "-R", "--noconfirm", "--"]),
    (pacman.remove_packages_batch, (["linux-zen", "nvidia"],), ["sudo", "-n", "pacman", "-R", "--noconfirm", "--"]),
    (pacman.mark_as_explicit, ("nvidia",), ["sudo", "-n", "pacman", "-D", "--asexplicit", "--"]),
    (pacman.mark_as_dependency, ("nvidia",), ["sudo", "-n", "pacman", "-D", "--asdeps", "--"]),
])
async def test_good_names_argv_has_separator(fn, args, prefix):
    result, mock_run = await _call(fn, *args)
    argv = mock_run.call_args.args[0]
    assert argv[:len(prefix)] == prefix
    names = args[0] if isinstance(args[0], list) else [args[0]]
    assert argv[len(prefix):] == names


@pytest.mark.asyncio
async def test_remove_orphans_argv_and_validation():
    a, b, c = _patched()
    with a, b, c as mock_run, patch(
        "arch_ops_server.pacman.list_orphan_packages",
        new=AsyncMock(return_value={"orphans": ["orph-a", "orph-b"]}),
    ):
        mock_run.return_value = (0, "", "")
        await pacman.remove_orphans(dry_run=False)
        argv = mock_run.call_args.args[0]
        assert argv == ["sudo", "-n", "pacman", "-Rns", "--noconfirm", "--", "orph-a", "orph-b"]
    a, b, c = _patched()
    with a, b, c as mock_run, patch(
        "arch_ops_server.pacman.list_orphan_packages",
        new=AsyncMock(return_value={"orphans": ["ok", "-Rdd"]}),
    ):
        result = await pacman.remove_orphans(dry_run=False)
        assert result.get("error")
        mock_run.assert_not_called()


@pytest.mark.asyncio
async def test_run_command_timeout_kills_child():
    with pytest.raises(asyncio.TimeoutError):
        await run_command(["sleep", "5"], timeout=1)
    r = subprocess.run(["pgrep", "-f", "[s]leep 5"], capture_output=True)
    assert r.returncode != 0


@pytest.mark.asyncio
async def test_groups_rejects_flag_and_uses_separator():
    from arch_ops_server import groups
    with patch("arch_ops_server.groups.IS_ARCH", True), \
         patch("arch_ops_server.groups.run_command", new_callable=AsyncMock) as m:
        res = await groups.manage_groups("list_packages_in_group", "--config=/x")
        assert res.get("error")
        m.assert_not_called()
        m.return_value = (0, "gnome gedit\n", "")
        await groups.manage_groups("list_packages_in_group", "gnome")
        assert m.call_args.args[0] == ["pacman", "-Sg", "--", "gnome"]


@pytest.mark.asyncio
async def test_list_package_files_bad_filter_pattern():
    for pat in ["(", "a" * 201]:
        result, mock_run = await _call(pacman.list_package_files, "nvidia", pat)
        assert result.get("error")
        mock_run.assert_not_called()
