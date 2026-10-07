# ws0 fork of arch-mcp — implementation plan

Run `dMillerus/arch-mcp` from source on ws0 as the single server both Zed and
Claude Code use, make it **read-only by default** before any agent touches it,
then grow ws0-specific read-only tools on top.

Written 2026-10-06 from three read-only scouts (architecture, live run, ~/Admin
overlap) plus a planning pass. Line refs are against `d637138`.

**Status (2026-10-06):** Phase 1.1 (editable `uv tool` install) done. Phases 0
and 2 done on `ws0`, reviewed (code + adversarial security), review fixes
applied. Beyond the plan, review added: fail-closed gate (unclassified tools
refused), no kill of a timed-out `sudo` child (it cannot reach pacman and
leaves `db.lck`), `--` + validation in `groups.py` (the live `manage_groups`
path), a 200-char cap on `filter_pattern`, and the HTTP Host/Content-Type
checks. `tests/test_mirrors.py` no longer collects the production
`test_mirror_speed` — that was 477 of the suite's 481 seconds; the fast suite
is now ~3 s. Phase 1.3 (Claude Code registration) not done.

## Starting state (verified)

| Fact | Evidence |
|---|---|
| Clone at `~/Repos/arch-mcp`, clean, `main` = `origin/main` = `upstream/main` = `d637138` | `git rev-list --left-right --count` 0/0 both |
| `.venv` synced incl. dev extra; Python 3.13 (`.python-version`); build backend `uv_build` | `uv sync --extra dev` no-op |
| Runs from source over stdio: 22 tools, 24 resources, 8 prompts; init 0.25 s | scratch smoke test |
| Tests: **165 pass / 11 fail**, 9.5 min (network-bound) | `uv run pytest -q` |
| PyPI 3.4.0 installed via `uv tool`, pinned `--with 'mcp<1.20'`; `~/.local/bin/arch-ops-server` → that tool env | `uv-receipt.toml` |
| Zed launches `~/.local/bin/arch-ops-server` | `~/.config/zed/settings.json` (mirrored in `~/Admin/dotfiles/zed_settings.json`) |
| Claude Code: **not registered**; `~/Admin/.claude/settings.local.json:97` already allows `mcp__arch-ops-server__fetch_news` | `claude mcp list` |
| CI: only `publish-pypi.yml` + `publish-ghcr.yml`, both fire on **tag push**; no test/lint CI | `.github/workflows/` |

## Why hardening is not optional on ws0

`utils.run_command` (utils.py:58-150) guards sudo with a `sudo -n true`
pre-check — designed to fail fast on a password-prompting host. ws0 has
**NOPASSWD sudo**, so the check passes and every write tool runs unattended with
`--noconfirm`. Claude Code's `Bash(sudo *)` ask rule does **not** apply: the
sudo runs inside the MCP server process, not through the Bash tool.

| Tool | Command | Guard today |
|---|---|---|
| `install_package_secure` | `sudo pacman -S --noconfirm` (aur.py:740); AUR via `paru/yay -S --noconfirm` (aur.py:880, stdin inherits the MCP pipe) | PKGBUILD regex scan only |
| `remove_packages` | `sudo pacman -Rs` / `-Rdd` when `force` (pacman.py:354, 433, 534) | **none** — no dry run, `skip_sudo_check=True` |
| `manage_orphans action=remove` | `sudo pacman -Rns --noconfirm` (pacman.py:662) | `dry_run` defaults True (server.py:1160) |
| `manage_install_reason mark_*` | `sudo pacman -D --asexplicit/--asdeps` (pacman.py:1320, 1374) | none |

Other defects: no `--` before package names (a name like `-Rdd` injects flags);
`test_mirror_speed` GETs any caller URL with redirects (mirrors.py:121-139,
SSRF); HTTP mode binds `0.0.0.0:8080` with no auth and `CORS *` +
credentials (http_server.py:771-786) — and `:8080` is already nws-poller's web
port; timeout doesn't kill the child (utils.py:145); tool args logged at INFO
(server.py:1100); `check_updates_dry_run` fails open — empty stdout on error is
reported as "no updates" (pacman.py:258).

---

## Phase 0 — Branch, guardrails, baseline

**0.1 Branch model.** `main` mirrors upstream, fast-forward only. Your work
lives on `ws0`, and the checkout **stays on `ws0`** — the editable install runs
whatever is checked out.

```bash
cd ~/Repos/arch-mcp
git switch -c ws0
git config remote.upstream.tagOpt --no-tags     # upstream tags never land locally
mkdir -p docs && git add docs/ws0-fork.plan.md
```

Later upstream sync, without leaving `ws0`:

```bash
git fetch upstream && git fetch . upstream/main:main && git rebase main
uv run pytest -o addopts="" -q -m "not network"   # no CI exists — this is the gate
```

Done: `git branch -vv` shows `* ws0` and `main` at `d637138`.

**0.2 Neutralize the publish workflows.** Add to each job in
`.github/workflows/publish-pypi.yml` and `publish-ghcr.yml`:

```yaml
    if: github.repository == 'nihalxkumar/arch-mcp'
```

That only protects `ws0` commits — a tag on an upstream commit runs upstream's
file. So also **disable Actions in the fork's GitHub settings** (UI, yours to
do) and never `git push --tags`.
Done: `grep -c "github.repository" .github/workflows/*.yml` → 1 each.

**0.3 Version marker.** pyproject.toml:3 → `version = "3.4.0+ws0.1"` (PEP 440
local version), so `uv tool list` distinguishes fork from PyPI.

**0.4 Fast test loop.** pyproject.toml:62 uses `--strict-markers`, so register
the marker under `[tool.pytest.ini_options]`:

```toml
markers = ["network: hits the internet"]
```

Find the slow ones once — `uv run pytest -o addopts="" -q --durations=30` — and
tag them `@pytest.mark.network` (whole modules via `pytestmark = pytest.mark.network`
where every test is live). Dev loop from then on:

```bash
uv run pytest -o addopts="" -q -m "not network"   # -o addopts="" also skips coverage HTML
```

**0.5 Record the baseline.**

```bash
uv run pytest -o addopts="" -q -rf 2>&1 | tail -20 > docs/test-baseline.txt
git add -A && git commit -m "chore(ws0): branch guardrails, version marker, network marker, test baseline"
```

Done: baseline lists exactly 11 failures (4 `test_groups`, 6 `test_security`,
1 `test_storage`).
Rollback: `git switch main && git branch -D ws0`.

---

## Phase 1 — Run from source (smoke only until Phase 2 lands)

**1.1 Switch the uv tool to an editable install of the fork.** Verified flags
for uv 0.11.6: `-e/--editable` ("changes in the package's source directory are
reflected without reinstallation"), `--force`, `--with`. Keep the existing
`mcp<1.20` pin or it is silently dropped:

```bash
uv tool install --editable /home/dave/Repos/arch-mcp --with 'mcp<1.20' --python 3.13 --force
```

Python edits are live on next server start. Changes to `pyproject.toml`
(deps, entry points, version) need the command re-run.
Done:

```bash
uv tool list | grep arch-ops                       # → arch-ops-server v3.4.0+ws0.1
~/.local/share/uv/tools/arch-ops-server/bin/python -c \
  "import arch_ops_server; print(arch_ops_server.__file__)"   # → .../Repos/arch-mcp/src/...
```

**1.2 Zed: no change.** It already points at `~/.local/bin/arch-ops-server`.
Read-only will be the *code* default (Phase 2), so no env var is needed in
Zed's config and `dotfiles/zed_settings.json` doesn't drift. Done: restart Zed;
the agent panel lists the tools.

**1.3 Claude Code: project scope in `~/Admin` (recommended).** The operate
domain is where these tools belong; it keeps them away from every other repo's
agents; `.mcp.json` is tracked, so the change is recorded; and the existing
allow rule already uses the `arch-ops-server` name.

```bash
cd /home/dave/Admin && claude mcp add --scope project arch-ops-server -- /home/dave/.local/bin/arch-ops-server
```

Done: `claude mcp list` shows it ✔ connected; in a session, `/mcp` lists the
tools and `get_system_info` returns `hostname: ws0`. Approve the project server
when Claude Code prompts on next start.

> Until Phase 2 is merged, only do 1.3 for a smoke test, then
> `claude mcp remove --scope project arch-ops-server` — or apply the 2.7 deny
> rules first.

**1.4 Reload after edits.** Claude Code: `/mcp` → arch-ops-server → reconnect
(or restart the session). Zed: restart, or toggle the context server off/on.

**1.5 Rollback to PyPI:**

```bash
uv tool install arch-ops-server==3.4.0 --with 'mcp<1.20' --force
claude mcp remove --scope project arch-ops-server     # run in ~/Admin
```

---

## Phase 2 — Safety hardening (one commit per step; tests in `tests/test_safety.py`)

**2.1 `src/arch_ops_server/safety.py` (new).**

```python
READONLY = os.getenv("ARCH_OPS_READONLY", "1") != "0"   # on unless explicitly "0"

WRITE_TOOLS = {"install_package_secure", "remove_packages"}
MIXED_TOOLS = {                       # tool -> actions allowed in read-only mode
    "manage_orphans": {"list"},                       # enum list|remove (server.py:782)
    "manage_install_reason": {"list"},                # enum list|mark_explicit|mark_dependency (:881)
}
READ_TOOLS = {...}                    # explicit allowlist of the other 18, incl. optimize_mirrors
PKG_RE = re.compile(r"^[a-z0-9@_+][a-z0-9@._+-]*$")   # Arch naming; no leading - or .

def check_allowed(name: str, arguments: dict) -> str | None: ...   # refusal text or None
def validate_packages(names: list[str]) -> None: ...                # raises ValueError
```

`optimize_mirrors` (enum `status|test|suggest|health`, server.py:1008) is
read-only — mirrors.py only ever opens the mirrorlist for reading.

**2.2 Gate in server.py.**
- `list_tools` (:613): drop `WRITE_TOOLS` when `READONLY`. Keep `MIXED_TOOLS`
  listed but narrow their `action` enum to the allowed set.
- top of `call_tool` (:1100): `if (msg := check_allowed(name, arguments)): return [TextContent(type="text", text=json.dumps({"error": msg}))]`.
  For `manage_orphans`, also refuse `dry_run=False`.
- Downgrade the args log at :1100 to `logger.debug`.
- HTTP reuses these handlers (http_server.py:38), so one gate covers both transports.

**2.3 Argument injection.** Call `validate_packages` in `remove_package` /
`remove_packages_batch` (pacman.py:323/398), `mark_as_*` (:1294/1348) and
`install_package_secure` (aur.py). Insert `"--"` before package names at
pacman.py:363, 440, 662 and aur.py:740, 881. Use `sudo -n` in every sudo argv
so nothing can ever wait on a password.

**2.4 Kill the child on timeout.** utils.py:145, before re-raising:
`process.kill(); await process.wait()`. (Killing sudo mid-transaction can leave
`/var/lib/pacman/db.lck` — one more reason writes stay off.)

**2.5 HTTP defaults.** Bind from `ARCH_OPS_HOST` (default `127.0.0.1`) and
`ARCH_OPS_PORT` (default `8220` — next free block after prism-executive's 8210;
`:8080` is nws-poller). Drop `allow_credentials=True`; origins only from
`CORS_ORIGINS` (default none); remove the hard-coded `access-control-allow-origin: *`
on the POST `/mcp` response; reject a non-local `Host` (403, DNS-rebinding) and
non-JSON POSTs (415). stdio stays the primary transport — HTTP is not deployed
by this plan.

**2.6 SSRF.** mirrors.py:121: accept `mirror_url` only when its host appears in
`/etc/pacman.d/mirrorlist` (or the archlinux.org mirror-status JSON); set
`follow_redirects=False` at :139. (Open decision: drop the parameter entirely.)

**2.7 Defense in depth in Claude Code.** In `~/Admin/.claude/settings.local.json`:

```json
"deny": ["mcp__arch-ops-server__install_package_secure",
         "mcp__arch-ops-server__remove_packages"],
"ask":  ["mcp__arch-ops-server__manage_orphans",
         "mcp__arch-ops-server__manage_install_reason"]
```

(If config-protection blocks the edit, apply it by hand.)

**Tests — `tests/test_safety.py`:**
- read-only: `list_tools()` names ∩ `WRITE_TOOLS` = ∅; mixed-tool enums narrowed
- `call_tool("remove_packages", …)` refused **and** mocked `run_command` never called
- `manage_orphans` with `action=remove` or `dry_run=False` refused
- `ARCH_OPS_READONLY=0` (monkeypatch + `importlib.reload`) → write tools reappear
- **classification completeness:** with read-only off, every listed tool is in
  exactly one of the three sets. A new upstream tool then fails CI-by-hand
  instead of slipping in ungated.
- `PKG_RE` rejects `-Rdd`, `--overwrite=*`, `.x`, `""`; accepts `linux-zen`, `lib32-gcc-libs`, `zfs-linux`
- argv passed to mocked `run_command` has `--` immediately before the names
- `run_command(["sleep", "5"], timeout=1)` raises and `pgrep -f "[s]leep 5"` finds nothing
- `test_mirror_speed("http://127.0.0.1:1/")` → validation error
- `run_http_server` default host is `127.0.0.1`

Done:
- `uv run pytest -o addopts="" -q -m "not network"` → no failures beyond the baseline 11
- stdio smoke: **20** tools listed (was 22); `remove_packages` call refused
- in Claude Code (`~/Admin`), `/mcp` shows 20 tools

Rollback: revert the Phase 2 commits on `ws0`. Because read-only is the code
default, a revert is the *only* way writes come back.

---

## Phase 3 — Extension pattern; worked example `preupgrade_gate`

Adding any read-only tool touches exactly these places:

1. implementation `async def` in a module, using `utils.run_command` (argv list,
   never a shell), returning a dict; errors via `create_error_response`
2. `__init__.py` import block (:20-74) and `__all__` (:189+)
3. `server.py` `from . import (...)` (:27+)
4. a `Tool(..., annotations=ToolAnnotations(readOnlyHint=True))` in `list_tools`
5. an `elif name == "...":` branch in `call_tool` before the `else` (:1288)
6. the name in `safety.READ_TOOLS` (the completeness test enforces this)
7. `tests/test_<name>.py` — `asyncio_mode=auto`, fixtures in `tests/conftest.py`
   (`mock_subprocess_success`, `mock_httpx_response`, `mock_arch_release`)

`tool_metadata.py` is unreferenced documentation — optional.

**Worked example — `preupgrade_gate`.** Verdict `GO | HOLD | BLOCK | UNKNOWN`
for the pending upgrade. Read-only, **fails closed**: UNKNOWN is never GO.
It encodes ws0's real upgrade hazards (archzfs lag, proprietary NVIDIA ABI).

1. **Fix the prerequisite bug first.** pacman.py:258 — test
   `exit_code not in (0, 2)` *before* the empty-stdout shortcut. Add a test:
   exit 1 + empty stdout ⇒ error, not "no updates".
2. **`src/arch_ops_server/upgrade_gate.py`**, `async def preupgrade_gate() -> dict`:
   - `check_updates_dry_run()` (pacman.py:219) — error ⇒ UNKNOWN
   - `get_news_since_last_update()` (news.py:200) + `check_critical_news()`
     (news.py:146) — any manual-intervention item since last update ⇒ HOLD
   - coupling table as data:
     `COUPLED = {"linux": ["zfs-linux", NVIDIA_PKG], "nvidia-utils": [NVIDIA_PKG]}`,
     `NVIDIA_PKG` resolved from `pacman -Qq` matching `^nvidia(-open)?$`
   - `linux` in the update list without `zfs-linux` ⇒ **BLOCK** (archzfs lag)
   - both present: read new zfs-linux's `linux=` dependency from the sync DB
     checkupdates uses — run `checkupdates` with `CHECKUPDATES_DB` set to a
     known path (documented override, `/usr/bin/checkupdates:71`), then
     `pacman -Si --dbpath "$CHECKUPDATES_DB" zfs-linux`. Mismatch with the new
     `linux` version ⇒ BLOCK. Same for the NVIDIA module vs `nvidia-utils`.
   - returns `{verdict, reasons[], updates_count, coupled_checks[], news[]}`
3. wire it per the 7-step list above.
4. **`tests/test_upgrade_gate.py`** (patch `arch_ops_server.upgrade_gate.*`):
   no updates ⇒ GO · linux without zfs-linux ⇒ BLOCK · version mismatch ⇒
   BLOCK · critical news ⇒ HOLD · checkupdates error ⇒ UNKNOWN · tool listed in
   read-only mode.

Done: tests green; a live call from Claude Code in `~/Admin` returns a verdict
with reasons.

**Menu of further ws0 tools** (candidates, not commitments):

- `zfs_health` — `zpool status -x`, last-scrub age, key-load state of `ipool/repos` and `dpool/admin`
- `compose_units_health` — oneshot compose units joined with their containers (`active (exited)` is healthy)
- `systemstate://` resources — expose `~/Admin/system-state/data/*.json` with their TTLs/ages
- `post_boot_gpu_check` — `lsmod | grep nvidia_drm` + `/sys/class/drm` connectors
- `pacnew_finder` — `.pacnew` / `.pacsave` under `/etc`

---

## Phase 4 — The 11 failing tests

One file at a time, investigate before changing anything:

```bash
uv run pytest -o addopts="" tests/test_security.py -x --tb=long
git log -S audit_package_security --oneline -- src tests   # which side moved last
```

- `test_security` (6) / `test_groups` (3), mostly `TypeError`: compare each
  call against the current signatures of `audit_package_security` and
  `manage_groups` — likely tests left behind by the recent tool consolidations
  (e.g. `9978c4b` "consolidate news tools 3->1"). *Cause not verified.*
- `test_groups` base-devel: fails with "package group 'base-devel' was not
  found" — the test depends on the live host. Replace with a mocked `pacman -Sg`.
- `test_storage::test_analyze_storage_cache_stats`: diff expected keys against
  `get_pacman_cache_stats` (system.py:152).

Fix clearly stale tests; otherwise `@pytest.mark.xfail(reason=..., strict=True)`
and note it in `docs/test-baseline.txt`.
Done: 0 failed; any xfails listed with reasons. Offering fixes upstream is a
separate decision (each push/PR needs its own yes).

---

## Phase 5 (optional) — wire into `~/Admin` arch-upgrade

In `~/Admin/.claude/skills/arch-upgrade/SKILL.md`, before Phase 1's
`checkupdates`: "If `mcp__arch-ops-server__preupgrade_gate` is available, call
it first; stop on BLOCK or UNKNOWN and report reasons." Keep the existing
`checkupdates` + WebFetch news path as the fallback. Allow
`mcp__arch-ops-server__preupgrade_gate` in `~/Admin/.claude/settings.local.json`.
Record the change with `/log-admin`.
Done: a dry run of the skill cites the gate verdict.

---

## Risks

| Risk | Mitigation |
|---|---|
| Write tools live through a missing env var | read-only is the code default; completeness test |
| Upstream rebase silently drops a guard | no CI — run the non-network suite after every rebase |
| Editable install follows the checked-out branch | checkout stays on `ws0` |
| Upstream adds a new write tool | completeness test fails until it is classified |
| Tag push publishes to PyPI/GHCR | `if:` guard + Actions disabled in GitHub + `tagOpt --no-tags` |
| Killed sudo leaves a pacman lock | writes are off; if ever enabled, document `db.lck` recovery |

## Open decisions (yours)

1. Claude Code scope: project `~/Admin` (recommended) vs user.
2. Upstream sync by rebase (assumed) or merge.
3. Ever enable writes (`ARCH_OPS_READONLY=0`)? If so, only behind Claude Code ask rules.
4. `mirror_url`: restrict to mirrorlist hosts, or remove it.
5. Offer fixes upstream (each push/PR its own yes).
6. Disable Actions on the fork in GitHub settings (only you can).

## Not verified

- causes of the 11 test failures (TypeError/AssertionError text only)
- that `pacman -Si --dbpath "$CHECKUPDATES_DB"` exposes new-version deps as described
- which tests hit the live network vs mocks
