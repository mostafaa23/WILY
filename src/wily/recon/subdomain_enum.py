"""Passive subdomain enumeration via ProjectDiscovery's ``subfinder``.

Instead of only scanning the exact host(s) the user names, Wily can expand each
root target into its real, live subdomains first - so ``wily scan example.com``
also reaches ``api.example.com``, ``dev.example.com`` and the rest, exactly the
kind of forgotten edge hosts where cloud misconfigurations live. This replaces
blind guessing with a grounded attack surface.

Enumeration is **passive**: ``subfinder`` queries public sources (certificate
transparency, DNS aggregators, passive-DNS providers) and never sends brute-force
traffic to the target, which keeps Wily's read-only posture intact. Each
discovered subdomain that is in scope becomes an additional scan target, and the
complete target list is written to ``subdomains.txt`` so a later run can pick up
the same set with ``--targets-file``.

``subfinder`` is an external Go binary (https://github.com/projectdiscovery/
subfinder). Wily shells out to it when it is present and degrades gracefully with
a clear install hint when it is not - it is never a hard dependency.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

logger = logging.getLogger("wily.subdomain")

INSTALL_HINT = (
    "subfinder was not found on PATH. Install ProjectDiscovery's subfinder "
    "(https://github.com/projectdiscovery/subfinder) - e.g. "
    "`go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`, "
    "or `sudo apt install subfinder` on Kali - then re-run with --subdomains "
    "(or point to it with --subfinder-path)."
)


@dataclass
class SubdomainResult:
    """Outcome of enumerating one root target."""

    root: str
    subdomains: list[str] = field(default_factory=list)
    tool_available: bool = True
    error: str | None = None


def target_host(target: str) -> str:
    """Extract the bare hostname from a target that may be a URL or host:port."""
    raw = (target or "").strip()
    if not raw:
        return raw
    parsed = urlparse(raw if "://" in raw else f"//{raw}")
    return (parsed.hostname or raw).lower()


def find_subfinder(explicit: str | None = None) -> str | None:
    """Resolve the subfinder binary. Returns a runnable path, or ``None`` when it
    cannot be found. ``explicit`` (``--subfinder-path``) wins when it points at an
    existing file or a name on PATH."""
    if explicit:
        if Path(explicit).exists():
            return explicit
        return shutil.which(explicit)
    return shutil.which("subfinder")


def enumerate_subdomains(
    target: str,
    *,
    max_results: int | None = None,
    timeout: float = 180.0,
    binary: str | None = None,
    runner=None,
) -> SubdomainResult:
    """Run subfinder against ``target`` and return its in-scope subdomains.

    Passive only: ``subfinder -d <host> -silent``. Results are lowercased,
    de-duplicated, restricted to the target's own domain, sorted, and capped at
    ``max_results`` when given. ``runner`` is injectable for testing:
    ``runner(cmd: list[str], timeout: float) -> str`` (the raw stdout); when it
    is ``None`` the real ``subprocess`` is used. Any failure is captured on the
    result - this never raises.
    """
    host = target_host(target)
    result = SubdomainResult(root=host)
    if not host:
        result.error = "empty target"
        return result

    exe = find_subfinder(binary) if runner is None else (binary or "subfinder")
    if runner is None and exe is None:
        result.tool_available = False
        result.error = INSTALL_HINT
        return result

    cmd = [exe or "subfinder", "-d", host, "-silent"]
    try:
        if runner is None:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout, check=False
            )
            stdout = proc.stdout or ""
        else:
            stdout = runner(cmd, timeout) or ""
    except subprocess.TimeoutExpired:
        result.error = f"subfinder timed out after {timeout:.0f}s"
        return result
    except (OSError, ValueError) as exc:
        result.tool_available = False
        result.error = f"could not run subfinder: {exc}"
        return result

    suffix = f".{host}"
    seen: set[str] = set()
    found: list[str] = []
    for line in stdout.splitlines():
        name = line.strip().lower()
        if not name or name in seen:
            continue
        # subfinder only returns subdomains of the queried domain, but guard
        # anyway so an unexpected line can never pull us off-scope.
        if name == host or name.endswith(suffix):
            seen.add(name)
            found.append(name)

    found.sort()
    if max_results is not None and max_results > 0:
        found = found[:max_results]
    result.subdomains = found
    return result
