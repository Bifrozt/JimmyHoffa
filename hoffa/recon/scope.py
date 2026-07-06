"""
hoffa.recon.scope — engagement scope enforcement.

A target is permitted only if it matches the configured allowlist. The
allowlist is declared in cfg under [scope]:

    [scope]
    allow = ["10.0.0.0/24", "192.168.56.0/24", "target.example.com"]

Matching rules:
  - IP target vs CIDR entry: membership test.
  - IP target vs IP entry: equality.
  - Hostname target vs hostname entry: case-insensitive exact match, or
    subdomain match when the entry is a bare domain (e.g. "example.com"
    permits "app.example.com").
  - Hostname target vs CIDR entry: no match (no DNS resolution is performed;
    resolving to satisfy scope would let DNS control scope, which is unsafe).

Design intent: the tool must be structurally unable to act outside scope.
Enforcement is fail-closed — an empty or absent allowlist permits nothing,
and any parse ambiguity raises rather than silently widening scope.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field

from .core import is_ip_literal


class ScopeError(Exception):
    """Raised when a target is out of scope or the scope config is invalid."""


@dataclass
class Scope:
    """Parsed engagement scope allowlist."""
    networks: list[ipaddress._BaseNetwork] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)  # lowercased hostnames
    raw: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not self.networks and not self.hosts

    @classmethod
    def from_entries(cls, entries: list[str]) -> "Scope":
        """Build a Scope from raw cfg allowlist strings.

        CIDR / IP entries become networks; everything else is treated as a
        hostname entry. Invalid entries raise ScopeError (fail-closed).
        """
        networks: list[ipaddress._BaseNetwork] = []
        hosts: list[str] = []
        for entry in entries:
            e = entry.strip()
            if not e:
                continue
            if _looks_like_ip_or_cidr(e):
                try:
                    networks.append(ipaddress.ip_network(e, strict=False))
                except ValueError as exc:
                    raise ScopeError(f"invalid CIDR/IP in scope: {e!r} ({exc})")
            else:
                hosts.append(e.lower())
        return cls(networks=networks, hosts=hosts, raw=list(entries))

    def permits(self, target: str) -> bool:
        """True if target is within scope."""
        t = target.strip()
        if not t:
            return False

        if is_ip_literal(t):
            addr = ipaddress.ip_address(t)
            return any(addr in net for net in self.networks)

        # Hostname target.
        host = t.lower()
        for entry in self.hosts:
            if host == entry:
                return True
            # bare-domain entry permits its subdomains
            if host.endswith("." + entry):
                return True
        return False


def _looks_like_ip_or_cidr(entry: str) -> bool:
    """Heuristic: does this entry denote an IP or CIDR rather than a hostname?"""
    if "/" in entry:
        return True
    return is_ip_literal(entry)


def enforce(scope: Scope, target: str) -> None:
    """Raise ScopeError unless target is permitted. Fail-closed on empty scope."""
    if scope.is_empty:
        raise ScopeError(
            "no engagement scope configured. Define [scope] allow = [...] in cfg. "
            "Refusing to scan with an empty allowlist (fail-closed)."
        )
    if not scope.permits(target):
        raise ScopeError(
            f"target {target!r} is not within the configured engagement scope: "
            f"{scope.raw}. Refusing."
        )
