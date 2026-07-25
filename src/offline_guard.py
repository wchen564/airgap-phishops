"""A narrow network policy for the inference adapter.

This is an application-level guard, not a claim of OS-level packet capture.
Every inference endpoint is checked before the local client is invoked.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
from urllib.parse import urlparse


class OfflinePolicyError(RuntimeError):
    """Raised before any non-loopback inference request can be made."""


def is_loopback_host(hostname: str | None) -> bool:
    if hostname is None:
        return False
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


@dataclass
class InferenceNetworkAudit:
    local_calls: int = 0
    external_attempts: int = 0
    blocked_hosts: list[str] = field(default_factory=list)

    def authorize(self, endpoint: str) -> None:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"}:
            self.external_attempts += 1
            self.blocked_hosts.append(endpoint)
            raise OfflinePolicyError(
                "Inference endpoint must use HTTP(S) on a loopback host."
            )
        if not is_loopback_host(parsed.hostname):
            self.external_attempts += 1
            self.blocked_hosts.append(parsed.hostname or endpoint)
            raise OfflinePolicyError(
                f"Blocked non-local inference endpoint: {endpoint}"
            )
        self.local_calls += 1
