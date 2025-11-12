from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Callable


@dataclass
class RevocationConfig:
    enable_crl: bool = False
    enable_ocsp: bool = False
    # Pluggable fetchers/checkers; return True if not revoked, False if revoked
    crl_checker: Optional[Callable[[bytes], bool]] = None
    ocsp_checker: Optional[Callable[[bytes], bool]] = None
    # Cache toggle (no-op placeholder)
    cache_enabled: bool = True


@dataclass
class X509Policy:
    """
    X.509 certificate policy checks applied after chain validation.
    """
    require_digital_signature_ku: bool = True
    # Acceptable EKUs as dotted-string OIDs; empty means no EKU restriction
    acceptable_ekus: List[str] = field(default_factory=list)
    # Validity leeway in seconds
    not_before_leeway_s: int = 300
    not_after_leeway_s: int = 300
    revocation: RevocationConfig = field(default_factory=RevocationConfig)


