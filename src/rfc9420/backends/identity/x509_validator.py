"""X.509 credential validator implementing IdentityProviderProtocol.

Uses chain verification and optional policy/revocation from rfc9420.crypto.x509.
"""

from __future__ import annotations

from typing import Any, List, Optional

from .x509 import verify_certificate_chain_with_policy
from .x509_policy import X509Policy
from ...messages.credentials import BasicCredential, X509Credential
from ...mls.exceptions import CredentialValidationError


class X509IdentityProvider:
    """Identity backend that validates X.509 credentials and accepts Basic credentials.

    For X509Credential: verifies the certificate chain against trust_roots and
    applies the optional X509Policy (validity, KU/EKU, revocation).
    For BasicCredential: no cryptographic validation (accept by default).
    """

    def __init__(
        self,
        trust_roots: Optional[List[bytes]] = None,
        policy: Optional[X509Policy] = None,
    ) -> None:
        self._trust_roots = trust_roots or []
        self._policy = policy

    def validate_credential(self, credential: Any, context: str) -> None:
        if isinstance(credential, BasicCredential):
            return
        if isinstance(credential, X509Credential):
            if not self._trust_roots:
                raise CredentialValidationError("X.509 validation requires trust roots")
            verify_certificate_chain_with_policy(
                credential.cert_chain,
                self._trust_roots,
                self._policy,
            )
            return
        raise CredentialValidationError(f"Unsupported credential type: {type(credential)}")
