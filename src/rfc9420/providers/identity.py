"""Protocol for credential and identity validation (RFC 9420 §5.3.1).

Implementations validate credentials in contexts such as add_key_package,
add, add_proposal, update_proposal, commit_update_path, group_info_join,
and external_senders. Raise to reject.
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable, Any


@runtime_checkable
class IdentityProviderProtocol(Protocol):
    """Interface for credential validation at MLS protocol events.

    Called with (credential, context_str). Raise an exception to reject
    the credential; return normally to accept.
    """

    def validate_credential(self, credential: Any, context: str) -> None:
        """Validate credential in the given context.

        Parameters
        ----------
        credential : Any
            The credential object (e.g. BasicCredential, X509Credential).
        context : str
            One of add_key_package, add, add_proposal, update_proposal,
            commit_update_path, group_info_join, external_senders.

        Raises
        ------
        Exception
            Any exception to reject the credential.
        """
        ...
