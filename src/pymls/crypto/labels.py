"""
Canonical MLS label constants for domain separation (RFC 9420 §5, §6, §12, §17).
All labels here are the context-specific parts; cryptographic helpers that
require "MLS 1.0 " prefixing will prepend it as needed.
"""

# Signing labels (used with sign_with_label/verify_with_label; provider prepends "MLS 1.0 ")
FRAMED_CONTENT_TBS = b"FramedContentTBS"
GROUP_INFO_TBS = b"GroupInfoTBS"

# HPKE info labels (embedded inside the EncryptContext.label as "MLS 1.0 " + <LABEL>)
HPKE_WELCOME = b"Welcome"
HPKE_UPDATE_PATH_NODE = b"UpdatePathNode"

# Hash-based reference labels (embedded literally inside RefHashInput.label)
REF_KEYPACKAGE = b"MLS 1.0 KeyPackage Reference"
REF_PROPOSAL = b"MLS 1.0 Proposal Reference"

# Key schedule and exporter textual labels (passed to derive/expand helpers)
# Note: Provider will prepend "MLS 1.0 " for expand_with_label/derive_secret.
KS_EPOCH = b"epoch"
KS_INIT = b"init"
KS_HANDSHAKE = b"handshake"
KS_APPLICATION = b"application"
KS_EXPORTER = b"exporter"
KS_EXTERNAL = b"external"
KS_SENDER_DATA = b"sender data"
KS_ENCRYPTION = b"encryption"
KS_CONFIRM = b"confirm"
KS_MEMBERSHIP = b"membership"
KS_RESUMPTION = b"resumption"
KS_AUTHENTICATION = b"authentication"


