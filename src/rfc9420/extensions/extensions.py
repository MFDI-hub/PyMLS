"""Encoding helpers and simple constructors for MLS extensions (MVP set)."""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
from typing import Optional, Tuple
import os

from ..codec.tls import (
    write_uint16,
    write_opaque_varint,
    read_uint16,
    read_opaque_varint,
)


class ExtensionType(IntEnum):
    """Extension type identifiers per RFC 9420 §17.3 IANA registry.

    Values 0x0001–0x0005 are from RFC 9420 Table 9.
    Values 0x000A–0x000D follow common interop conventions.
    Values 0xFF00+ are private-use / implementation-specific.
    """
    # RFC 9420 Table 9 (IANA-registered)
    APPLICATION_ID = 0x0001
    RATCHET_TREE = 0x0002
    REQUIRED_CAPABILITIES = 0x0003
    EXTERNAL_PUB = 0x0004
    EXTERNAL_SENDERS = 0x0005
    # Standard LeafNode extensions (interop conventions)
    # Note: These use private-use values (0xFFxx) as they are not standardized in RFC 9420 IANA registry.
    CAPABILITIES = 0xFF02   # Private-use: no IANA-assigned value for LeafNode capabilities
    LIFETIME = 0xFF03       # Private-use: no IANA-assigned value for LeafNode lifetime
    KEY_ID = 0xFF04         # Private-use: no IANA-assigned value for external key ID
    PARENT_HASH = 0xFF05    # Private-use: no IANA-assigned value for parent hash
    # Implementation-specific (private-use range)
    SUPPORTED_VERSIONS = 0xFF00
    EPOCH_AUTHENTICATOR = 0xFF01


GREASE_VALUES: tuple[int, ...] = (
    0x0A0A, 0x1A1A, 0x2A2A, 0x3A3A, 0x4A4A,
    0x5A5A, 0x6A6A, 0x7A7A, 0x8A8A, 0x9A9A,
    0xAAAA, 0xBABA, 0xCACA, 0xDADA, 0xEAEA,
)


def is_grease_value(value: int) -> bool:
    """Return True when value is one of RFC 9420 §13.5 GREASE code points."""
    return int(value) in GREASE_VALUES


def random_grease_values(max_count: int = 2) -> list[int]:
    """Pick up to max_count GREASE values for extensibility hardening."""
    if max_count <= 0:
        return []
    count = min(max_count, len(GREASE_VALUES))
    # Random sampling without replacement.
    entropy = os.urandom(count)
    out: list[int] = []
    used: set[int] = set()
    for b in entropy:
        v = GREASE_VALUES[b % len(GREASE_VALUES)]
        if v in used:
            continue
        out.append(v)
        used.add(v)
        if len(out) >= count:
            break
    return out


@dataclass(frozen=True)
class Extension:
    """Generic extension: (type, opaque data)."""
    ext_type: int
    data: bytes

    def serialize(self) -> bytes:
        """Encode as uint16(type) || opaque16(data)."""
        return write_uint16(self.ext_type) + write_opaque_varint(self.data)

    @classmethod
    def deserialize(cls, data: bytes) -> Tuple["Extension", int]:
        """Parse an Extension from the beginning of data and return (ext, bytes_used)."""
        off = 0
        t, off = read_uint16(data, off)
        body, off = read_opaque_varint(data, off)
        # We store as int to allow unknown/private types
        return cls(t, body), off



def serialize_extensions(exts: list[Extension]) -> bytes:
    """Encode a vector of extensions as concatenated entries (no count prefix).

    The caller is responsible for adding any outer length prefix (e.g. vector<V>).
    Extension types must be unique within the list.

    Parameters:
        exts: List of Extension instances (no duplicate ext_type).

    Returns:
        Concatenated serialized extensions.

    Raises:
        ValueError: If duplicate extension types are present.
    """
    validate_extension_uniqueness(exts)
    out = b""
    for e in exts:
        out += e.serialize()
    return out


def deserialize_extensions(data: bytes) -> list[Extension]:
    """Parse a vector of extensions from the data (consumes all data).

    Parameters:
        data: Concatenated extension encodings (uint16 type || opaque16 payload per extension).

    Returns:
        List of Extension instances. Duplicate types are rejected.
    """
    out: list[Extension] = []
    off = 0
    while off < len(data):
        e, used = Extension.deserialize(data[off:])
        out.append(e)
        off += used
    validate_extension_uniqueness(out)
    return out


def validate_extension_uniqueness(exts: list[Extension]) -> None:
    """Reject extension lists that contain duplicate extension types.

    Parameters:
        exts: List of extensions to check.

    Raises:
        ValueError: If any extension type appears more than once.
    """
    seen: set[int] = set()
    for ext in exts:
        ext_type = int(ext.ext_type)
        if ext_type in seen:
            raise ValueError(f"duplicate extension type: {ext_type}")
        seen.add(ext_type)



def make_parent_hash_ext(parent_hash: bytes) -> Extension:
    """Build a PARENT_HASH extension from the provided parent hash bytes."""
    return Extension(ExtensionType.PARENT_HASH, parent_hash)


def make_capabilities_ext(data: bytes) -> Extension:
    """Build a CAPABILITIES extension with pre-encoded capability data."""
    return Extension(ExtensionType.CAPABILITIES, data)


def make_key_id_ext(key_id: bytes) -> Extension:
    """Build a KEY_ID extension wrapping an opaque identifier."""
    return Extension(ExtensionType.KEY_ID, key_id)


def make_lifetime_ext(not_before: int, not_after: int) -> Extension:
    """Build a LIFETIME extension from not_before/not_after unix timestamps."""
    from ..codec.tls import write_uint64
    payload = write_uint64(not_before) + write_uint64(not_after)
    return Extension(ExtensionType.LIFETIME, payload)


def parse_lifetime_ext(data: bytes) -> tuple[int, int]:
    """Parse LIFETIME extension payload into (not_before, not_after) timestamps."""
    from ..codec.tls import read_uint64
    off = 0
    nb, off = read_uint64(data, off)
    na, off = read_uint64(data, off)
    return nb, na


def make_external_pub_ext(public_key: bytes) -> Extension:
    """Build an EXTERNAL_PUB extension carrying a public key bytes value."""
    return Extension(ExtensionType.EXTERNAL_PUB, public_key)


def parse_external_pub_ext(data: bytes) -> bytes:
    """Return the raw EXTERNAL_PUB payload (identity function)."""
    return data


def build_capabilities_data(
    ciphersuite_ids: list[int],
    supported_exts: list[int],
    versions: Optional[list[int]] = None,
    proposals: Optional[list[int]] = None,
    credentials: Optional[list[int]] = None,
    include_grease: bool = True,
) -> bytes:
    """Encode Capabilities per RFC 9420 §7.2.

    struct {
        ProtocolVersion versions<V>;
        CipherSuite ciphersuites<V>;
        ExtensionType extensions<V>;
        ProposalType proposals<V>;
        CredentialType credentials<V>;
    } Capabilities;
    """
    from ..codec.tls import write_uint16
    versions = versions or [0x0001]  # MLS10 by default
    proposals = proposals or []
    credentials = credentials or [1]  # Basic credential by default

    cs_vals = [int(v) for v in ciphersuite_ids]
    ext_vals = [int(v) for v in supported_exts]
    prop_vals = [int(v) for v in proposals]
    cred_vals = [int(v) for v in credentials]
    if include_grease:
        for g in random_grease_values(2):
            if g not in cs_vals:
                cs_vals.append(g)
            if g not in ext_vals:
                ext_vals.append(g)
            if g not in prop_vals:
                prop_vals.append(g)
            if g not in cred_vals:
                cred_vals.append(g)

    def encode_vec(items: list[int]) -> bytes:
        out = write_uint16(len(items))
        for v in items:
            out += write_uint16(int(v))
        return out

    return (
        encode_vec(versions)
        + encode_vec(cs_vals)
        + encode_vec(ext_vals)
        + encode_vec(prop_vals)
        + encode_vec(cred_vals)
    )


def parse_capabilities_data(data: bytes) -> dict:
    """Decode Capabilities payload per RFC 9420 §7.2.

    Returns a dict with keys: versions, ciphersuites, extensions, proposals, credentials.
    Falls back to 2-field legacy format if the 5-field parse fails, for backward compatibility.
    """
    from ..codec.tls import read_uint16

    def read_vec(d: bytes, off: int) -> tuple[list[int], int]:
        n, off = read_uint16(d, off)
        items = []
        for _ in range(n):
            v, off = read_uint16(d, off)
            items.append(v)
        return items, off

    try:
        off = 0
        versions, off = read_vec(data, off)
        ciphersuites, off = read_vec(data, off)
        extensions, off = read_vec(data, off)
        proposals, off = read_vec(data, off)
        credentials, off = read_vec(data, off)
        # GREASE values are intentionally ignored by receivers.
        return {
            "versions": versions,
            "ciphersuites": [v for v in ciphersuites if not is_grease_value(v)],
            "extensions": [v for v in extensions if not is_grease_value(v)],
            "proposals": [v for v in proposals if not is_grease_value(v)],
            "credentials": [v for v in credentials if not is_grease_value(v)],
        }
    except Exception:
        # Legacy 2-field fallback: (ciphersuites, extensions)
        from ..codec.tls import read_uint16
        off = 0
        n_cs, off = read_uint16(data, off)
        cs_ids = []
        for _ in range(n_cs):
            cs, off = read_uint16(data, off)
            cs_ids.append(cs)
        n_ext, off = read_uint16(data, off)
        exts = []
        for _ in range(n_ext):
            t, off = read_uint16(data, off)
            exts.append(t)
        return {"versions": [], "ciphersuites": cs_ids, "extensions": exts, "proposals": [], "credentials": []}


def build_required_capabilities(
    exts_required: list[int],
    props_required: Optional[list[int]] = None,
    creds_required: Optional[list[int]] = None,
) -> bytes:
    """Encode REQUIRED_CAPABILITIES extension.

    RFC 9420 §11.1:
    struct {
        ExtensionType extension_types<V>;
        ProposalType proposal_types<V>;
        CredentialType credential_types<V>;
    } RequiredCapabilities;
    """
    from ..codec.tls import write_uint16
    
    props_required = props_required or []
    creds_required = creds_required or []

    out = write_uint16(len(exts_required))
    for e in exts_required:
        out += write_uint16(int(e))
    
    out += write_uint16(len(props_required))
    for p in props_required:
        out += write_uint16(int(p))
        
    out += write_uint16(len(creds_required))
    for c in creds_required:
        out += write_uint16(int(c))
        
    return out


def parse_required_capabilities(data: bytes) -> tuple[list[int], list[int], list[int]]:
    """Decode REQUIRED_CAPABILITIES payload.
    
    Returns:
        (extension_types, proposal_types, credential_types)
    """
    from ..codec.tls import read_uint16
    off = 0
    
    # Extension types
    num_ext, off = read_uint16(data, off)
    exts: list[int] = []
    for _ in range(num_ext):
        val, off = read_uint16(data, off)
        exts.append(val)
        
    # Proposal types
    num_prop, off = read_uint16(data, off)
    props: list[int] = []
    for _ in range(num_prop):
        val, off = read_uint16(data, off)
        props.append(val)
        
    # Credential types
    num_cred, off = read_uint16(data, off)
    creds: list[int] = []
    for _ in range(num_cred):
        val, off = read_uint16(data, off)
        creds.append(val)
        
    return exts, props, creds
