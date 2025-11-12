"""Best-effort X.509 chain verification and policy enforcement helpers."""
from __future__ import annotations

from typing import List
from ..mls.exceptions import (
    PyMLSError,
    UnsupportedCipherSuiteError,
    CredentialValidationError,
    CredentialRevocationError,
)

def verify_certificate_chain(chain_der: List[bytes], trust_roots_pem: List[bytes]) -> bytes:
    """
    Minimal X.509 chain verification:
    - chain_der[0] is the leaf, subsequent entries are intermediates
    - trust_roots_pem contains one or more root certificates in PEM or DER
    Returns the leaf public key in raw SubjectPublicKeyInfo DER encoding.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import padding
    except Exception as e:
        raise PyMLSError("cryptography package required for X.509 validation") from e

    # Load certificates
    def load_cert(buf: bytes):
        try:
            return x509.load_der_x509_certificate(buf)
        except Exception:
            return x509.load_pem_x509_certificate(buf)

    certs = [load_cert(c) for c in chain_der]
    if not certs:
        raise CredentialValidationError("empty certificate chain")

    roots = [load_cert(r) for r in trust_roots_pem]
    if not roots:
        raise CredentialValidationError("no trust roots provided")

    # Verify each certificate is signed by the next (leaf -> intermediates)
    def verify_sig(child, issuer):
        pub = issuer.public_key()
        sig = child.signature
        data = child.tbs_certificate_bytes
        # Choose padding/hash based on signature algorithm
        if not hasattr(pub, "verify"):
            raise CredentialValidationError("unsupported public key type")
        if child.signature_hash_algorithm is None:
            raise UnsupportedCipherSuiteError("unsupported signature algorithm")
        # Use concrete key classes for robust detection
        try:
            from cryptography.hazmat.primitives.asymmetric import rsa, ec as _ec_mod
        except Exception as e:
            raise PyMLSError("cryptography package required for X.509 validation") from e
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(sig, data, padding.PKCS1v15(), child.signature_hash_algorithm)
        elif isinstance(pub, _ec_mod.EllipticCurvePublicKey):
            pub.verify(sig, data, _ec_mod.ECDSA(child.signature_hash_algorithm))
        else:
            # Ed25519/Ed448 and others: their verify() typically takes (sig, data)
            pub.verify(sig, data)

    for i in range(len(certs) - 1):
        verify_sig(certs[i], certs[i + 1])

    # Verify the last cert is signed by a trusted root
    last = certs[-1]
    matched = False
    for root in roots:
        # Match by subject / issuer and verify signature
        if last.issuer == root.subject:
            verify_sig(last, root)
            matched = True
            break
    if not matched:
        raise CredentialValidationError("no matching trust root for issuer")

    # Return leaf public key (SPKI DER)
    leaf_pub = certs[0].public_key()
    return leaf_pub.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def load_default_trust_roots() -> List[bytes]:
    """
    Load system default trust roots via certifi, if available.
    Returns a list with a single PEM bundle or empty if not available.
    """
    try:
        import certifi
        with open(certifi.where(), "rb") as f:
            return [f.read()]
    except Exception:
        return []


def verify_certificate_chain_with_policy(chain_der: List[bytes], trust_roots_pem: List[bytes], policy) -> bytes:
    """
    Verify the certificate chain and enforce policy checks (validity, KU/EKU, revocation).
    Returns the leaf SPKI DER on success.
    """
    try:
        from cryptography import x509
    except Exception as e:
        raise PyMLSError("cryptography package required for X.509 validation") from e

    leaf_spki = verify_certificate_chain(chain_der, trust_roots_pem)
    if policy is None:
        return leaf_spki

    # Load leaf certificate for policy checks
    def load_cert(buf: bytes):
        try:
            return x509.load_der_x509_certificate(buf)
        except Exception:
            return x509.load_pem_x509_certificate(buf)

    leaf = load_cert(chain_der[0])

    # Validity period with leeway
    import datetime as _dt
    now = _dt.datetime.utcnow()
    if leaf.not_valid_before - _dt.timedelta(seconds=policy.not_before_leeway_s) > now:
        raise CredentialValidationError("certificate not yet valid")
    if leaf.not_valid_after + _dt.timedelta(seconds=policy.not_after_leeway_s) < now:
        raise CredentialValidationError("certificate expired")

    # Key Usage (require digitalSignature when requested)
    if policy.require_digital_signature_ku:
        try:
            ku = leaf.extensions.get_extension_for_class(x509.KeyUsage).value
            if not ku.digital_signature:
                raise CredentialValidationError("digitalSignature key usage not present")
        except x509.ExtensionNotFound:
            raise CredentialValidationError("KeyUsage extension missing")

    # EKU: if acceptable EKUs configured, require one to match
    if policy.acceptable_ekus:
        try:
            eku_ext = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            eku_oids = {oid.dotted_string for oid in eku_ext}
            if not any(oid in eku_oids for oid in policy.acceptable_ekus):
                raise CredentialValidationError("certificate EKU does not permit use for MLS policy")
        except x509.ExtensionNotFound:
            raise CredentialValidationError("ExtendedKeyUsage extension missing")

    # Revocation: pluggable checks (no network I/O here)
    if policy.revocation.enable_crl and policy.revocation.crl_checker:
        if not policy.revocation.crl_checker(chain_der[0]):
            raise CredentialRevocationError("certificate revoked (CRL)")
    if policy.revocation.enable_ocsp and policy.revocation.ocsp_checker:
        if not policy.revocation.ocsp_checker(chain_der[0]):
            raise CredentialRevocationError("certificate revoked (OCSP)")

    return leaf_spki