from __future__ import annotations

from typing import List

def verify_certificate_chain(chain_der: List[bytes], trust_roots_pem: List[bytes]) -> bytes:
    """
    Minimal X.509 chain verification:
    - chain_der[0] is the leaf, subsequent entries are intermediates
    - trust_roots_pem contains one or more root certificates in PEM or DER
    Returns the leaf public key in raw SubjectPublicKeyInfo DER encoding.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization, hashes
        from cryptography.hazmat.primitives.asymmetric import padding
    except Exception as e:
        raise RuntimeError("cryptography package required for X.509 validation") from e

    # Load certificates
    def load_cert(buf: bytes):
        try:
            return x509.load_der_x509_certificate(buf)
        except Exception:
            return x509.load_pem_x509_certificate(buf)

    certs = [load_cert(c) for c in chain_der]
    if not certs:
        raise ValueError("empty certificate chain")

    roots = [load_cert(r) for r in trust_roots_pem]
    if not roots:
        raise ValueError("no trust roots provided")

    # Verify each certificate is signed by the next (leaf -> intermediates)
    def verify_sig(child, issuer):
        pub = issuer.public_key()
        sig = child.signature
        data = child.tbs_certificate_bytes
        # Choose padding/hash based on signature algorithm
        if hasattr(pub, "verify"):
            if child.signature_hash_algorithm is None:
                raise ValueError("unsupported signature algorithm")
            if pub.__class__.__name__.startswith("RSAPublicKey"):
                pub.verify(sig, data, padding.PKCS1v15(), child.signature_hash_algorithm)
            elif pub.__class__.__name__.startswith("EllipticCurvePublicKey"):
                pub.verify(sig, data, child.signature_hash_algorithm)
            else:
                # Fallback; attempt a generic verify (may raise)
                pub.verify(sig, data)
        else:
            raise ValueError("unsupported public key type")

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
        raise ValueError("no matching trust root for issuer")

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

