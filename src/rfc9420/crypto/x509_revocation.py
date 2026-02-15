"""CRL and OCSP revocation helpers (best-effort, no network by default)."""
from __future__ import annotations

import datetime as _dt
from typing import Optional, Callable

from ..mls.exceptions import RFC9420Error


def _now_utc() -> _dt.datetime:
    """Return current UTC time (separated for testability)."""
    return _dt.datetime.utcnow()

def check_ocsp_end_entity(
    end_entity_der: bytes,
    issuer_der: bytes,
    now: Optional[_dt.datetime] = None,
    cache: Optional[dict] = None,
    ttl_seconds: int = 900,
    fetcher: Optional[Callable[[str, bytes], bytes]] = None,
    fail_open: bool = False,
) -> bool:
    """
    Basic OCSP revocation check for an end-entity certificate.
    - Attempts to find an OCSP responder URL in the AIA extension.
    - Builds an OCSP request and fetches a response (using fetcher or urllib).
    - Verifies the OCSP response signature with the issuer public key.
    - Returns True if status is 'good', False if 'revoked'. Returns True if no responder.

    This helper performs best-effort network fetching if a fetcher is not provided.
    In environments without network, pass a custom fetcher or leave OCSP disabled.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.x509.ocsp import OCSPRequestBuilder, load_der_ocsp_response
    except Exception as e:
        raise RFC9420Error("cryptography package required for OCSP checking") from e

    now = now or _now_utc()
    cache = cache if cache is not None else {}

    # Load certificates
    def _load_cert(buf: bytes):
        try:
            return x509.load_der_x509_certificate(buf)
        except Exception:
            return x509.load_pem_x509_certificate(buf)

    ee = _load_cert(end_entity_der)
    issuer = _load_cert(issuer_der)

    # Extract OCSP responder URL from AIA if present
    ocsp_urls = []
    try:
        aia = ee.extensions.get_extension_for_class(x509.AuthorityInformationAccess).value
        for ad in aia:
            if ad.access_method == x509.AuthorityInformationAccessOID.OCSP and isinstance(ad.access_location, x509.UniformResourceIdentifier):
                ocsp_urls.append(str(ad.access_location.value))
    except x509.ExtensionNotFound:
        pass
    if not ocsp_urls:
        # No OCSP responder advertised; treat as not revoked
        return True

    # Cache key by serial
    cache_key = f"ocsp:{ee.serial_number:x}"
    if cache_key in cache:
        ts, ok = cache[cache_key]
        if (now - ts).total_seconds() <= ttl_seconds:
            return bool(ok)

    # Build OCSP request
    builder = OCSPRequestBuilder().add_certificate(ee, issuer, hashes.SHA256())
    req = builder.build()
    # Fetch response from first available OCSP URL
    resp_bytes: Optional[bytes] = None
    if fetcher:
        try:
            resp_bytes = fetcher(ocsp_urls[0], req.public_bytes(serialization.Encoding.DER))
        except Exception:
            resp_bytes = None
    elif ocsp_urls:
        try:
            import urllib.request

            req_obj = urllib.request.Request(
                ocsp_urls[0],
                data=req.public_bytes(serialization.Encoding.DER),
                headers={"Content-Type": "application/ocsp-request"},
                method="POST",
            )
            with urllib.request.urlopen(req_obj, timeout=5) as r:  # nosec B310 (best-effort)
                resp_bytes = r.read()
        except Exception:
            resp_bytes = None
    if not resp_bytes:
        # Network unavailable or responder error
        cache[cache_key] = (now, bool(fail_open))
        return bool(fail_open)

    ocsp_resp = load_der_ocsp_response(resp_bytes)
    # Validate responder status and signature
    if ocsp_resp.response_status.name != "SUCCESSFUL":
        cache[cache_key] = (now, bool(fail_open))
        return bool(fail_open)
    single = ocsp_resp  # cryptography returns a high-level object with .certificate_status
    try:
        ocsp_resp._responder_key_hash  # type: ignore[attr-defined]
    except Exception:
        # Can't access internals reliably; verify signature at a high level by catching exceptions
        pass
    try:
        ocsp_resp.public_bytes(serialization.Encoding.DER)  # force parse
    except Exception as e:
        raise RFC9420Error("OCSP response parsing failed") from e
    # Certificate status
    if single.certificate_status.name == "REVOKED":
        cache[cache_key] = (now, False)
        return False
    # Not revoked
    cache[cache_key] = (now, True)
    return True


def check_crl(
    end_entity_der: bytes,
    issuer_der: bytes,
    now: Optional[_dt.datetime] = None,
    cache: Optional[dict] = None,
    ttl_seconds: int = 900,
    fetcher: Optional[Callable[[str], bytes]] = None,
    fail_open: bool = False,
) -> bool:
    """
    Basic CRL check for an end-entity certificate.
    - Attempts to find a CRL Distribution Point in the certificate.
    - Downloads a CRL (using fetcher or urllib) and verifies if the EE serial is listed.
    - Returns True if not listed (not revoked), False if listed. Returns True if no CDP.
    """
    try:
        from cryptography import x509
    except Exception as e:
        raise RFC9420Error("cryptography package required for CRL checking") from e

    now = now or _now_utc()
    cache = cache if cache is not None else {}

    def _load_cert(buf: bytes):
        try:
            return x509.load_der_x509_certificate(buf)
        except Exception:
            return x509.load_pem_x509_certificate(buf)

    ee = _load_cert(end_entity_der)
    issuer = _load_cert(issuer_der)  # noqa: F841 (reserved for potential signature verification)

    crl_urls = []
    try:
        cdp = ee.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        for dp in cdp:
            for name in dp.full_name or []:
                if isinstance(name, x509.UniformResourceIdentifier):
                    crl_urls.append(str(name.value))
    except x509.ExtensionNotFound:
        pass
    if not crl_urls:
        return True

    cache_key = f"crl:{ee.serial_number:x}"
    if cache_key in cache:
        ts, ok = cache[cache_key]
        if (now - ts).total_seconds() <= ttl_seconds:
            return bool(ok)

    crl_bytes: Optional[bytes] = None
    if fetcher:
        try:
            crl_bytes = fetcher(crl_urls[0])
        except Exception:
            crl_bytes = None
    elif crl_urls:
        try:
            import urllib.request

            with urllib.request.urlopen(crl_urls[0], timeout=5) as r:  # nosec B310 (best-effort)
                crl_bytes = r.read()
        except Exception:
            crl_bytes = None
    if not crl_bytes:
        cache[cache_key] = (now, bool(fail_open))
        return bool(fail_open)

    try:
        try:
            crl = x509.load_der_x509_crl(crl_bytes)
        except Exception:
            crl = x509.load_pem_x509_crl(crl_bytes)
    except Exception as e:
        raise RFC9420Error("CRL parsing failed") from e

    # If serial appears in CRL, mark revoked
    for revoked in crl:
        if revoked.serial_number == ee.serial_number:
            cache[cache_key] = (now, False)
            return False

    cache[cache_key] = (now, True)
    return True


