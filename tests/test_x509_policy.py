import unittest
import datetime
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

from rfc9420.crypto.x509_policy import X509Policy
from rfc9420.crypto.x509 import verify_certificate_chain_with_policy


def _self_signed_cert(digital_signature: bool = True, add_eku_client_auth: bool = True) -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "PyMLS Test Cert")])
    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    ku = x509.KeyUsage(
        digital_signature=digital_signature,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
    )
    builder = builder.add_extension(ku, critical=False)
    if add_eku_client_auth:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False
        )
    cert = builder.sign(private_key=key, algorithm=hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


class TestX509Policy(unittest.TestCase):
    def test_policy_accepts_valid_cert(self):
        leaf = _self_signed_cert(digital_signature=True, add_eku_client_auth=True)
        policy = X509Policy(
            require_digital_signature_ku=True,
            acceptable_ekus=[ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string],
        )
        # trust root is the same self-signed cert
        spki = verify_certificate_chain_with_policy([leaf], [leaf], policy)
        self.assertIsInstance(spki, bytes)
        self.assertTrue(len(spki) > 0)

    def test_policy_rejects_missing_ku(self):
        leaf = _self_signed_cert(digital_signature=False, add_eku_client_auth=True)
        policy = X509Policy(
            require_digital_signature_ku=True,
            acceptable_ekus=[ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string],
        )
        with self.assertRaises(Exception):
            verify_certificate_chain_with_policy([leaf], [leaf], policy)

    def test_policy_rejects_missing_eku(self):
        leaf = _self_signed_cert(digital_signature=True, add_eku_client_auth=False)
        policy = X509Policy(
            require_digital_signature_ku=True,
            acceptable_ekus=[ExtendedKeyUsageOID.CLIENT_AUTH.dotted_string],
        )
        with self.assertRaises(Exception):
            verify_certificate_chain_with_policy([leaf], [leaf], policy)
