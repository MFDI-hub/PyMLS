from ..protocol.data_structures import CipherSuite
from .hpke import KEM, KDF, AEAD

# DAVE profile (v1.1.x) initial MLS ciphersuite targeting:
# MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519
DAVE_MLS_CIPHERSUITE = CipherSuite(
    kem=KEM.DHKEM_X25519_HKDF_SHA256,
    kdf=KDF.HKDF_SHA256,
    aead=AEAD.AES_128_GCM,
)

# Signature algorithm used alongside the above ciphersuite.
DAVE_SIGNATURE_ALGORITHM = "Ed25519"

