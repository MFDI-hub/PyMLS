import os
import unittest

from rfc9420 import DefaultCryptoProvider
from rfc9420.protocol.secret_tree import SecretTree


class TestAlgorithmicSecretTree(unittest.TestCase):
    def setUp(self):
        self.crypto = DefaultCryptoProvider()
        self.secret = os.urandom(self.crypto.kdf_hash_len())

    def test_generation_is_monotonic(self):
        st = SecretTree(self.secret, self.crypto, n_leaves=1)
        _, _, g0 = st.next_application(0)
        _, _, g1 = st.next_application(0)
        self.assertEqual(g1, g0 + 1)

    def test_leaf_isolation(self):
        st = SecretTree(self.secret, self.crypto, n_leaves=2)
        k0, n0, _ = st.application_for(0, 4)
        k1, n1, _ = st.application_for(1, 4)
        self.assertNotEqual(k0, k1)
        self.assertNotEqual(n0, n1)

    def test_window_out_of_order_access(self):
        st = SecretTree(self.secret, self.crypto, n_leaves=1, window_size=2)
        _, _, g2 = st.application_for(0, 2)
        self.assertEqual(g2, 2)
        # This should still be retrievable from skipped cache.
        _, _, g1 = st.application_for(0, 1)
        self.assertEqual(g1, 1)


if __name__ == "__main__":
    unittest.main()
