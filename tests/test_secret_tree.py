import unittest
from pymls.protocol.secret_tree import SecretTree
from pymls import DefaultCryptoProvider


class TestSecretTree(unittest.TestCase):
    def test_application_and_handshake_paths(self):
        c = DefaultCryptoProvider()
        st = SecretTree(b"root", c, n_leaves=1)
        k1, n1, g1 = st.next_application(0)
        k2, n2, g2 = st.application_for(0, g1)
        self.assertEqual(n1, n2)
        self.assertEqual(g2, g1)
        hk1, hn1, hg1 = st.next_handshake(0)
        hk2, hn2, hg2 = st.handshake_for(0, hg1)
        self.assertEqual(hn1, hn2)
        self.assertEqual(hg2, hg1)

    def test_multi_leaf_isolation(self):
        c = DefaultCryptoProvider()
        st = SecretTree(b"root", c, n_leaves=3)
        # Same generation across two different leaves should yield different keys
        k0, n0, _ = st.application_for(0, 5)
        k1, n1, _ = st.application_for(1, 5)
        self.assertNotEqual(k0, k1)
        self.assertNotEqual(n0, n1)


if __name__ == "__main__":
    unittest.main()


