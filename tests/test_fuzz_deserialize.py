import unittest
import os
from pymls.protocol.messages import MLSPlaintext, MLSCiphertext


class TestFuzzDeserialize(unittest.TestCase):
    def test_plaintext_fuzz(self):
        for _ in range(50):
            data = os.urandom(32)
            try:
                _ = MLSPlaintext.deserialize(data)
            except Exception:
                pass

    def test_ciphertext_fuzz(self):
        for _ in range(50):
            data = os.urandom(48)
            try:
                _ = MLSCiphertext.deserialize(data)
            except Exception:
                pass


if __name__ == "__main__":
    unittest.main()


