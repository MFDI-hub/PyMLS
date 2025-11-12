import unittest
from src.pymls.protocol.test_vectors import generate_key_schedule_vector


class TestKeyScheduleVectors(unittest.TestCase):
    def test_vector_fields_present(self):
        v = generate_key_schedule_vector()
        # Ensure expected fields exist and look hex-like (length > 0)
        for k in [
            "epoch_secret",
            "handshake_secret",
            "application_secret",
            "exporter_secret",
            "confirmation_key",
            "membership_key",
            "resumption_psk",
        ]:
            self.assertIn(k, v)
            self.assertTrue(isinstance(v[k], str))
            self.assertTrue(len(v[k]) > 0)


if __name__ == "__main__":
    unittest.main()


