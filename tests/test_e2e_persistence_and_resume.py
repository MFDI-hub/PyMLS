import unittest

from tests.helpers import has_hpke, make_group

from rfc9420.api import MLSGroupSession


class TestE2EPersistenceAndResume(unittest.TestCase):
    def setUp(self):
        if not has_hpke():
            self.skipTest("HPKE support not available: rfc9180-py dependency missing")

    def test_group_to_bytes_from_bytes(self):
        group, _, crypto = make_group(b"persist-group")
        blob = group.to_bytes()
        restored = type(group).from_bytes(blob, crypto)
        self.assertEqual(restored.group_id, group.group_id)
        self.assertEqual(restored.epoch, group.epoch)

    def test_session_serialize_deserialize(self):
        group, _, crypto = make_group(b"persist-session")
        sess = MLSGroupSession(group)
        blob = sess.serialize()
        loaded = MLSGroupSession.deserialize(blob, crypto)
        self.assertEqual(loaded.group_id, sess.group_id)
        self.assertEqual(loaded.epoch, sess.epoch)


if __name__ == "__main__":
    unittest.main()
