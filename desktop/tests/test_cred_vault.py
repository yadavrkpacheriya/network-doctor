# -*- coding: utf-8 -*-
"""One saved place for logins: the camera/NVR/DVR try-list (used automatically by the Login sweep) and the
PC-admin store (used by remote deploy). Passwords are always encrypted."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import nd_sweep as S  # noqa: E402
import nd_deploy as D  # noqa: E402


class CameraVault(unittest.TestCase):
    def test_add_encrypts_and_reads_back_as_pairs(self):
        store = []
        S.trylist_add(store, "admin", "cam123")
        S.trylist_add(store, "root", "pass!")
        self.assertNotIn("cam123", repr(store))                 # encrypted at rest
        self.assertEqual(S.trylist_pairs(store), [("admin", "cam123"), ("root", "pass!")])

    def test_no_duplicates_and_masked_display(self):
        store = []
        S.trylist_add(store, "admin", "cam123")
        S.trylist_add(store, "admin", "cam123")                 # same -> ignored
        self.assertEqual(len(store), 1)
        self.assertEqual(S.trylist_show(store), [("admin", "******")])  # never the real password

    def test_delete(self):
        store = []
        S.trylist_add(store, "admin", "a")
        S.trylist_add(store, "root", "b")
        S.trylist_del(store, "admin")
        self.assertEqual(S.trylist_pairs(store), [("root", "b")])

    def test_blank_user_is_ignored(self):
        store = []
        S.trylist_add(store, "  ", "x")
        self.assertEqual(store, [])


class SweepUsesTheVault(unittest.TestCase):
    def test_merge_typed_then_saved_deduped(self):
        # mirrors nd_sweeptab._creds(): typed first, then saved vault, no duplicates
        vault = []
        S.trylist_add(vault, "admin", "saved1")
        S.trylist_add(vault, "root", "saved2")
        typed = [("admin", "typed")]
        out, seen = [], set()
        for pair in typed + S.trylist_pairs(vault):
            if pair not in seen:
                seen.add(pair)
                out.append(pair)
        self.assertEqual(out, [("admin", "typed"), ("admin", "saved1"), ("root", "saved2")])


class PcAdminStoreStillWorks(unittest.TestCase):
    def test_admin_store_separate_from_camera_vault(self):
        admin = []
        D.admin_set(admin, "office", "Administrator", "pw")
        self.assertEqual(D.admin_creds(admin), [("office", "Administrator", "pw")])


if __name__ == "__main__":
    unittest.main()
