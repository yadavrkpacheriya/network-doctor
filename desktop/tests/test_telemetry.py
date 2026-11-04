# -*- coding: utf-8 -*-
"""3.21: nd_telemetry.py - the sending side (opt-in usage/crash reports). Off by default; never records or
sends anything until switched on; never sends anything until an admin address is set."""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import nd_telemetry as TL  # noqa: E402


def telem(**over):
    store = {}
    t = TL.Telemetry("ND", "9.9", store, lambda: None)
    for k, v in over.items():
        setattr(t, k, v)
    return t, store


class InstallId(unittest.TestCase):
    def test_a_fresh_store_gets_a_random_16_char_hex_id(self):
        t, _ = telem()
        self.assertEqual(len(t.install_id), 16)
        int(t.install_id, 16)  # all hex

    def test_the_same_store_keeps_its_id_across_instances(self):
        store = {}
        a = TL.Telemetry("ND", "9.9", store, lambda: None)
        b = TL.Telemetry("ND", "9.9", store, lambda: None)
        self.assertEqual(a.install_id, b.install_id)

    def test_two_different_stores_get_different_ids(self):
        a, _ = telem()
        b, _ = telem()
        self.assertNotEqual(a.install_id, b.install_id)


class OffByDefault(unittest.TestCase):
    def test_disabled_until_switched_on(self):
        t, _ = telem()
        self.assertFalse(t.enabled)

    def test_note_is_a_noop_while_disabled(self):
        t, _ = telem()
        t.note("scan")
        self.assertEqual(t.pending_report()["counts"], {})

    def test_note_error_is_a_noop_while_disabled(self):
        t, _ = telem()
        try:
            1 / 0
        except ZeroDivisionError as e:
            t.note_error("test", e)
        rep = t.pending_report()
        self.assertEqual(rep["counts"], {})
        self.assertEqual(rep["crashes"], [])

    def test_send_now_refuses_while_disabled_even_with_an_address(self):
        t, _ = telem()
        t.set_admin_url("https://admin.example.com")
        ok, detail = t.send_now()
        self.assertFalse(ok)
        self.assertIn("off", detail)

    def test_send_now_refuses_without_an_address_even_when_enabled(self):
        t, _ = telem()
        t.set_enabled(True)
        ok, detail = t.send_now()
        self.assertFalse(ok)
        self.assertIn("address", detail)


class Counting(unittest.TestCase):
    def setUp(self):
        self.t, self.store = telem()
        self.t.set_enabled(True)

    def test_note_counts_each_call(self):
        self.t.note("scan")
        self.t.note("scan")
        self.t.note("login_sweep")
        counts = self.t.pending_report()["counts"]
        self.assertEqual(counts["scan"], 2)
        self.assertEqual(counts["login_sweep"], 1)

    def test_note_error_counts_and_remembers_a_sanitised_crash(self):
        try:
            raise ValueError("boom")
        except ValueError as e:
            self.t.note_error("quick_check", e)
        rep = self.t.pending_report()
        self.assertEqual(rep["counts"]["error:quick_check"], 1)
        self.assertEqual(len(rep["crashes"]), 1)
        c = rep["crashes"][0]
        self.assertEqual(c["type"], "ValueError")
        self.assertEqual(c["message"], "boom")

    def test_crash_list_is_capped(self):
        for _ in range(TL.MAX_CRASHES + 10):
            try:
                raise RuntimeError("x")
            except RuntimeError as e:
                self.t.note_error("loop", e)
        self.assertEqual(len(self.t.pending_report()["crashes"]), TL.MAX_CRASHES)

    def test_turning_off_clears_whatever_was_pending(self):
        self.t.note("scan")
        self.t.set_enabled(False)
        self.assertEqual(self.t.pending_report()["counts"], {})

    def test_pending_report_never_carries_anything_beyond_the_known_fields(self):
        self.t.note("scan")
        rep = self.t.pending_report()
        self.assertEqual(set(rep), {"install_id", "app", "kind", "version", "platform", "sent_at",
                                    "counts", "crashes"})
        self.assertEqual(rep["kind"], "desktop")


class Where(unittest.TestCase):
    def test_prefers_the_deepest_network_doctor_frame(self):
        def nd_core_like():
            raise ValueError("x")

        def NetworkDoctor_like():
            nd_core_like()
        try:
            NetworkDoctor_like()
        except ValueError as e:
            w = TL.where(e.__traceback__)
        self.assertIn("test_telemetry.py", w)  # this test file itself is the deepest frame (not nd_/NetworkDoctor)

    def test_blank_traceback_gives_a_placeholder(self):
        self.assertEqual(TL.where(None), "?")


class Sending(unittest.TestCase):
    def setUp(self):
        self.t, self.store = telem()
        self.t.set_enabled(True)
        self.t.set_admin_url("https://admin.example.com")
        self.t.note("scan")

    def test_nothing_to_send_is_reported_ok_without_a_network_call(self):
        t2, _ = telem()
        t2.set_enabled(True)
        t2.set_admin_url("https://admin.example.com")
        calls = []
        ok, detail = t2.send_now(opener=lambda *a, **k: calls.append(1))
        self.assertTrue(ok)
        self.assertIn("nothing", detail)
        self.assertEqual(calls, [])

    def test_successful_send_clears_pending_and_posts_to_the_telemetry_path(self):
        seen = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"{}"

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            seen["body"] = req.data
            return FakeResp()

        ok, detail = self.t.send_now(opener=opener)
        self.assertTrue(ok)
        self.assertEqual(detail, "sent")
        self.assertEqual(seen["url"], "https://admin.example.com/api/telemetry")
        self.assertEqual(self.t.pending_report()["counts"], {})

    def test_a_trailing_slash_on_the_admin_url_is_tolerated(self):
        self.t.set_admin_url("https://admin.example.com/")
        seen = {}

        class FakeResp:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

            def read(self):
                return b"{}"

        def opener(req, timeout=None):
            seen["url"] = req.full_url
            return FakeResp()

        self.t.note("scan")
        self.t.send_now(opener=opener)
        self.assertEqual(seen["url"], "https://admin.example.com/api/telemetry")

    def test_a_network_failure_leaves_the_pending_report_untouched(self):
        def opener(req, timeout=None):
            raise OSError("network down")

        before = self.t.pending_report()["counts"]
        ok, detail = self.t.send_now(opener=opener)
        self.assertFalse(ok)
        self.assertIn("network down", detail)
        self.assertEqual(self.t.pending_report()["counts"], before)


class Hooks(unittest.TestCase):
    def test_sys_excepthook_records_and_calls_through(self):
        t, _ = telem()
        t.set_enabled(True)
        calls = []
        prev_hook = lambda et, v, tb: calls.append((et, v))  # noqa: E731
        import sys
        old = sys.excepthook
        sys.excepthook = prev_hook
        try:
            t.install_hook()
            try:
                raise RuntimeError("crash")
            except RuntimeError:
                sys.excepthook(*sys.exc_info())
        finally:
            sys.excepthook = old
        self.assertEqual(len(calls), 1)
        self.assertEqual(t.pending_report()["crashes"][0]["type"], "RuntimeError")

    def test_tk_hook_records_and_calls_through(self):
        t, _ = telem()
        t.set_enabled(True)

        class FakeWidget:
            def report_callback_exception(self, *a):
                pass
        w = FakeWidget()
        called = []
        w.report_callback_exception = lambda et, v, tb: called.append(v)
        t.install_tk_hook(w)
        try:
            raise KeyError("missing")
        except KeyError:
            import sys
            w.report_callback_exception(*sys.exc_info())
        self.assertEqual(len(called), 1)
        self.assertEqual(t.pending_report()["crashes"][0]["type"], "KeyError")


if __name__ == "__main__":
    unittest.main()
