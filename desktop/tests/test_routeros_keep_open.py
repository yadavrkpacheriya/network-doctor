"""One router login is kept open and reused (no more "logged in / logged out via api" for every reading)."""
import threading
import unittest

import nd_routeros as RO


class FakeSock:
    def __init__(self):
        self.closed = False

    def settimeout(self, t):
        pass

    def close(self):
        self.closed = True


class Client(RO.RouterOS):
    """RouterOS with the network replaced: counts logins, answers every command with !done."""
    logins = 0
    dead = set()

    def connect(self):
        Client.logins += 1
        self.sock, self._buf = FakeSock(), b""
        return self

    def talk(self, words, check=True):
        if self.sock is None or self.sock in Client.dead:
            raise RO.RosError("the router closed the connection")
        return [("!done", [])]


class KeepOpen(unittest.TestCase):
    def setUp(self):
        RO.close_all()
        Client.logins, Client.dead = 0, set()

    def tearDown(self):
        RO.close_all()

    def c(self, pw="p"):
        return Client("192.168.0.1", "fanair", pw)

    def test_many_readings_use_one_login(self):
        for _ in range(5):
            with self.c() as c:
                c.talk(["/ip/dns/cache/all/print"])
        self.assertEqual(Client.logins, 1)

    def test_router_restart_logs_in_again_without_an_error(self):
        with self.c() as c:
            first = c.sock
        Client.dead.add(first)                       # the router dropped that connection
        with self.c() as c:
            c.talk(["/system/resource/print"])       # works: a new login was made behind the scenes
        self.assertEqual(Client.logins, 2)
        self.assertTrue(first.closed)

    def test_an_error_in_the_middle_does_not_keep_that_login(self):
        with self.assertRaises(ValueError):
            with self.c() as c:
                sock = c.sock
                raise ValueError("boom")
        self.assertTrue(sock.closed)
        with self.c():
            pass
        self.assertEqual(Client.logins, 2)

    def test_another_password_never_shares_the_login(self):
        with self.c("a"):
            pass
        with self.c("b"):
            pass
        self.assertEqual(Client.logins, 2)

    def test_nested_with_on_the_same_client_keeps_it_open_until_the_outer_ends(self):
        c = self.c()
        with c:
            with c:
                pass
            self.assertIsNotNone(c.sock)
        self.assertIsNone(c.sock)
        self.assertEqual(Client.logins, 1)

    def test_two_threads_take_turns_on_the_one_login(self):
        inside, clash = [0], [False]

        def use():
            for _ in range(20):
                with self.c() as c:
                    inside[0] += 1
                    if inside[0] > 1:
                        clash[0] = True
                    c.talk(["/x"])
                    inside[0] -= 1
        ts = [threading.Thread(target=use) for _ in range(4)]
        [t.start() for t in ts]
        [t.join() for t in ts]
        self.assertFalse(clash[0])
        self.assertEqual(Client.logins, 1)

    def test_close_all_and_switching_it_off(self):
        with self.c() as c:
            sock = c.sock
        RO.close_all()
        self.assertTrue(sock.closed)
        RO.KEEP_OPEN = False
        try:
            with self.c() as c:
                s2 = c.sock
            self.assertTrue(s2.closed)
        finally:
            RO.KEEP_OPEN = True


if __name__ == "__main__":
    unittest.main()
