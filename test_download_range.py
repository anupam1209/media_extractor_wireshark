#!/usr/bin/env python3
"""
Tests for HTTP Range support on /api/download -- what makes the audio/video seek bar
in the web UI work (a player seeks by asking for "the bytes from offset N onward").

Stdlib only (unittest): no ffmpeg / tshark / browser / optional extras needed.
Run directly:
    python3 test_download_range.py
...or under pytest:
    pytest test_download_range.py

Three layers are covered:
  1. parse_byte_range()  -- the pure header parser (every form, every edge case).
  2. the real /api/download handler on a throwaway localhost server: a request without
     Range is the same full 200 as ever; Range requests get exact 206 slices; bad ranges
     get 416; unknown tokens still 404.
  3. a client that hangs up mid-transfer (what a browser does on every seek) must not
     produce a server traceback.
"""
import http.client
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from http.server import ThreadingHTTPServer
from unittest import mock

import webapp
from webapp import RangeNotSatisfiable, parse_byte_range


class ParseByteRangeTests(unittest.TestCase):
    def test_satisfiable_ranges(self):
        cases = {
            "bytes=0-99": (0, 99),
            "bytes=10-19": (10, 19),
            "bytes=0-0": (0, 0),
            "bytes=10-": (10, 99),            # open-ended: through the last byte
            "bytes=99-": (99, 99),
            "bytes=-10": (90, 99),            # suffix: the final 10 bytes
            "bytes=-1000": (0, 99),           # suffix longer than the file: all of it
            "bytes=50-9999": (50, 99),        # end clamped to the file
            "BYTES = 5-6": (5, 6),            # unit is case-insensitive; stray spaces tolerated
        }
        for header, want in cases.items():
            with self.subTest(header=header):
                self.assertEqual(parse_byte_range(header, 100), want)

    def test_ignored_headers_mean_serve_everything(self):
        # None -> the caller sends the whole file as a normal 200 (all allowed by RFC 9110)
        for header in (None, "", "items=0-5", "bytes", "bytes=", "bytes=-", "bytes=abc",
                       "bytes=5-2", "bytes=0-1,5-6", "bytes 0-5", "bytes=0-5x",
                       "bytes=0-" + "9" * 5000):   # absurd length must not blow up int()
            with self.subTest(header=header[:30] if header else header):
                self.assertIsNone(parse_byte_range(header, 100))

    def test_unsatisfiable_ranges_raise(self):
        for header in ("bytes=100-", "bytes=100-200", "bytes=5000-", "bytes=-0"):
            with self.subTest(header=header):
                with self.assertRaises(RangeNotSatisfiable):
                    parse_byte_range(header, 100)
        for header in ("bytes=0-", "bytes=0-0", "bytes=-5"):     # nothing to range over
            with self.subTest(header=header, size=0):
                with self.assertRaises(RangeNotSatisfiable):
                    parse_byte_range(header, 0)


class _Server(ThreadingHTTPServer):
    """Throwaway server that records what socketserver would have printed as a traceback,
    and counts finished requests so a test can wait for one to be fully handled."""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.errors = []
        self.finished = threading.Semaphore(0)

    def handle_error(self, request, client_address):
        self.errors.append(sys.exc_info()[1])

    def process_request_thread(self, request, client_address):
        super().process_request_thread(request, client_address)   # runs handle_error on failure
        self.finished.release()


class _ServerCase(unittest.TestCase):
    """Starts the real webapp.Handler on an ephemeral localhost port."""

    @classmethod
    def setUpClass(cls):
        cls._env = mock.patch.dict(os.environ)      # basic-auth env vars would 401 the requests
        cls._env.start()
        os.environ.pop("MEDIAX_USER", None)
        os.environ.pop("MEDIAX_PASS", None)
        cls.tmp = tempfile.TemporaryDirectory()
        cls.tokens = []
        cls.server = _Server(("127.0.0.1", 0), webapp.Handler)
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        for tok in cls.tokens:
            webapp.OUTPUT_REGISTRY.pop(tok, None)
        cls.tmp.cleanup()
        cls._env.stop()

    @classmethod
    def register(cls, token, name, data):
        path = os.path.join(cls.tmp.name, name)
        with open(path, "wb") as fh:
            fh.write(data)
        webapp.OUTPUT_REGISTRY[token] = path
        cls.tokens.append(token)
        return path


class DownloadEndpointTests(_ServerCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        # non-repeating payload, so a slice from the wrong offset can't pass by accident
        cls.data = bytes((i * 7 + i // 251) % 256 for i in range(300_000))
        cls.register("rng_wav", "clip_accurate.wav", cls.data)
        cls.register("rng_mp4", "clip.mp4", cls.data)

    def get(self, token="rng_wav", range_header=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request("GET", f"/api/download?f={token}",
                         headers={"Range": range_header} if range_header else {})
            r = conn.getresponse()
            return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()
        finally:
            conn.close()

    def test_request_without_range_is_still_the_whole_file(self):
        status, h, body = self.get()
        self.assertEqual(status, 200)
        self.assertEqual(body, self.data)
        self.assertEqual(h["content-length"], str(len(self.data)))
        self.assertEqual(h["content-type"], "audio/wav")
        self.assertEqual(h["content-disposition"], 'attachment; filename="clip_accurate.wav"')
        self.assertEqual(h["accept-ranges"], "bytes")     # advertises seekability to the player
        self.assertNotIn("content-range", h)

    def test_mp4_keeps_its_content_type(self):
        for rng in (None, "bytes=0-99"):
            status, h, _ = self.get("rng_mp4", rng)
            self.assertEqual(h["content-type"], "video/mp4")
            self.assertEqual(status, 200 if rng is None else 206)

    def test_range_requests_return_the_exact_slice(self):
        n = len(self.data)
        cases = {
            "bytes=1000-1999": (1000, 1999),
            "bytes=0-": (0, n - 1),                       # what a player sends first
            f"bytes={n - 100}-": (n - 100, n - 1),        # seek near the end
            "bytes=-100": (n - 100, n - 1),               # suffix
            "bytes=250000-99999999": (250000, n - 1),     # end clamped
            "bytes=0-0": (0, 0),
        }
        for header, (a, b) in cases.items():
            with self.subTest(header=header):
                status, h, body = self.get(range_header=header)
                self.assertEqual(status, 206)
                self.assertEqual(body, self.data[a:b + 1])
                self.assertEqual(h["content-range"], f"bytes {a}-{b}/{n}")
                self.assertEqual(h["content-length"], str(b - a + 1))
                self.assertEqual(h["accept-ranges"], "bytes")
                self.assertEqual(h["content-type"], "audio/wav")
                self.assertEqual(h["content-disposition"],
                                 'attachment; filename="clip_accurate.wav"')

    def test_slice_spanning_several_write_chunks(self):
        a, b = 1, len(self.data) - 2        # unaligned start, crosses every 64 KiB boundary
        status, _, body = self.get(range_header=f"bytes={a}-{b}")
        self.assertEqual(status, 206)
        self.assertEqual(body, self.data[a:b + 1])

    def test_range_past_the_end_is_416(self):
        n = len(self.data)
        for header in (f"bytes={n}-", f"bytes={n + 5}-{n + 50}", "bytes=-0"):
            with self.subTest(header=header):
                status, h, _ = self.get(range_header=header)
                self.assertEqual(status, 416)
                self.assertEqual(h["content-range"], f"bytes */{n}")

    def test_unusable_range_falls_back_to_the_whole_file(self):
        for header in ("bytes=0-10,20-30", "items=0-10", "bytes=9-2", "bytes=oops"):
            with self.subTest(header=header):
                status, _, body = self.get(range_header=header)
                self.assertEqual(status, 200)
                self.assertEqual(body, self.data)

    def test_unknown_token_is_still_404(self):
        for rng in (None, "bytes=0-9"):
            status, h, body = self.get("no-such-token", rng)
            self.assertEqual(status, 404)
            self.assertIn(b"not found", body)
            self.assertEqual(h["content-type"], "application/json")


class ClientHangUpTests(_ServerCase):
    def test_hanging_up_mid_transfer_is_not_a_server_error(self):
        """A browser cancels the in-flight request on every seek. That must be silent,
        not a 'Exception occurred during processing of request' traceback."""
        self.register("rng_big", "big.wav", bytes(16 * 1024 * 1024))   # far bigger than socket buffers
        s = socket.socket()
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)        # tiny window: server blocks mid-send
        s.settimeout(10)
        s.connect(("127.0.0.1", self.port))
        s.sendall(b"GET /api/download?f=rng_big HTTP/1.1\r\nHost: x\r\nRange: bytes=0-\r\n\r\n")
        self.assertIn(b"206", s.recv(1024))                            # transfer is under way
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        s.close()                                                      # RST, like a dropped request
        self.assertTrue(self.server.finished.acquire(timeout=15), "server never finished the request")
        self.assertEqual(self.server.errors, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
