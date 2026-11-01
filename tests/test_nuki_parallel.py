"""Cross-process Nuki request serialization and bounded busy retries."""
import contextlib
import fcntl
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "check_nuki.py"
SPEC = importlib.util.spec_from_file_location("nuki_parallel", SCRIPT)
nuki = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nuki)
HAVE_NACL = importlib.util.find_spec("nacl") is not None


class ParallelNukiChecks(unittest.TestCase):
    def test_busy_is_retried_but_authentication_is_not(self):
        for sequence, expected_calls, success in (
            ([nuki.BridgeBusy("busy"), {"ok": True}], 2, True),
            ([nuki.BridgeBusy("busy")] * 3, 3, False),
            ([nuki.CheckError("auth rejected")], 1, False),
        ):
            with patch.object(nuki, "bridge_lock", return_value=contextlib.nullcontext()), \
                    patch.object(nuki.time, "sleep"), \
                    patch.object(nuki, "request_once", side_effect=sequence) as request:
                if success:
                    self.assertEqual(nuki.request("127.0.0.1", 8080, "fake", "/info"), {"ok": True})
                else:
                    with self.assertRaises(nuki.CheckError):
                        nuki.request("127.0.0.1", 8080, "fake", "/info")
                self.assertEqual(request.call_count, expected_calls)

    def test_every_busy_retry_uses_a_new_encrypted_token(self):
        responses = []
        for status in (503, 200):
            response = Mock(status=status)
            response.read.return_value = b'{"ok":true}'
            connection = Mock()
            connection.getresponse.return_value = response
            responses.append(connection)
        with patch.object(nuki, "bridge_lock", return_value=contextlib.nullcontext()), \
                patch.object(nuki.time, "sleep"), \
                patch.object(nuki, "encrypted_query", side_effect=("ctoken=first&nonce=one", "ctoken=second&nonce=two")), \
                patch.object(nuki.http.client, "HTTPConnection", side_effect=responses):
            self.assertEqual(nuki.request("127.0.0.1", 8080, "fake", "/info"), {"ok": True})
        self.assertNotEqual(responses[0].request.call_args.args[1], responses[1].request.call_args.args[1])

    def test_private_persistent_lock_and_unsafe_path_refusal(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "check-nuki-127.0.0.1-8080.lock"
            with patch.object(nuki.time, "sleep"):
                with nuki.bridge_lock("127.0.0.1", 8080, folder):
                    self.assertTrue(path.is_file())
                    self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            self.assertTrue(path.is_file(), "unlinking a lock permits split lock ownership")
            path.chmod(0o644)
            with self.assertRaises(nuki.CheckError):
                with nuki.bridge_lock("127.0.0.1", 8080, folder):
                    self.fail("broad permissions accepted")
            path.unlink()
            path.symlink_to(Path(folder) / "other-file")
            with self.assertRaises(nuki.CheckError):
                with nuki.bridge_lock("127.0.0.1", 8080, folder):
                    self.fail("symlink accepted")

    def test_queue_wait_is_bounded_and_lock_is_released_on_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "check-nuki-127.0.0.1-8080.lock"
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                with patch.object(nuki.time, "monotonic", side_effect=(10, 19)):
                    with self.assertRaises(nuki.CheckError) as failure:
                        with nuki.bridge_lock("127.0.0.1", 8080, folder):
                            self.fail("contended lock acquired")
                self.assertEqual(failure.exception.code, 3)
            finally:
                os.close(fd)
            with patch.object(nuki.time, "sleep"):
                with self.assertRaises(ValueError):
                    with nuki.bridge_lock("127.0.0.1", 8080, folder):
                        raise ValueError("fake transport failure")
                with nuki.bridge_lock("127.0.0.1", 8080, folder):
                    pass

    @unittest.skipUnless(HAVE_NACL, "PyNaCl is not installed")
    def test_four_real_processes_share_one_bridge_request_slot(self):
        counts = {"active": 0, "peak": 0, "busy": 0, "requests": 0}
        guard = threading.Lock()

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_):
                pass

            def do_GET(self):
                with guard:
                    counts["active"] += 1
                    counts["peak"] = max(counts["peak"], counts["active"])
                    counts["requests"] += 1
                    busy = counts["active"] > 1
                    counts["busy"] += int(busy)
                try:
                    time.sleep(0.15)
                    self.send_response(503 if busy else 200)
                    self.end_headers()
                    self.wfile.write(json.dumps({"endpoint": urlsplit(self.path).path}).encode())
                finally:
                    with guard:
                        counts["active"] -= 1

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        processes = []
        try:
            with tempfile.TemporaryDirectory() as folder:
                worker = (
                    "import json,runpy,signal,sys; "
                    "p=runpy.run_path(sys.argv[1]); signal.alarm(15); "
                    "print(json.dumps(p['request']('127.0.0.1',int(sys.argv[2]),"
                    "'fake-test-token',sys.argv[3],lock_directory=sys.argv[4])))"
                )
                for endpoint in ("/list", "/list", "/info", "/info"):
                    processes.append(subprocess.Popen(
                        [sys.executable, "-c", worker, str(SCRIPT),
                         str(server.server_port), endpoint, folder],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                for process, expected in zip(processes, ("/list", "/list", "/info", "/info")):
                    output, error = process.communicate(timeout=20)
                    self.assertEqual(process.returncode, 0, error)
                    self.assertEqual(json.loads(output)["endpoint"], expected)
            self.assertEqual(counts, {"active": 0, "peak": 1, "busy": 0, "requests": 4})
        finally:
            for process in processes:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()

