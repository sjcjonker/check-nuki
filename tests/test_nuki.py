"""Nuki parsing, monitoring semantics and credential transport regressions."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("nuki", ROOT / "check_nuki.py")
nuki = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(nuki)
ID = 12345678
TOKEN = "test-token-not-a-real-credential"
HAVE_NACL = importlib.util.find_spec("nacl") is not None


def inventory(**values):
    return [{"nukiId": ID, "deviceType": 0, "lastKnownState": {
        "mode": 2, "state": 1, "batteryCritical": False,
        "batteryChargeState": 60, **values}}]


class NukiChecks(unittest.TestCase):
    def setUp(self):
        folder = tempfile.TemporaryDirectory()
        self.addCleanup(folder.cleanup)
        lock_patch = patch.object(nuki, "LOCK_DIRECTORY", Path(folder.name))
        lock_patch.start()
        self.addCleanup(lock_patch.stop)

    def test_battery_percentage_and_existing_critical_semantics(self):
        self.assertEqual(nuki.battery(nuki.selected_state(inventory(), ID)),
                         (0, "lock battery 60%; not critical | battery_pct=60%;;;0;100"))
        self.assertEqual(nuki.battery({"batteryCritical": True})[0], 2)
        self.assertEqual(nuki.battery({"batteryCritical": False})[0], 0)
        for state in ({}, {"batteryCritical": "false"},
                      {"batteryCritical": False, "batteryChargeState": True},
                      {"batteryCritical": False, "batteryChargeState": 101}):
            with self.assertRaises(nuki.CheckError):
                nuki.battery(state)

    def test_open_or_unlocked_is_not_a_fault(self):
        for state in range(1, 8):
            self.assertEqual(nuki.health({"mode": 2, "state": state,
                                         "doorsensorState": 3})[0], 0)

    def test_blocked_and_uncalibrated_fail_even_without_mode(self):
        for state in (0, 254):
            self.assertEqual(nuki.health({"state": state})[0], 2)
        for state in ({"mode": 2, "state": 255}, {"mode": 2, "state": True},
                      {"mode": 2, "state": 42}, {"mode": 1, "state": 1}, {}):
            with self.assertRaises(nuki.CheckError):
                nuki.health(state)

    def test_missing_duplicate_or_wrong_device_does_not_pass(self):
        with self.assertRaises(nuki.CheckError) as failure:
            nuki.selected_state([], ID)
        self.assertEqual(failure.exception.code, 2)
        for payload in ({}, inventory() * 2,
                        [{"nukiId": ID, "deviceType": 2}],
                        [{"nukiId": True, "deviceType": 0}],
                        [{"nukiId": ID, "deviceType": 0}]):
            with self.assertRaises(nuki.CheckError):
                nuki.selected_state(payload, ID)

    def test_cloud_failure_is_warning_not_local_lock_failure(self):
        self.assertEqual(nuki.cloud({"serverConnected": True})[0], 0)
        self.assertEqual(nuki.cloud({"serverConnected": False})[0], 1)
        for value in ({}, {"serverConnected": "true"}, [], {"serverConnected": 1}):
            with self.assertRaises(nuki.CheckError):
                nuki.cloud(value)

    def test_rssi_stays_negative_and_never_proves_active_lock_reachability(self):
        info = {"scanResults": [{"nukiId": ID, "paired": True, "rssi": -63}]}
        code, text = nuki.bluetooth(info, ID)
        self.assertEqual(code, 0)
        self.assertIn("bridge scan", text)
        self.assertIn("rssi_dbm=-63;;;-127;0", text)
        for item in ({"nukiId": ID, "paired": False, "rssi": -63},
                     {"nukiId": ID, "paired": True, "rssi": "-63"},
                     {"nukiId": ID, "paired": True, "rssi": -128}):
            with self.assertRaises(nuki.CheckError):
                nuki.bluetooth({"scanResults": [item]}, ID)
        for scans in ([], info["scanResults"] * 2):
            with self.assertRaises(nuki.CheckError):
                nuki.bluetooth({"scanResults": scans}, ID)

    def test_raw_and_legacy_resource_values_resolve_to_the_same_token(self):
        for value in (TOKEN, "'" + TOKEN + "'",
                      "http://192.0.2.10:8080/list?token=" + TOKEN):
            self.assertEqual(nuki.parse_token("$USER10$=" + value + "\n", "192.0.2.10", 8080), TOKEN)
        for value in ("http://192.0.2.11:8080/list?token=" + TOKEN,
                      "http://192.0.2.10:8080/lock?token=" + TOKEN,
                      "http://192.0.2.10:8080/list?token=" + TOKEN + "&action=1",
                      "$(id)", "bad token", ""):
            with self.assertRaises(nuki.CheckError):
                nuki.parse_token("$USER10$=" + value, "192.0.2.10", 8080)
        for text in ("", "$USER10$=one\n$USER10$=two\n"):
            with self.assertRaises(nuki.CheckError):
                nuki.parse_token(text, "192.0.2.10", 8080)

    def test_private_resource_permissions_and_symlinks(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "resource.cfg"
            path.write_text("$USER10$=" + TOKEN + "\n")
            path.chmod(0o644)
            with self.assertRaises(nuki.CheckError):
                nuki.load_token(path, "192.0.2.10", 8080)
            link = Path(folder) / "link"
            link.symlink_to(path)
            with self.assertRaises(nuki.CheckError):
                nuki.load_token(link, "192.0.2.10", 8080)
            path.chmod(0o640)
            if os.geteuid() == 0:
                self.assertEqual(nuki.load_token(path, "192.0.2.10", 8080), TOKEN)

    def test_configurable_resource_macro(self):
        self.assertEqual(nuki.parse_token("$USER15$=" + TOKEN + "\n",
                                          "192.0.2.10", 8080, "USER15"), TOKEN)
        with self.assertRaises(nuki.CheckError):
            nuki.parse_token("$USER10$=" + TOKEN, "192.0.2.10", 8080, "USER15")
        for macro in ("USER0", "USER1$", "TOKEN", "USER-1", "USER1\n"):
            with self.assertRaises(nuki.CheckError):
                nuki.parse_token("$USER10$=" + TOKEN, "192.0.2.10", 8080, macro)

    def test_token_file_and_resource_options_are_exclusive(self):
        with patch.object(nuki, "load_token", return_value=TOKEN) as loader, \
                patch.object(nuki, "request", return_value=inventory()), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(nuki.main(["--host", "192.0.2.10", "--nuki-id", str(ID),
                                         "--mode", "battery", "--token-file", "/tmp/token"]), 0)
            self.assertEqual(loader.call_args.args,
                             ("/tmp/token", "192.0.2.10", 8080, None, True))
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                nuki.main(["--host", "192.0.2.10", "--nuki-id", str(ID),
                           "--mode", "battery", "--token-file", "/tmp/token",
                           "--resource-macro", "USER15"])
            with self.assertRaises(SystemExit):
                nuki.main(["--host", "192.0.2.10", "--nuki-id", str(ID),
                           "--mode", "battery"])

    def test_resource_macro_source_and_default_path(self):
        with patch.object(nuki, "load_token", return_value=TOKEN) as loader, \
                patch.object(nuki, "request", return_value=inventory()), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(nuki.main(["--host", "192.0.2.10", "--nuki-id", str(ID),
                                         "--mode", "battery", "--resource-macro", "USER15"]), 0)
        self.assertEqual(loader.call_args.args,
                         ("/etc/nagios4/resource.cfg", "192.0.2.10", 8080, "USER15", False))

    def test_raw_token_validation(self):
        self.assertEqual(nuki.validate_token(TOKEN), TOKEN)
        for value in ("$USER10$=" + TOKEN, "", "bad token", "http://192.0.2.10/"):
            with self.assertRaises(nuki.CheckError):
                nuki.validate_token(value)

    @unittest.skipUnless(HAVE_NACL, "PyNaCl is not installed")
    def test_crypto_decrypts_timestamp_and_nonzero_random_with_fresh_nonce(self):
        from nacl.secret import SecretBox
        first = parse_qs(nuki.encrypted_query(TOKEN))
        second = parse_qs(nuki.encrypted_query(TOKEN))
        self.assertEqual(set(first), {"ctoken", "nonce"})
        self.assertNotEqual(first["nonce"], second["nonce"])
        box = SecretBox(hashlib.sha256(TOKEN.encode()).digest())
        message = box.decrypt(bytes.fromhex(first["ctoken"][0]),
                              bytes.fromhex(first["nonce"][0])).decode()
        timestamp, random_number = message.split(",")
        clock = nuki.dt.datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=nuki.dt.timezone.utc)
        self.assertLess(abs((nuki.dt.datetime.now(nuki.dt.timezone.utc) - clock).total_seconds()), 5)
        self.assertTrue(1 <= int(random_number) <= 65535)
        self.assertNotIn(TOKEN, message)

    def test_get_only_no_redirect_no_plaintext_token(self):
        connection = Mock()
        response = connection.getresponse.return_value
        response.status = 200
        response.read.return_value = b'{"serverConnected":true}'
        with patch.object(nuki, "encrypted_query", return_value="ctoken=encrypted&nonce=random"), \
                patch.object(nuki.http.client, "HTTPConnection", return_value=connection):
            self.assertTrue(nuki.request("192.0.2.10", 8080, TOKEN, "/info")["serverConnected"])
        self.assertEqual(connection.request.call_args.args, ("GET", "/info?ctoken=encrypted&nonce=random"))
        self.assertNotIn(TOKEN, str(connection.request.call_args))
        connection.close.assert_called_once()
        for endpoint in ("/lock", "/unlock", "/lockState", "/fwupdate", "/reboot"):
            with self.assertRaises(nuki.CheckError):
                nuki.request("192.0.2.10", 8080, TOKEN, endpoint)

    def test_bad_response_errors_and_bodies_never_leak(self):
        for status in (302, 401, 403, 503):
            connection = Mock()
            connection.getresponse.return_value.status = status
            with patch.object(nuki, "encrypted_query", return_value="ctoken=x&nonce=y"), \
                    patch.object(nuki.http.client, "HTTPConnection", return_value=connection):
                with self.assertRaises(nuki.CheckError) as failure:
                    nuki.request("192.0.2.10", 8080, TOKEN, "/list")
            self.assertNotIn(TOKEN, str(failure.exception))
            connection.getresponse.return_value.read.assert_not_called()
        for payload in (b"not JSON " + TOKEN.encode(), b"x" * (nuki.LIMIT + 1)):
            connection = Mock()
            connection.getresponse.return_value.status = 200
            connection.getresponse.return_value.read.return_value = payload
            with patch.object(nuki, "encrypted_query", return_value="ctoken=x&nonce=y"), \
                    patch.object(nuki.http.client, "HTTPConnection", return_value=connection):
                with self.assertRaises(nuki.CheckError) as failure:
                    nuki.request("192.0.2.10", 8080, TOKEN, "/list")
            self.assertNotIn(TOKEN, str(failure.exception))

    def test_main_routes_each_mode_and_hides_network_exceptions(self):
        for mode, endpoint in (("battery", "/list"), ("health", "/list"),
                               ("cloud", "/info"), ("bluetooth", "/info")):
            info = {"serverConnected": True, "scanResults": [{"nukiId": ID, "paired": True, "rssi": -63}]}
            with patch.object(nuki, "load_token", return_value=TOKEN), \
                    patch.object(nuki, "request", return_value=inventory() if endpoint == "/list" else info) as request, \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(nuki.main(["--host", "192.0.2.10", "--nuki-id", str(ID), "--mode", mode, "--resource-macro", "USER10"]), 0)
            self.assertEqual(request.call_args.args[-1], endpoint)
        output = io.StringIO()
        with patch.object(nuki, "load_token", return_value=TOKEN), \
                patch.object(nuki, "request", side_effect=OSError(TOKEN)), \
                contextlib.redirect_stdout(output):
            self.assertEqual(nuki.main(["--host", "192.0.2.10", "--nuki-id", str(ID), "--mode", "health", "--resource-macro", "USER10"]), 2)
        self.assertNotIn(TOKEN, output.getvalue())


if __name__ == "__main__":
    unittest.main()

