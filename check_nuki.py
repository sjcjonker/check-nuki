#!/usr/bin/env python3
"""Read-only Nuki Bridge checks using encrypted token authentication."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import datetime as dt
import fcntl
import hashlib
import http.client
import ipaddress
import json
import os
import re
import secrets
import signal
import stat
import time
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit

LIMIT = 1024 * 1024
LOCK_DIRECTORY = Path("/var/lib/nagios4")
STATES = {0: "uncalibrated", 1: "locked", 2: "unlocking", 3: "unlocked",
          4: "locking", 5: "unlatched", 6: "unlocked (lock 'n' go)",
          7: "unlatching", 254: "motor blocked", 255: "undefined"}


class CheckError(Exception):
    def __init__(self, message, code=3):
        super().__init__(message)
        self.code = code


class BridgeBusy(CheckError):
    pass


@contextmanager
def bridge_lock(host, port, directory=None):
    """Serialize all plugin processes for one bridge; never unlink a lock file."""
    directory = LOCK_DIRECTORY if directory is None else Path(directory)
    path = directory / ("check-nuki-%s-%d.lock" % (host, port))
    try:
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    except OSError:
        raise CheckError("cannot open bridge lock; check Nagios state directory permissions")
    try:
        metadata = os.fstat(fd)
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid() or
                metadata.st_mode & 0o077):
            raise CheckError("bridge lock must be a private file owned by the check user")
        until = time.monotonic() + 8
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= until:
                    raise CheckError("bridge request queue busy for more than 8 seconds")
                time.sleep(0.05)
            except OSError:
                raise CheckError("cannot acquire bridge request lock")
        try:
            yield
        finally:
            # Keep a short gap after completion before the next process sends.
            time.sleep(0.25)
    finally:
        os.close(fd)


def validate_token(value):
    if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,128}", value):
        raise CheckError("credential file must contain a valid Nuki API token")
    return value


def parse_token(text, host, port, macro="USER10"):
    if not re.fullmatch(r"USER[1-9][0-9]*", macro):
        raise CheckError("resource macro must be USER followed by a positive number")
    values = re.findall(r"^\s*\$" + re.escape(macro) + r"\$\s*=([^\r\n]*)$", text, re.M)
    if len(values) != 1:
        raise CheckError("resource file must define selected macro exactly once")
    value = values[0].strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if value.startswith(("http://", "https://")):
        # Migration compatibility only: never send the legacy plaintext URL.
        try:
            url = urlsplit(value)
            query = parse_qs(url.query, strict_parsing=True)
            if (url.scheme != "http" or url.hostname != host or
                    url.port != port or url.path != "/list" or
                    url.username is not None or url.password is not None or
                    url.fragment or set(query) != {"token"} or
                    len(query["token"]) != 1):
                raise ValueError()
            value = query["token"][0]
        except (ValueError, KeyError):
            raise CheckError("legacy token URL does not match the configured bridge")
    return validate_token(value)


def load_token(filename, host, port, macro="USER10", token_file=False):
    try:
        fd = os.open(filename, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, encoding="utf-8") as source:
            metadata = os.fstat(source.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0 or
                    metadata.st_mode & 0o037):
                raise CheckError("credential file must be root-owned, mode 0640 or stricter")
            text = source.read(LIMIT + 1)
        if len(text) > LIMIT:
            raise CheckError("credential file exceeds size limit")
        if token_file:
            return validate_token(text.strip())
        return parse_token(text, host, port, macro)
    except (OSError, UnicodeError):
        raise CheckError("private credential file missing, unreadable or unsafe")


def encrypted_query(token):
    try:
        from nacl.secret import SecretBox
    except ImportError:
        raise CheckError("PyNaCl is required; install Debian python3-nacl")
    timestamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    nonce = secrets.token_bytes(24)
    message = f"{timestamp},{secrets.randbelow(65535) + 1}".encode()
    box = SecretBox(hashlib.sha256(token.encode()).digest())
    return urlencode({"ctoken": box.encrypt(message, nonce).ciphertext.hex(),
                      "nonce": nonce.hex()})


def request_once(host, port, token, endpoint):
    if endpoint not in ("/list", "/info"):
        raise CheckError("only read-only inventory endpoints are permitted")
    query = encrypted_query(token)
    connection = http.client.HTTPConnection(host, port, timeout=8)
    try:
        connection.request("GET", endpoint + "?" + query,
                           headers={"Accept": "application/json", "Connection": "close"})
        response = connection.getresponse()
        if response.status in (401, 403):
            raise CheckError("API authentication rejected; verify token and clocks (60s window)")
        if response.status == 503:
            raise BridgeBusy("bridge busy after bounded retries")
        if response.status != 200:
            raise CheckError("API returned HTTP %d" % response.status)
        raw = response.read(LIMIT + 1)
        if len(raw) > LIMIT:
            raise CheckError("API response exceeds 1 MiB")
        try:
            return json.loads(raw)
        except (ValueError, UnicodeError):
            raise CheckError("API returned invalid JSON")
    finally:
        connection.close()


def request(host, port, token, endpoint, *, lock_directory=None):
    if endpoint not in ("/list", "/info"):
        raise CheckError("only read-only inventory endpoints are permitted")
    with bridge_lock(host, port, lock_directory):
        for attempt in range(3):
            try:
                # Generate a fresh encrypted token/nonce for every retry.
                return request_once(host, port, token, endpoint)
            except BridgeBusy:
                if attempt == 2:
                    raise
                time.sleep(0.5 * (attempt + 1))


def selected_state(payload, nuki_id):
    if not isinstance(payload, list):
        raise CheckError("invalid Nuki device inventory")
    identities = set()
    chosen = None
    for item in payload:
        if (not isinstance(item, dict) or type(item.get("nukiId")) is not int or
                type(item.get("deviceType")) is not int):
            raise CheckError("invalid Nuki device identity")
        identity = (item["nukiId"], item["deviceType"])
        if identity in identities:
            raise CheckError("duplicate Nuki device identity")
        identities.add(identity)
        if item["nukiId"] == nuki_id:
            if chosen is not None:
                raise CheckError("ambiguous Nuki device ID")
            chosen = item
    if chosen is None:
        raise CheckError("expected smart lock missing from paired inventory", 2)
    if chosen["deviceType"] not in (0, 3, 4):
        raise CheckError("expected device is not a supported smart lock")
    state = chosen.get("lastKnownState")
    if not isinstance(state, dict):
        raise CheckError("cached lock state missing or invalid")
    return state


def battery(state):
    critical = state.get("batteryCritical")
    if type(critical) is not bool:
        raise CheckError("battery critical flag missing or invalid")
    charge = state.get("batteryChargeState")
    valid_charge = type(charge) is int and 0 <= charge <= 100
    if critical:
        return 2, "lock battery critical" + (f" ({charge}%) | battery_pct={charge}%;;;0;100" if valid_charge else "")
    if charge is not None and not valid_charge:
        raise CheckError("battery charge percentage invalid")
    if charge is None:
        return 0, "lock battery not critical; percentage unavailable"
    return 0, f"lock battery {charge}%; not critical | battery_pct={charge}%;;;0;100"


def health(state):
    value = state.get("state")
    if type(value) is not int or value not in STATES:
        raise CheckError("lock state missing or unrecognized")
    if value in (0, 254):
        return 2, "lock fault: " + STATES[value] + " (cached)"
    if value == 255:
        raise CheckError("lock state undefined (cached)")
    if type(state.get("mode")) is not int or state["mode"] != 2:
        raise CheckError("lock is not in normal door mode")
    # Neither unlocked nor an open door is an equipment fault.
    return 0, "lock reports normal operation; " + STATES[value] + " (cached)"


def cloud(info):
    if not isinstance(info, dict) or type(info.get("serverConnected")) is not bool:
        raise CheckError("cloud connection status missing or invalid")
    return (0, "bridge connected to Nuki cloud") if info["serverConnected"] else (
        1, "bridge disconnected from Nuki cloud; local API responds")


def bluetooth(info, nuki_id):
    if not isinstance(info, dict) or not isinstance(info.get("scanResults"), list):
        raise CheckError("Bluetooth scan results missing or invalid")
    matches = []
    for item in info["scanResults"]:
        if not isinstance(item, dict):
            raise CheckError("invalid Bluetooth scan entry")
        if type(item.get("nukiId")) is int and item["nukiId"] == nuki_id:
            matches.append(item)
    if len(matches) != 1 or matches[0].get("paired") is not True:
        raise CheckError("expected paired lock absent or ambiguous in bridge scan")
    value = matches[0].get("rssi")
    if type(value) is not int or not -127 <= value <= 0:
        raise CheckError("Bluetooth RSSI missing or invalid")
    return 0, f"lock Bluetooth signal {value} dBm (bridge scan) | rssi_dbm={value};;;-127;0"


def deadline(*_):
    raise CheckError("Nuki check exceeded 15 seconds", 2)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--resource-file", default="/etc/nagios4/resource.cfg")
    credentials = parser.add_mutually_exclusive_group(required=True)
    credentials.add_argument("--resource-macro",
                             help="Nagios resource macro name, e.g. USER10")
    credentials.add_argument("--token-file",
                             help="protected file containing only the raw API token")
    parser.add_argument("--lock-directory", default=None,
                        help="shared writable lock directory (default: /var/lib/nagios4)")
    parser.add_argument("--nuki-id", type=int, required=True)
    parser.add_argument("--mode", choices=("battery", "health", "cloud", "bluetooth"), required=True)
    args = parser.parse_args(argv)
    signal.signal(signal.SIGALRM, deadline)
    signal.alarm(15)
    try:
        try:
            host = str(ipaddress.ip_address(args.host))
        except ValueError:
            raise CheckError("host must be a literal IP address")
        if not 1 <= args.port <= 65535 or not 0 <= args.nuki_id <= 0xffffffff:
            raise CheckError("port or Nuki ID outside valid range")
        filename = args.token_file or args.resource_file
        token = load_token(filename, host, args.port, args.resource_macro, bool(args.token_file))
        endpoint = "/list" if args.mode in ("battery", "health") else "/info"
        payload = request(host, args.port, token, endpoint, lock_directory=args.lock_directory)
        if args.mode in ("battery", "health"):
            state = selected_state(payload, args.nuki_id)
            code, text = battery(state) if args.mode == "battery" else health(state)
        else:
            code, text = cloud(payload) if args.mode == "cloud" else bluetooth(payload, args.nuki_id)
        print(("OK", "WARNING", "CRITICAL", "UNKNOWN")[code] + " - " + text)
        return code
    except CheckError as exc:
        print(("OK", "WARNING", "CRITICAL", "UNKNOWN")[exc.code] + " - " + str(exc))
        return exc.code
    except (OSError, http.client.HTTPException):
        print("CRITICAL - Nuki bridge connection failed; no credentials logged")
        return 2
    except (ValueError, TypeError, KeyError, RecursionError):
        print("UNKNOWN - invalid Nuki configuration or API response")
        return 3
    finally:
        signal.alarm(0)


if __name__ == "__main__":
    raise SystemExit(main())
