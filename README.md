# check-nuki

Read-only Nagios plugin for monitoring Nuki Smart Locks via a local Nuki Bridge API.

Checks lock battery, health, Bridge cloud connection, and Bluetooth scan signal strength. An unlocked or open lock is **not** treated as a monitoring failure.

## Requirements

- Linux with Python 3.10+
- PyNaCl (on Debian/Ubuntu: `python3-nacl`)
- A reachable Nuki Bridge with its local HTTP API enabled and an API token
- Nagios Core or a compatible monitoring system

Install the runtime dependency on Debian/Ubuntu:

```sh
sudo apt install python3 python3-nacl
```

The HTTP client uses Python's standard library; no `requests` package is needed.

## Installation

Install the plugin in your Nagios plugin directory (adjust the path for your system):

```sh
sudo install -m 0755 check_nuki.py /usr/local/lib/nagios/plugins/check_nuki.py
```

Run `python3 check_nuki.py --help` for all supported options.

## Authentication and permissions

Create a protected Nagios-style resource file containing a **raw** Nuki Bridge API token:

```text
$USER10$=REPLACE_WITH_YOUR_NUKI_API_TOKEN
```

The resource-file path defaults to `/etc/nagios4/resource.cfg`, but **no credential source is selected by default**. You must explicitly specify either `--resource-macro USER10` (or another numbered `USER` macro) or `--token-file /path/to/token`. Use `--resource-file /path/to/file` to override the resource path when using `--resource-macro`. The selected macro must appear exactly once.

Alternatively, `--token-file /path/to/token` reads a file containing **only the raw token**, without a Nagios resource macro. The `--token-file` and `--resource-macro` options are mutually exclusive; `--resource-file` is only relevant in resource-macro mode.

Both file types must be **root-owned and mode 0640 or stricter**, readable by the monitoring account, and inaccessible to other users. For a group-readable file, use an appropriate restricted group; never place tokens in Git or command-line arguments.

Example (choose one):

```sh
python3 check_nuki.py --host 192.0.2.10 --nuki-id 12345678 --mode battery --resource-macro USER15
python3 check_nuki.py --host 192.0.2.10 --nuki-id 12345678 --mode battery --token-file /etc/nagios4/private/nuki/token
```

Requests authenticate with an encrypted token using PyNaCl. Ensure that the Bridge and monitoring host have accurate clocks; authentication has a limited time window.

**Network security:** The Bridge API uses plain HTTP, not TLS. Encrypted token authentication protects the credential but **does not encrypt API responses or provide transport integrity**. Restrict inbound Bridge API access to trusted monitoring hosts using network segmentation/firewall rules. Do not expose port 8080 to the internet or untrusted networks. Monitoring results may include lock status; treat them as sensitive operational information.

## Usage

For illustration, replace the documentation IP and Nuki ID with actual values:

```sh
python3 check_nuki.py --host 192.0.2.10 --port 8080 --nuki-id 12345678 --mode battery --resource-macro USER10
python3 check_nuki.py --host 192.0.2.10 --port 8080 --nuki-id 12345678 --mode health --resource-macro USER10
python3 check_nuki.py --host 192.0.2.10 --port 8080 --nuki-id 12345678 --mode cloud --resource-macro USER10
python3 check_nuki.py --host 192.0.2.10 --port 8080 --nuki-id 12345678 --mode bluetooth --resource-macro USER10
```

| Mode | Checks |
| --- | --- |
| `battery` | Lock battery status and available battery metrics |
| `health` | Lock state and operational health |
| `cloud` | Bridge cloud connectivity |
| `bluetooth` | Bridge-reported scan RSSI for the selected lock |

The plugin returns standard Nagios exit codes (0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN) and includes performance data where applicable. The host must be a literal IPv4 or IPv6 address.

### Example Nagios configuration

This example assumes the installed script is at `/usr/local/lib/nagios/plugins/check_nuki.py` and the Bridge IP is configured as the host address:

```text
define command {
    command_name    check_nuki
    command_line    /usr/local/lib/nagios/plugins/check_nuki.py --host $HOSTADDRESS$ --port 8080 --nuki-id $ARG1$ --mode $ARG2$
}

define service {
    use                    generic-service
    host_name              nuki-bridge
    service_description    Nuki Battery
    check_command          check_nuki!12345678!battery
}
```

This requires an existing `nuki-bridge` host definition and `generic-service` template. Adjust paths and arguments to your Nagios installation.

## Concurrent checks

Requests to the same Bridge are serialized using private lock files. The default lock directory is `/var/lib/nagios4`; change it with `--lock-directory`.

The monitoring account must be able to create private lock files in that directory. Use a trusted directory, not a world-writable location, and configure **all** checks for a given Bridge to use the same directory. Lock files are intentionally persistent: do not remove them while checks may be running.

The plugin uses a 15-second execution deadline and retries temporary Bridge-busy responses. Only read-only inventory API endpoints are used.

## Tests

```sh
python3 -m unittest discover -s tests -v
```

The test suite covers authentication, failures, device selection, and parallel requests. GitHub Actions runs the tests on pushes and pull requests.

## License

GNU General Public License version 3 (GPL-3.0-only). See [LICENSE](LICENSE).

## Development and releases

Development happens in the private `check-nuki-dev` repository. The public [check-nuki](https://github.com/sjcjonker/check-nuki) repository contains curated release snapshots without development history.
