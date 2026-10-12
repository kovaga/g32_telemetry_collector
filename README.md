# G32 Telemetry Collector

Passive collector for **Otto Wilde G32** grill telemetry. It decodes the status
frames the grill sends to the Otto Wilde cloud and publishes them as JSON to
**MQTT** (e.g. for openHAB / Home Assistant) and/or a local **HTTP** endpoint.

The grill keeps talking to the official cloud and app as usual. The collector
only receives a mirrored copy of the traffic from a MikroTik router and never
sends anything to the grill or the cloud.

```
G32 grill ──TCP:4501──► Otto Wilde cloud
                 │
         MikroTik router (sniff-tzsp mirror)
                 │ UDP:37009 (TZSP)
                 ▼
     g32_telemetry_collector.py
        ├─► stdout   (JSON or human-readable)
        ├─► MQTT     openhab/g32/status, openhab/g32/availability
        └─► HTTP     http://127.0.0.1:8765/g32
```

## Contents

- [Requirements](#requirements)
- [MikroTik setup](#mikrotik-setup)
- [Quick start](#quick-start)
- [Configuration](#configuration)
- [Running as a service](#running-as-a-service)
- [Deploying with Puppet](#deploying-with-puppet)
- [Output](#output)
- [openHAB example](#openhab-example)
- [Frame format](#frame-format)
- [Troubleshooting](#troubleshooting)
- [Limitations](#limitations)
- [Development](#development)

## Requirements

- Python 3.9+ (standard library only)
- [`paho-mqtt`](https://pypi.org/project/paho-mqtt/) 1.6 or newer when MQTT is
  enabled: `pip install -r requirements.txt` or `apt install python3-paho-mqtt`
- A MikroTik router that forwards the grill's traffic

## MikroTik setup

Mirror the grill's outgoing traffic to the host running the collector. Only the
grill → cloud direction is needed. This is the working rule of the reference
installation (grill `192.168.6.103`, collector host `192.168.6.15`); replace the
addresses with your own:

```
/ip firewall mangle
add action=sniff-tzsp chain=prerouting comment="G32 intercept forward to s5" \
    sniff-target=192.168.6.15 sniff-target-port=37009 src-address=192.168.6.103
```

- `chain=prerouting` sees the packets as they arrive from the grill, with the
  grill's own address as source.
- The rule mirrors all of the grill's traffic; the collector itself picks out
  the cloud connection (TCP port 4501, `--tcp-port`).
- `sniff-tzsp` only sends a copy; the grill's traffic is delivered as usual.
- `sniff-target-port` must match the collector's `port` (default 37009).

## Quick start

```sh
# 1. Check that decoding works (uses a built-in captured frame)
python3 g32_telemetry_collector.py --self-test --pretty

# 2. Create your configuration
cp config.example.ini config.ini
chmod 600 config.ini        # required: the file holds the MQTT password
$EDITOR config.ini

# 3. Run in the foreground
python3 g32_telemetry_collector.py --config config.ini --human
```

## Configuration

Settings can be given in the INI file (`--config FILE`) or on the command line;
command-line options override the file. `config.example.ini` contains every
setting with comments.

| INI section / key | Command-line option | Default | Meaning |
|---|---|---|---|
| `[listener] bind` | `--bind` | `0.0.0.0` | Local address for the TZSP listener |
| `[listener] port` | `--port` | `37009` | TZSP UDP port |
| `[grill] ip` | `--grill-ip` | any | Only accept traffic from this grill |
| `[grill] tcp_port` | `--tcp-port` | `4501` | Grill → cloud TCP port |
| `[grill] device_id` | `--device-id` | any | Only accept frames with this 4-byte device ID (hex) |
| `[grill] tare_weight_g` | `--tare-weight-g` | none | Empty bottle weight; adds an estimated gross weight |
| `[output] timezone` | `--timezone` | `Europe/Berlin` | Timezone of the local tank timestamp (verbose output) |
| `[output] human` | `--human` | `false` | Compact one-line console output |
| `[output] pretty` | `--pretty` | `false` | Indented JSON console output |
| `[output] rawframe` | `--rawframe` | `false` | Add the raw frame as hex |
| `[output] verbose` | `--verbose` | `false` | Add network metadata and undecoded bytes; log malformed packets and gaps |
| `[output] offline_after` | `--offline-after` | `60` | Seconds without a frame before "offline" is published |
| `[output] stats_interval` | `--stats-interval` | `0` (off) | Log packet/frame counters every N seconds |
| `[http] enabled` | `--http-enabled` | `false` | Enable the HTTP endpoint |
| `[http] bind` / `port` / `path` | `--http-bind` / `--http-port` / `--http-path` | `127.0.0.1` / `8765` / `/g32` | HTTP endpoint address |
| `[mqtt] enabled` | `--mqtt-enabled` | `false` | Enable MQTT publishing |
| `[mqtt] host` / `port` | `--mqtt-host` / `--mqtt-port` | none / `1883` | MQTT broker |
| `[mqtt] topic` | `--mqtt-topic` | `openhab/g32/status` | Status topic |
| `[mqtt] availability_topic` | `--mqtt-availability-topic` | `openhab/g32/availability` | Collector availability (last will); empty disables |
| `[mqtt] qos` | `--mqtt-qos` | `1` | MQTT QoS (0–2) |
| `[mqtt] retain` | `--mqtt-retain` | `false` | Retain the status message (recommended: `true`) |
| `[mqtt] client_id` | `--mqtt-client-id` | `g32_telemetry_collector` | MQTT client ID |
| `[mqtt] username` | `--mqtt-username` | none | MQTT username |
| `[mqtt] password` | — | none | MQTT password (config file only) |
| `[mqtt] password_env` | `--mqtt-password-env` | `G32_MQTT_PASSWORD` | Environment variable holding the password |
| `[mqtt] tls` | `--mqtt-tls` | `false` | TLS with the system CA store |
| — | `--self-test` | | Decode a built-in sample and exit |

Security notes:

- There is intentionally no command-line option for the MQTT password, because
  the command line is visible in `ps`. The `password` in the config file takes
  precedence over the environment variable.
- An ordinary config file must not be readable by group or others
  (`chmod 600`), otherwise the collector refuses to start. systemd credentials
  are exempt from this check.

Compatibility: `--mqtt-config` is a deprecated alias for `--config`. If
`--http-enabled` / `--mqtt-enabled` are not set, giving `--http-port` /
`--mqtt-host` on the command line enables HTTP / MQTT, as in older releases.

## Running as a service

`g32_telemetry_collector.service` runs the collector as an unprivileged,
sandboxed systemd service (`DynamicUser`, read-only system) and passes the
config as a systemd credential, so the file stays root-only on disk:

```sh
sudo install -D -m 0755 g32_telemetry_collector.py /opt/g32_telemetry_collector/g32_telemetry_collector.py
sudo install -D -m 0600 config.ini /etc/g32_telemetry_collector/config.ini
sudo cp g32_telemetry_collector.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now g32_telemetry_collector

journalctl -u g32_telemetry_collector -f      # follow the log
```

To update, install the new script the same way and run
`sudo systemctl restart g32_telemetry_collector`. On `systemctl stop` the
collector disconnects from MQTT cleanly, publishes `offline` on the
availability topic and logs its final counters.

## Deploying with Puppet

`puppet/` contains a Puppet class and config template that deploy the same
hardened service as the systemd unit above, managed by Puppet:

| Repository file | Location in the Puppet module `packages` |
|---|---|
| `puppet/g32_telemetry_collector.pp` | `manifests/g32_telemetry_collector.pp` (class `packages::g32_telemetry_collector`) |
| `puppet/g32_telemetry_collector.conf.epp` | `templates/g32_telemetry_collector/g32_telemetry_collector.conf.epp` |
| `g32_telemetry_collector.py` | `files/g32_telemetry_collector/g32_telemetry_collector.py` |

Requirements: `puppetlabs/stdlib` and `puppet/systemd` >= 8.3.0 (for
`LoadCredential` in `systemd::manage_unit`).

The class installs `python3-paho-mqtt`, copies the script to
`/opt/g32_telemetry_collector/`, renders the config to
`/opt/g32_telemetry_collector/g32_telemetry_collector.conf` (root, 0600, diff hidden in Puppet reports),
passes it to the service as a systemd credential and manages
`g32_telemetry_collector.service` (dynamic user, hardened, stdout discarded, stderr to the
journal). The service restarts when the script or the config changes.

Every parameter is a Hiera key `packages::g32_telemetry_collector::<parameter>`.
`mqtt_password` is required while MQTT is enabled; keep it encrypted (e.g.
with hiera-eyaml). Parameters and the config keys they set:

| Parameter | Default | Config key |
|---|---|---|
| `tzsp_bind`, `tzsp_port` | `0.0.0.0`, `37009` | `[listener] bind`, `port` |
| `grill_ip`, `grill_tcp_port` | `192.168.6.103`, `4501` | `[grill] ip`, `tcp_port` |
| `device_id` | `84e0422c` | `[grill] device_id` |
| `tare_weight_g` | not set | `[grill] tare_weight_g` (only written when set) |
| `timezone` | `UTC` | `[output] timezone` |
| `human_output`, `pretty_output`, `include_rawframe`, `verbose` | `false` | `[output] human`, `pretty`, `rawframe`, `verbose` |
| `offline_after` | `60` | `[output] offline_after` |
| `http_enabled`, `http_bind`, `http_port`, `http_path` | `false`, `127.0.0.1`, `8765`, `/g32` | `[http]` |
| `mqtt_enabled` | `true` | `[mqtt] enabled` |
| `mqtt_host`, `mqtt_port` | `192.168.9.12`, `1883` | `[mqtt] host`, `port` |
| `mqtt_topic` | `openhab/g32/status` | `[mqtt] topic` |
| `mqtt_qos`, `mqtt_retain`, `mqtt_tls` | `1`, `true`, `false` | `[mqtt] qos`, `retain`, `tls` |
| `mqtt_client_id` | `g32_telemetry_collector` | `[mqtt] client_id` |
| `mqtt_username`, `mqtt_password` | `mqttuser`, none | `[mqtt] username`, `password` |
| `install_dir` | `/opt/g32_telemetry_collector` | — |

Settings without a parameter keep the daemon's defaults, e.g. the availability topic `openhab/g32/availability` and `stats_interval = 0`.

```sh
journalctl -u g32_telemetry_collector -f      # follow the log
```

The repository's stand-alone unit file is an alternative to this class; use
one or the other, not both.

## Output

One JSON event is published per decoded frame (MQTT and HTTP use compact JSON
with sorted keys):

```json
{
  "received_at_utc": "2026-10-06T12:39:59.154610Z",
  "g32": {
    "device_id": "84e0422c",
    "status": "online",
    "temperatures_c": {
      "zone_1": 22.0, "zone_2": 21.0, "zone_3": 21.0, "zone_4": 21.0,
      "probe_1": null, "probe_2": null, "probe_3": null, "probe_4": null
    },
    "gas": {
      "weight_kg": 10.323,
      "capacity_kg": 11.0,
      "level_percent": 93,
      "calculated_level_percent": 93.85
    },
    "lid_open": false,
    "light_on": false,
    "hood_light_sensitivity_percent": 24,
    "probable_tank_installed_utc": "2026-08-06T17:00:17Z"
  }
}
```

Human-readable output (`--human`):

```
2026-10-06T12:39:59.154610Z id=84e0422c status=online zones=[22.0,21.0,21.0,21.0]C probes=[-,-,-,-]C gas=10.323kg/11.000kg level=93% lid=closed light=off hood_light_sensitivity=24% probable_tank_installed=2026-08-06T17:00:17Z
```

Field notes:

- A `null` probe temperature means no probe is connected.
- `gas.level_percent` is reported by the grill; `calculated_level_percent` is
  weight / capacity.
- With `tare_weight_g`, `gas` also contains `tare_weight_kg_configured_locally`
  and `estimated_gross_weight_kg` (bottle weight plus gas; not from the grill).
- `--verbose` adds `mirror_sender`, `inner_tcp`, the raw and local tank
  timestamp and the undecoded bytes (`unknown_fields`); `--rawframe` adds
  `raw_frame_hex`.

### Offline handling

If no frame arrives for `offline_after` seconds (default 60), an offline event
is published and repeated at the same interval. It keeps only the values that
stay valid while the grill is off:

```json
{
  "g32": {
    "device_id": "84e0422c",
    "status": "offline",
    "gas": { "weight_kg": 10.323, "capacity_kg": 11.0, "level_percent": 93, "calculated_level_percent": 93.85 },
    "probable_tank_installed_utc": "2026-08-06T17:00:17Z"
  },
  "received_at_utc": "2026-10-06T18:42:10.004211Z",
  "offline_since_utc": "2026-10-06T18:43:10.120531Z",
  "status_published_at_utc": "2026-10-06T18:43:10.120544Z"
}
```

- `received_at_utc` is the last time a frame was received, i.e. when the grill
  was last on. Temperatures, lid and light are left out because stale values
  mislead.
- After a collector restart the last event is read back once from the retained
  MQTT status message, so the gas values and `offline_since_utc` survive
  restarts while the grill is off.
- If nothing is known yet, the offline event is printed but not sent to MQTT,
  so existing retained data is never overwritten.

### MQTT topics

| Topic (default) | Retained | Content |
|---|---|---|
| `openhab/g32/status` | if `retain = true` | Status JSON as above (online or offline) |
| `openhab/g32/availability` | yes | `online` while the collector is connected; `offline` on clean shutdown, or set by the broker (last will) if the collector crashes or loses its connection |

`g32.status` tells whether the **grill** is sending; the availability topic
tells whether the **collector** is running.

### HTTP endpoint

`GET http://<bind>:<port><path>` returns the latest event with status 200,
`503 {"error":"no_g32_frame_received"}` before the first frame, and
`404 {"error":"not_found"}` for other paths.

### Counters

On shutdown, and every `stats_interval` seconds if enabled, the collector logs:
`tzsp` (datagrams received), `inner_tcp`, `matching_tcp` (segments from the
grill to the cloud port), `frames` (decoded), `offline_events`, `gaps` (missing
TCP data in the mirror) and `malformed` (unparseable datagrams).

## openHAB example

With the [MQTT binding](https://www.openhab.org/addons/bindings/mqtt/) and the
JSONPath transformation installed (replace `mybroker` with your broker thing):

```
Thing mqtt:topic:g32 "G32 grill" (mqtt:broker:mybroker) {
    Channels:
        Type string : status    "Status"        [ stateTopic="openhab/g32/status", transformationPattern="JSONPATH:$.g32.status" ]
        Type number : gasLevel  "Gas level"     [ stateTopic="openhab/g32/status", transformationPattern="JSONPATH:$.g32.gas.level_percent" ]
        Type number : gasWeight "Gas remaining" [ stateTopic="openhab/g32/status", transformationPattern="JSONPATH:$.g32.gas.weight_kg" ]
        Type number : zone1     "Zone 1"        [ stateTopic="openhab/g32/status", transformationPattern="JSONPATH:$.g32.temperatures_c.zone_1" ]
        Type string : collector "Collector"     [ stateTopic="openhab/g32/availability" ]
}
```

## Frame format

The grill sends a fixed 50-byte frame as TCP payload to port 4501:

| Bytes   | Field                                     | Status            |
|---------|-------------------------------------------|-------------------|
| 0–1     | Magic `a3 3a`                             | confirmed         |
| 2–5     | Device ID                                 | confirmed         |
| 6–13    | Zone 1–4 temperatures (2 bytes each)      | confirmed         |
| 14–21   | Probe 1–4 temperatures (`96 00` = none)   | confirmed         |
| 22–23   | Gas weight, grams (big-endian)            | confirmed         |
| 24      | Lid open (1 = open)                       | confirmed         |
| 25      | Light on (1 = on)                         | confirmed         |
| 31      | Gas level, percent                        | confirmed         |
| 33      | Hood light sensitivity, percent (steps of 4) | confirmed via app |
| 37–40   | Tank installed, Unix time (little-endian) | probable          |
| 45–46   | Tank capacity, grams (big-endian)         | confirmed         |
| 26–30, 32, 34–36, 41–44, 47–49 | Unknown            | under analysis    |

Temperature encoding: `first_byte * 10 + second_byte / 10` °C. Byte 49 is not
a simple sum or XOR checksum.

Frames are found in the TCP stream by the `a3 3a` marker; frames split across
TCP segments are reassembled, and retransmissions are ignored.

## Troubleshooting

| Symptom | Check |
|---|---|
| No output at all | Is the mangle rule counting packets (`/ip firewall mangle print stats`)? Does the host firewall allow UDP 37009? Use `--stats-interval 10` to see whether TZSP datagrams arrive (`tzsp=`). |
| `tzsp` counts up but `frames=0` | Grill IP or port filter wrong (`--grill-ip`, `--tcp-port`), or a `--device-id` that does not match. To see what is mirrored, capture it with `tcpdump -n -i any udp port 37009 -w g32.pcap` and open it in Wireshark (Analyze → Decode As → UDP port 37009 → TZSP). |
| Collector refuses to start: "must not be readable by group or others" | `chmod 600 config.ini` |
| "MQTT requires paho-mqtt" | `pip install -r requirements.txt` or `apt install python3-paho-mqtt` |
| MQTT values stay old in openHAB | Check `openhab/g32/availability`: `offline` means the collector is down. |

## Limitations

- Several frame bytes are not decoded yet (see the table); the tank
  installation date is a probable interpretation.
- Only the G32's status frames are decoded; the collector cannot control the
  grill.
- Old TCP connection state is cleaned up after 10 minutes of inactivity, but
  only while no mirrored packets arrive for a second; with continuous mirror
  traffic this cleanup is delayed. Only grill connections are tracked, so the
  impact is negligible.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
python3 -O g32_telemetry_collector.py --self-test   # also works with -O
```

The tests cover TZSP/TCP parsing, stream reassembly (gaps, retransmissions,
sequence wraparound), frame decoding, offline events, configuration, the HTTP
endpoint, the MQTT publisher (using a fake paho client, no broker needed) and
the running daemon end to end, including shutdown on SIGTERM.

Project files:

| File | Purpose |
|---|---|
| `g32_telemetry_collector.py` | The collector (single file, no dependencies besides paho-mqtt) |
| `config.example.ini` | Commented example configuration |
| `g32_telemetry_collector.service` | systemd unit |
| `requirements.txt` / `requirements-dev.txt` | Runtime / test dependencies |
| `puppet/` | Puppet class and config template |
| `tests/` | pytest suite |
