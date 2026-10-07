# G32 Telemetry Collector

Passive collector for **Otto Wilde G32** grill telemetry. It decodes the status
frames the grill sends to the Otto Wilde cloud and publishes them as JSON to
**MQTT** (e.g. for openHAB / Home Assistant) and/or a local **HTTP** endpoint.

The grill keeps talking to the official cloud and app as usual. The collector
only receives a mirrored copy of the traffic from a MikroTik router.

```
G32 grill ──TCP:4501──► Otto Wilde cloud
                 │
         MikroTik router (sniff-tzsp mirror)
                 │ UDP:37009 (TZSP)
                 ▼
     g32_telemetry_collector.py
        ├─► stdout   (JSON or human-readable)
        ├─► MQTT     openhab/g32/status
        └─► HTTP     http://127.0.0.1:8765/g32
```

## Requirements

- Python 3.9+ (standard library only)
- [`paho-mqtt`](https://pypi.org/project/paho-mqtt/) when MQTT is enabled:
  `pip install -r requirements.txt` or `apt install python3-paho-mqtt`
- A MikroTik router that forwards the grill's traffic

## MikroTik setup

Mirror the grill's cloud traffic to the host running the collector
(replace the addresses with your own):

```
/ip firewall mangle add chain=forward src-address=192.168.6.117 protocol=tcp dst-port=4501 \
    action=sniff-tzsp sniff-target=<collector-ip> sniff-target-port=37009 \
    comment="G32 telemetry -> collector"
```

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

All options are listed with `python3 g32_telemetry_collector.py --help`.
Command-line options override the config file. For security there is no
command-line option for the MQTT password. Set it in the config file or
through the environment variable named by `password_env`.

## Running as a service

`g32-telemetry-collector.service` runs the collector as an unprivileged,
sandboxed systemd service and passes the config as a systemd credential.
Installation steps are in the comment at the top of the unit file.

```sh
journalctl -u g32-telemetry-collector -f
```

## Output

One JSON event is published per decoded frame:

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

- A `null` probe temperature means no probe is connected.
- If no frame arrives for `offline_after` seconds (default 60), the last event
  is republished with `"status": "offline"` plus `offline_since_utc`, and
  repeated at the same interval.
- The collector itself publishes a retained `online` / `offline` to
  `availability_topic` (default `openhab/g32/availability`). The broker sets
  `offline` automatically via MQTT last will if the collector crashes or loses
  its connection, so stale grill data can be recognised. `g32.status` says
  whether the *grill* is sending; the availability topic says whether the
  *collector* is running.
- `--verbose` adds network metadata and the undecoded bytes; `--rawframe` adds
  the raw frame as hex.

## Frame format (50 bytes, TCP payload to port 4501)

| Bytes   | Field                                   | Status            |
|---------|-----------------------------------------|-------------------|
| 0–1     | Magic `a3 3a`                           | confirmed         |
| 2–5     | Device ID                               | confirmed         |
| 6–13    | Zone 1–4 temperatures (2 bytes each)    | confirmed         |
| 14–21   | Probe 1–4 temperatures (`96 00` = none) | confirmed         |
| 22–23   | Gas weight, grams (big-endian)          | confirmed         |
| 24      | Lid open (1 = open)                     | confirmed         |
| 25      | Light on (1 = on)                       | confirmed         |
| 31      | Gas level, percent                      | confirmed         |
| 33      | Hood light sensitivity, percent         | confirmed via app |
| 37–40   | Tank installed, Unix time (little-endian)| probable         |
| 45–46   | Tank capacity, grams (big-endian)       | confirmed         |
| 26–30, 32, 34–36, 41–44, 47–49 | Unknown          | under analysis    |

Temperature encoding: `first_byte * 10 + second_byte / 10` °C.

## Development

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt
.venv/bin/python -m pytest
```

The tests cover TZSP/TCP parsing, stream reassembly, frame decoding,
configuration, the HTTP endpoint, the MQTT publisher (using a fake paho
client, no broker needed) and the running daemon end to end.
