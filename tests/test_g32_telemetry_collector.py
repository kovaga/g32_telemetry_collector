"""Tests for g32_telemetry_collector.py. Run with: python3 -m pytest"""

from __future__ import annotations

import json
import os
import signal
import socket
import struct
import subprocess
import sys
import time
import types
import urllib.error
import urllib.request
from argparse import Namespace
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

import g32_telemetry_collector as g32

PROJECT_DIR = Path(__file__).resolve().parents[1]
SCRIPT = PROJECT_DIR / "g32_telemetry_collector.py"

# Real frame captured from the grill (same sample as --self-test).
FRAME = bytes.fromhex(
    "a33a84e0422c0214020a020a020a9600960096009600285300000d010405bb"
    "5d0118010001a1bd746a000000002af80001c3"
)
DEVICE_ID = bytes.fromhex("84e0422c")
UTC = ZoneInfo("UTC")


# --------------------------------------------------------------------------
# Packet builders
# --------------------------------------------------------------------------

def with_bytes(frame: bytes, offset: int, data: bytes) -> bytes:
    return frame[:offset] + data + frame[offset + len(data) :]


def build_ethernet(
    payload: bytes,
    *,
    seq: int = 1000,
    flags: int = 0x18,
    src: str = "192.168.6.117",
    dst: str = "3.120.177.98",
    sport: int = 50000,
    dport: int = 4501,
    vlan: bool = False,
    ip_proto: int = socket.IPPROTO_TCP,
    fragment: int = 0,
    ethertype: int = 0x0800,
) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 65535, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(tcp), 0, fragment, 64, ip_proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    ) + tcp
    ethernet = b"\x00" * 12
    if vlan:
        ethernet += struct.pack("!HH", 0x8100, 6)
    return ethernet + struct.pack("!H", ethertype) + ip


def build_tzsp(ethernet: bytes, tags: bytes = b"") -> bytes:
    # version 1, type 0 (received), encapsulation 1 (Ethernet), tags, end tag
    return b"\x01\x00\x00\x01" + tags + b"\x01" + ethernet


def segment(seq: int, payload: bytes, flags: int = 0) -> g32.TCPPacket:
    return g32.TCPPacket("192.168.6.117", "3.120.177.98", 50000, 4501, seq, flags, payload)


def decode(frame: bytes = FRAME, **overrides) -> dict:
    options = dict(tare_weight_g=None, local_timezone=UTC, include_raw=False, include_unknown=False)
    options.update(overrides)
    return g32.decode_g32_frame(frame, **options)


# --------------------------------------------------------------------------
# TZSP
# --------------------------------------------------------------------------

def test_parse_tzsp_returns_encapsulated_ethernet() -> None:
    ethernet = build_ethernet(FRAME)
    assert g32.parse_tzsp(build_tzsp(ethernet)) == ethernet


def test_parse_tzsp_skips_padding_and_option_tags() -> None:
    ethernet = build_ethernet(FRAME)
    tags = b"\x00" + b"\x0a\x02\xab\xcd"  # padding, then tag 10 with 2 bytes
    assert g32.parse_tzsp(build_tzsp(ethernet, tags)) == ethernet


@pytest.mark.parametrize(
    "datagram",
    [
        pytest.param(b"\x01\x00\x00", id="too-short"),
        pytest.param(b"\x02\x00\x00\x01\x01" + b"\x00" * 14, id="wrong-version"),
        pytest.param(b"\x01\x05\x00\x01\x01" + b"\x00" * 14, id="no-captured-frame"),
        pytest.param(b"\x01\x00\x00\x12\x01" + b"\x00" * 14, id="not-ethernet"),
        pytest.param(b"\x01\x00\x00\x01\x0a\x02\xab\xcd", id="missing-end-tag"),
        pytest.param(b"\x01\x00\x00\x01\x0a\x09\xab", id="tag-overflows"),
        pytest.param(b"\x01\x00\x00\x01\x01" + b"\x00" * 5, id="truncated-ethernet"),
    ],
)
def test_parse_tzsp_rejects_malformed(datagram: bytes) -> None:
    with pytest.raises(g32.PacketError):
        g32.parse_tzsp(datagram)


# --------------------------------------------------------------------------
# Ethernet / IPv4 / TCP
# --------------------------------------------------------------------------

def test_parse_inner_tcp_extracts_fields() -> None:
    packet = g32.parse_inner_tcp(build_ethernet(FRAME, seq=1234, sport=64605))
    assert packet == g32.TCPPacket("192.168.6.117", "3.120.177.98", 64605, 4501, 1234, 0x18, FRAME)


def test_parse_inner_tcp_handles_vlan_tag() -> None:
    packet = g32.parse_inner_tcp(build_ethernet(FRAME, vlan=True))
    assert packet is not None and packet.payload == FRAME


@pytest.mark.parametrize(
    "ethernet",
    [
        pytest.param(build_ethernet(FRAME, ethertype=0x0806), id="arp"),
        pytest.param(build_ethernet(FRAME, ip_proto=socket.IPPROTO_UDP), id="udp"),
        pytest.param(build_ethernet(FRAME, fragment=0x2000), id="ip-fragment"),
    ],
)
def test_parse_inner_tcp_ignores_other_traffic(ethernet: bytes) -> None:
    assert g32.parse_inner_tcp(ethernet) is None


def test_parse_inner_tcp_rejects_truncated_packet() -> None:
    with pytest.raises(g32.PacketError):
        g32.parse_inner_tcp(build_ethernet(FRAME)[:-10])


# --------------------------------------------------------------------------
# TCP stream reassembly and frame extraction
# --------------------------------------------------------------------------

def test_stream_reassembles_split_frame() -> None:
    stream = g32.TCPStream()
    stream.append(segment(1000, FRAME[:17]))
    assert g32.pull_g32_frames(stream.buffer) == []
    stream.append(segment(1017, FRAME[17:]))
    assert g32.pull_g32_frames(stream.buffer) == [FRAME]


def test_stream_ignores_retransmission() -> None:
    stream = g32.TCPStream()
    stream.append(segment(1000, FRAME))
    assert g32.pull_g32_frames(stream.buffer) == [FRAME]
    stream.append(segment(1000, FRAME))
    assert g32.pull_g32_frames(stream.buffer) == []


def test_stream_trims_partial_overlap() -> None:
    stream = g32.TCPStream()
    stream.append(segment(1000, FRAME[:30]))
    stream.append(segment(1020, FRAME[20:]))  # first 10 bytes are a retransmission
    assert g32.pull_g32_frames(stream.buffer) == [FRAME]


def test_stream_resynchronises_after_capture_gap() -> None:
    stream = g32.TCPStream()
    stream.append(segment(1000, FRAME[:20]))
    stream.append(segment(5000, FRAME))
    assert stream.gaps == 1
    assert g32.pull_g32_frames(stream.buffer) == [FRAME]


def test_stream_handles_sequence_wraparound() -> None:
    stream = g32.TCPStream()
    start = 0xFFFFFFFF - 9
    stream.append(segment(start, FRAME[:20]))
    stream.append(segment((start + 20) & 0xFFFFFFFF, FRAME[20:]))
    assert stream.gaps == 0
    assert g32.pull_g32_frames(stream.buffer) == [FRAME]


def test_stream_syn_sets_initial_sequence() -> None:
    stream = g32.TCPStream()
    stream.append(segment(999, b"", flags=g32.TCP_SYN))
    stream.append(segment(1000, FRAME))
    assert stream.gaps == 0
    assert g32.pull_g32_frames(stream.buffer) == [FRAME]


def test_pull_frames_skips_leading_garbage_and_reads_consecutive_frames() -> None:
    buffer = bytearray(b"\x00\x11garbage" + FRAME + FRAME + FRAME[:10])
    assert g32.pull_g32_frames(buffer) == [FRAME, FRAME]
    assert bytes(buffer) == FRAME[:10]


def test_pull_frames_keeps_possible_first_magic_byte() -> None:
    buffer = bytearray(b"noise\xa3")
    assert g32.pull_g32_frames(buffer) == []
    assert bytes(buffer) == b"\xa3"


def test_pull_frames_device_filter_skips_other_grill() -> None:
    other = with_bytes(FRAME, 2, bytes.fromhex("01020304"))
    buffer = bytearray(other + FRAME)
    assert g32.pull_g32_frames(buffer, DEVICE_ID) == [FRAME]


# --------------------------------------------------------------------------
# Frame decoding
# --------------------------------------------------------------------------

def test_decode_sample_frame() -> None:
    decoded = decode()
    assert decoded["device_id"] == "84e0422c"
    assert decoded["status"] == "online"
    assert decoded["temperatures_c"] == {
        "zone_1": 22.0, "zone_2": 21.0, "zone_3": 21.0, "zone_4": 21.0,
        "probe_1": None, "probe_2": None, "probe_3": None, "probe_4": None,
    }
    assert decoded["gas"] == {
        "weight_kg": 10.323,
        "level_percent": 93,
        "calculated_level_percent": 93.85,
        "capacity_kg": 11.0,
    }
    assert decoded["lid_open"] is False
    assert decoded["light_on"] is False
    assert decoded["hood_light_sensitivity_percent"] == 24
    assert decoded["probable_tank_installed_utc"] == "2026-08-06T17:00:17Z"
    assert "unknown_fields" not in decoded
    assert "raw_frame_hex" not in decoded


def test_decode_optional_fields() -> None:
    decoded = decode(include_raw=True, include_unknown=True, tare_weight_g=9000)
    assert decoded["raw_frame_hex"] == FRAME.hex()
    assert decoded["unknown_fields"]["byte_49_hex"] == "c3"
    assert decoded["probable_tank_installed_timestamp_raw"] == 1786035617
    assert decoded["gas"]["estimated_gross_weight_kg"] == 19.323


def test_decode_probe_lid_and_light() -> None:
    frame = with_bytes(FRAME, 14, bytes([7, 50]))  # probe 1 = 7*10 + 50/10
    frame = with_bytes(frame, 24, b"\x01\x01")
    decoded = decode(frame)
    assert decoded["temperatures_c"]["probe_1"] == 75.0
    assert decoded["lid_open"] is True
    assert decoded["light_on"] is True


def test_decode_implausible_timestamp_and_zero_capacity() -> None:
    frame = with_bytes(FRAME, 37, b"\x00" * 4)
    frame = with_bytes(frame, 45, b"\x00\x00")
    decoded = decode(frame)
    assert decoded["probable_tank_installed_utc"] is None
    assert decoded["gas"]["calculated_level_percent"] is None


@pytest.mark.parametrize("frame", [FRAME[:-1], b"\x00\x00" + FRAME[2:]])
def test_decode_rejects_invalid_frame(frame: bytes) -> None:
    with pytest.raises(ValueError):
        decode(frame)


# --------------------------------------------------------------------------
# Offline handling
# --------------------------------------------------------------------------

def test_offline_event_without_previous_frame() -> None:
    event = g32.make_offline_event(None, DEVICE_ID, "2026-08-16T10:00:00Z")
    assert event["g32"] == {"status": "offline", "device_id": "84e0422c"}
    assert event["offline_since_utc"] == "2026-08-16T10:00:00Z"
    assert "status_published_at_utc" in event


def test_offline_event_keeps_only_meaningful_fields() -> None:
    online = {
        "received_at_utc": "2026-08-16T09:59:00Z",
        "g32": decode(include_unknown=True),
        "mirror_sender": {"ip": "192.168.6.251", "port": 37009},
    }
    offline = g32.make_offline_event(online, None, "2026-08-16T10:00:00Z")
    assert offline["received_at_utc"] == "2026-08-16T09:59:00Z"  # last time the grill was on
    assert set(offline["g32"]) == {
        "device_id",
        "status",
        "gas",
        "probable_tank_installed_utc",
        "probable_tank_installed_timestamp_raw",
        "probable_tank_installed_local",
    }
    assert offline["g32"]["status"] == "offline"
    assert offline["g32"]["gas"] == online["g32"]["gas"]
    assert "mirror_sender" not in offline


def test_offline_event_does_not_mutate_last_event() -> None:
    online = {"received_at_utc": "2026-08-16T09:59:00Z", "g32": decode()}
    offline = g32.make_offline_event(online, None, "2026-08-16T10:00:00Z")
    offline["g32"]["gas"]["weight_kg"] = 0
    assert online["g32"]["status"] == "online"
    assert online["g32"]["gas"]["weight_kg"] == 10.323


def test_offline_event_from_restored_offline_event() -> None:
    first = g32.make_offline_event(
        {"received_at_utc": "2026-08-16T09:59:00Z", "g32": decode()}, None, "2026-08-16T10:00:00Z"
    )
    again = g32.make_offline_event(first, None, "2026-08-16T10:00:00Z")
    assert again["g32"] == first["g32"]
    assert again["received_at_utc"] == "2026-08-16T09:59:00Z"


def test_human_offline_line_shows_gas() -> None:
    online = {"received_at_utc": "2026-08-16T09:59:00Z", "g32": decode()}
    line = g32.format_human(g32.make_offline_event(online, None, "2026-08-16T10:00:00Z"))
    assert "status=offline last_seen=2026-08-16T09:59:00Z" in line
    assert "gas=10.323kg/11.000kg level=93%" in line


@pytest.mark.parametrize(
    ("now", "last_frame", "last_offline", "due"),
    [
        (59.9, 0.0, None, False),
        (60.0, 0.0, None, True),
        (119.9, 0.0, 60.0, False),
        (120.0, 0.0, 60.0, True),
    ],
)
def test_offline_heartbeat_due(now, last_frame, last_offline, due) -> None:
    assert g32.offline_heartbeat_due(now, last_frame, last_offline, 60.0) is due


# --------------------------------------------------------------------------
# Configuration and command line
# --------------------------------------------------------------------------

def write_config(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / "config.ini"
    path.write_text(text)
    path.chmod(mode)
    return path


def test_example_config_is_valid(tmp_path: Path) -> None:
    path = write_config(tmp_path, (PROJECT_DIR / "config.example.ini").read_text())
    config = g32.load_config(str(path))
    assert config["device_id"] == DEVICE_ID
    assert config["mqtt_availability_topic"] == "openhab/g32/availability"


@pytest.mark.skipif(os.name != "posix", reason="file modes are POSIX-only")
def test_config_readable_by_others_is_rejected(tmp_path: Path) -> None:
    path = write_config(tmp_path, "[listener]\nport = 37009\n", mode=0o644)
    with pytest.raises(ValueError, match="chmod 600"):
        g32.load_config(str(path))


@pytest.mark.parametrize(
    "text",
    [
        pytest.param("[unknown]\nkey = 1\n", id="unknown-section"),
        pytest.param("[mqtt]\nhostname = broker\n", id="unknown-key"),
        pytest.param("[listener]\nport = abc\n", id="bad-int"),
        pytest.param("[grill]\ndevice_id = 1234\n", id="bad-device-id"),
    ],
)
def test_invalid_config_is_rejected(tmp_path: Path, text: str) -> None:
    with pytest.raises(ValueError):
        g32.load_config(str(write_config(tmp_path, text)))


def test_negative_stats_interval_is_rejected() -> None:
    with pytest.raises(SystemExit):
        g32.main(["--self-test", "--stats-interval", "-1"])


def test_availability_topic_must_differ_from_status_topic() -> None:
    with pytest.raises(SystemExit) as excinfo:
        g32.main(["--self-test", "--mqtt-topic", "a/b", "--mqtt-availability-topic", "a/b"])
    assert excinfo.value.code == 2


def test_self_test_passes(capsys: pytest.CaptureFixture[str]) -> None:
    assert g32.main(["--self-test"]) == 0
    assert "self-test passed" in capsys.readouterr().err


def test_self_test_reports_failure_without_assert(capsys: pytest.CaptureFixture[str]) -> None:
    # A non-matching device filter rejects the built-in sample frame.
    assert g32.main(["--self-test", "--device-id", "00000000"]) == 1
    assert "self-test failed" in capsys.readouterr().err


# --------------------------------------------------------------------------
# HTTP endpoint
# --------------------------------------------------------------------------

def http_get(url: str) -> tuple[int, dict]:
    try:
        with urllib.request.urlopen(url, timeout=5) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as exc:
        return exc.code, json.load(exc)


def test_http_endpoint_serves_latest_event() -> None:
    latest = g32.LatestJSON()
    args = Namespace(http_enabled=True, http_bind="127.0.0.1", http_port=0, http_path="/g32", verbose=False)
    exporter = g32.start_http_exporter(args, latest)
    assert exporter is not None
    base = f"http://127.0.0.1:{exporter.server.server_address[1]}"
    try:
        assert http_get(base + "/g32") == (503, {"error": "no_g32_frame_received"})
        latest.update({"g32": {"status": "online"}})
        assert http_get(base + "/g32?x=1") == (200, {"g32": {"status": "online"}})
        assert http_get(base + "/other")[0] == 404
    finally:
        exporter.close()


# --------------------------------------------------------------------------
# MQTT publisher (with a fake paho module, no broker needed)
# --------------------------------------------------------------------------

class FakeInfo:
    rc = 0

    def __init__(self) -> None:
        self.waited = False

    def wait_for_publish(self, timeout: float | None = None) -> None:
        self.waited = True


class FakeClient:
    instances: list["FakeClient"] = []

    def __init__(self, *args, **kwargs) -> None:
        self.calls: list[tuple] = []
        self.infos: list[FakeInfo] = []
        FakeClient.instances.append(self)

    def __getattr__(self, name: str):
        # Record any configuration call (reconnect_delay_set, tls_set, ...).
        return lambda *args, **kwargs: self.calls.append((name, args, kwargs))

    def publish(self, topic, payload=None, qos=0, retain=False) -> FakeInfo:
        self.calls.append(("publish", topic, payload, retain))
        info = FakeInfo()
        self.infos.append(info)
        return info

    def call_names(self) -> list[str]:
        return [call[0] for call in self.calls]

    def published(self) -> list[tuple]:
        return [call[1:] for call in self.calls if call[0] == "publish"]


@pytest.fixture
def fake_paho(monkeypatch: pytest.MonkeyPatch) -> type[FakeClient]:
    client_module = types.ModuleType("paho.mqtt.client")
    client_module.Client = FakeClient
    client_module.MQTTv311 = 4
    client_module.MQTT_ERR_SUCCESS = 0
    client_module.CallbackAPIVersion = types.SimpleNamespace(VERSION2=2)
    mqtt_package = types.ModuleType("paho.mqtt")
    mqtt_package.client = client_module
    paho_package = types.ModuleType("paho")
    paho_package.mqtt = mqtt_package
    monkeypatch.setitem(sys.modules, "paho", paho_package)
    monkeypatch.setitem(sys.modules, "paho.mqtt", mqtt_package)
    monkeypatch.setitem(sys.modules, "paho.mqtt.client", client_module)
    FakeClient.instances = []
    return FakeClient


def mqtt_args(*extra: str) -> Namespace:
    args = g32.build_parser().parse_args(["--mqtt-host", "broker", "--mqtt-retain", *extra])
    args.mqtt_password = None
    return args


def test_mqtt_registers_last_will_before_connecting(fake_paho, capsys) -> None:
    g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    names = client.call_names()
    assert names.index("will_set") < names.index("connect_async")
    will = client.calls[names.index("will_set")]
    assert will[1] == ("openhab/g32/availability", b"offline")
    assert will[2]["retain"] is True


def test_mqtt_announces_online_then_sends_pending_payload(fake_paho, capsys) -> None:
    publisher = g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    publisher.publish(b'{"g32":{}}')  # not connected yet: kept for later
    assert client.published() == []
    publisher._on_connect(client, None, {}, 0)
    assert client.published() == [
        ("openhab/g32/availability", b"online", True),
        ("openhab/g32/status", b'{"g32":{}}', True),
    ]


def test_mqtt_close_announces_offline_when_connected(fake_paho, capsys) -> None:
    publisher = g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    publisher._on_connect(client, None, {}, 0)
    publisher.close()
    assert client.published()[-1] == ("openhab/g32/availability", b"offline", True)
    assert client.infos[-1].waited
    assert client.call_names()[-2:] == ["disconnect", "loop_stop"]


def test_mqtt_close_without_connection_publishes_nothing(fake_paho, capsys) -> None:
    publisher = g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    publisher.close()
    assert client.published() == []


def retained(payload: bytes, retain: bool = True) -> types.SimpleNamespace:
    return types.SimpleNamespace(payload=payload, retain=retain)


def test_mqtt_reads_back_retained_event_once(fake_paho, capsys) -> None:
    publisher = g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    publisher._on_connect(client, None, {}, 0)
    subscribe = [call for call in client.calls if call[0] == "subscribe"]
    assert subscribe and subscribe[0][1] == ("openhab/g32/status",)

    event = {"received_at_utc": "2026-08-16T09:59:00Z", "g32": {"status": "offline", "gas": {}}}
    publisher._on_message(client, None, retained(json.dumps(event).encode()))
    assert ("unsubscribe", ("openhab/g32/status",), {}) in client.calls
    assert publisher.take_restored_event() == event
    assert publisher.take_restored_event() is None

    # Later messages (our own publications) are ignored.
    publisher._on_message(client, None, retained(b'{"g32":{"status":"online"}}'))
    assert publisher.take_restored_event() is None


def test_mqtt_does_not_resubscribe_after_reconnect(fake_paho, capsys) -> None:
    publisher = g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    publisher._on_connect(client, None, {}, 0)
    publisher._on_message(client, None, retained(b'{"g32":{}}'))
    publisher._on_connect(client, None, {}, 0)
    assert client.call_names().count("subscribe") == 1


@pytest.mark.parametrize(
    "message",
    [
        pytest.param(retained(b'{"g32":{}}', retain=False), id="live-not-retained"),
        pytest.param(retained(b"not json"), id="invalid-json"),
        pytest.param(retained(b'{"other":1}'), id="no-g32-object"),
        pytest.param(retained(b"\xff\xfe"), id="invalid-utf8"),
    ],
)
def test_mqtt_ignores_unusable_retained_message(fake_paho, capsys, message) -> None:
    publisher = g32.MQTTPublisher(mqtt_args())
    client = fake_paho.instances[0]
    publisher._on_connect(client, None, {}, 0)
    publisher._on_message(client, None, message)
    assert publisher.take_restored_event() is None
    assert "unsubscribe" in client.call_names()


def test_mqtt_availability_can_be_disabled(fake_paho, capsys) -> None:
    publisher = g32.MQTTPublisher(mqtt_args("--mqtt-availability-topic", ""))
    client = fake_paho.instances[0]
    publisher._on_connect(client, None, {}, 0)
    publisher.close()
    assert "will_set" not in client.call_names()
    assert all(topic != "openhab/g32/availability" for topic, *_ in client.published())


# --------------------------------------------------------------------------
# End-to-end: run the real daemon as a separate process
# --------------------------------------------------------------------------

def free_udp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture
def daemon(request):
    port = free_udp_port()
    extra = getattr(request, "param", [])
    process = subprocess.Popen(
        [sys.executable, str(SCRIPT), "--bind", "127.0.0.1", "--port", str(port), *extra],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert "Listening for TZSP" in process.stderr.readline()
    yield process, port
    if process.poll() is None:
        process.kill()
        process.wait()


def stop(process: subprocess.Popen) -> tuple[str, str]:
    process.send_signal(signal.SIGTERM)
    stdout, stderr = process.communicate(timeout=10)
    return stdout, stderr


def test_daemon_decodes_mirrored_packet(daemon) -> None:
    process, port = daemon
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(build_tzsp(build_ethernet(FRAME)), ("127.0.0.1", port))
    time.sleep(0.5)
    stdout, stderr = stop(process)
    event = json.loads(stdout.splitlines()[0])
    assert event["g32"]["device_id"] == "84e0422c"
    assert event["g32"]["gas"]["weight_kg"] == 10.323
    assert "frames=1" in stderr


def test_daemon_shuts_down_cleanly_on_sigterm(daemon) -> None:
    process, _ = daemon
    _, stderr = stop(process)
    assert process.returncode == 0
    assert "Stopped:" in stderr


def test_daemon_prints_no_statistics_by_default(daemon) -> None:
    process, _ = daemon
    time.sleep(1.2)
    _, stderr = stop(process)
    assert "Statistics:" not in stderr


@pytest.mark.parametrize("daemon", [["--stats-interval", "0.3"]], indirect=True)
def test_daemon_prints_statistics_at_interval(daemon) -> None:
    process, _ = daemon
    time.sleep(1.2)
    _, stderr = stop(process)
    assert stderr.count("Statistics: tzsp=0") >= 1
