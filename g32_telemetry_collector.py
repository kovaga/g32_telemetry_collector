#!/usr/bin/env python3
"""Listen for MikroTik TZSP mirrors and decode Otto Wilde G32 telemetry.

The G32 sends a fixed 50-byte status frame over TCP to destination port 4501.
MikroTik's sniff-tzsp action wraps the original Ethernet frame in TZSP and sends
it to this program over UDP (normally port 37008).

The latest decoded event can optionally be served as JSON over HTTP and
published as JSON to MQTT. HTTP uses only Python's standard library. MQTT
support requires the optional paho-mqtt package. All service settings,
including the MQTT password, can be read from a protected INI file or a systemd
credential with --config so secrets never have to be placed in the environment
or process command line.
"""

from __future__ import annotations

import argparse
import configparser
import copy
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


# Standard TZSP commonly uses 37008, but the supplied MikroTik captures use
# UDP/37009 (0x9091), so that is the useful default for this installation.
DEFAULT_TZSP_PORT = 37009
DEFAULT_G32_TCP_PORT = 4501
DEFAULT_HTTP_PORT = 8765
DEFAULT_HTTP_PATH = "/g32"
DEFAULT_MQTT_PORT = 1883
DEFAULT_MQTT_TOPIC = "openhab/g32/status"
DEFAULT_MQTT_AVAILABILITY_TOPIC = "openhab/g32/availability"
DEFAULT_OFFLINE_SECONDS = 60.0
G32_MAGIC = b"\xa3\x3a"
G32_FRAME_LENGTH = 50
TCP_FIN = 0x01
TCP_SYN = 0x02
TCP_RST = 0x04
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}

CONFIG_SCHEMA = {
    "listener": {
        "bind": ("bind", "string"),
        "port": ("port", "int"),
    },
    "grill": {
        "ip": ("grill_ip", "optional_string"),
        "tcp_port": ("tcp_port", "int"),
        "device_id": ("device_id", "device_id"),
        "tare_weight_g": ("tare_weight_g", "int"),
    },
    "output": {
        "timezone": ("timezone", "string"),
        "human": ("human", "bool"),
        "pretty": ("pretty", "bool"),
        "rawframe": ("rawframe", "bool"),
        "verbose": ("verbose", "bool"),
        "offline_after": ("offline_after", "float"),
    },
    "http": {
        "enabled": ("http_enabled", "bool"),
        "bind": ("http_bind", "string"),
        "port": ("http_port", "int"),
        "path": ("http_path", "string"),
    },
    "mqtt": {
        "enabled": ("mqtt_enabled", "bool"),
        "host": ("mqtt_host", "optional_string"),
        "port": ("mqtt_port", "int"),
        "topic": ("mqtt_topic", "string"),
        "availability_topic": ("mqtt_availability_topic", "string"),
        "qos": ("mqtt_qos", "int"),
        "retain": ("mqtt_retain", "bool"),
        "client_id": ("mqtt_client_id", "string"),
        "username": ("mqtt_username", "optional_string"),
        "password": ("mqtt_password", "string"),
        "password_env": ("mqtt_password_env", "optional_string"),
        "tls": ("mqtt_tls", "bool"),
    },
}


class PacketError(ValueError):
    """Raised when a captured packet is truncated or malformed."""


@dataclass(frozen=True)
class TCPPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    sequence: int
    flags: int
    payload: bytes

    @property
    def stream_key(self) -> tuple[str, int, str, int]:
        return (self.src_ip, self.src_port, self.dst_ip, self.dst_port)


@dataclass
class TCPStream:
    next_sequence: int | None = None
    buffer: bytearray = field(default_factory=bytearray)
    last_seen_monotonic: float = field(default_factory=time.monotonic)
    gaps: int = 0

    def reset(self, next_sequence: int | None = None) -> None:
        self.next_sequence = next_sequence
        self.buffer.clear()

    def append(self, packet: TCPPacket) -> None:
        """Append new TCP bytes while suppressing retransmitted overlap.

        This is intentionally small rather than a complete TCP stack. G32 frames
        normally arrive in order. If the capture starts after a gap, the buffer
        is reset and frame extraction resynchronises on the a3:3a marker.
        """

        self.last_seen_monotonic = time.monotonic()
        payload_sequence = (packet.sequence + (1 if packet.flags & TCP_SYN else 0)) & 0xFFFFFFFF

        if packet.flags & TCP_SYN:
            self.reset(payload_sequence)

        if not packet.payload:
            if self.next_sequence is None:
                self.next_sequence = payload_sequence
            return

        if self.next_sequence is None:
            self.buffer.extend(packet.payload)
            self.next_sequence = (payload_sequence + len(packet.payload)) & 0xFFFFFFFF
            return

        delta = sequence_delta(payload_sequence, self.next_sequence)

        if delta == 0:
            new_data = packet.payload
        elif delta < 0:
            overlap = -delta
            if overlap >= len(packet.payload):
                return
            new_data = packet.payload[overlap:]
        else:
            # Missing TCP data. Drop the partial application frame and resume
            # from this segment; pull_g32_frames() will find the next header.
            self.gaps += 1
            self.buffer.clear()
            new_data = packet.payload

        self.buffer.extend(new_data)
        self.next_sequence = (payload_sequence + len(packet.payload)) & 0xFFFFFFFF


@dataclass
class Counters:
    tzsp_datagrams: int = 0
    inner_tcp_segments: int = 0
    matching_tcp_segments: int = 0
    decoded_frames: int = 0
    stream_gaps: int = 0
    malformed_datagrams: int = 0
    offline_events: int = 0


class LatestJSON:
    """Thread-safe storage for the most recently decoded JSON event."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._payload: bytes | None = None

    def update(self, event: dict[str, Any]) -> bytes:
        payload = json.dumps(event, separators=(",", ":"), sort_keys=True).encode("utf-8")
        with self._lock:
            self._payload = payload
        return payload

    def get(self) -> bytes | None:
        with self._lock:
            return self._payload


def make_http_handler(
    latest_json: LatestJSON,
    path: str,
    verbose: bool,
) -> type[BaseHTTPRequestHandler]:
    class G32HTTPHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 - method name defined by BaseHTTPRequestHandler
            request_path = self.path.partition("?")[0]
            if request_path != path:
                self._send_json(404, b'{"error":"not_found"}')
                return

            payload = latest_json.get()
            if payload is None:
                self._send_json(503, b'{"error":"no_g32_frame_received"}')
                return
            self._send_json(200, payload)

        def _send_json(self, status: int, payload: bytes) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format_string: str, *args: Any) -> None:
            if verbose:
                super().log_message(format_string, *args)

    return G32HTTPHandler


@dataclass
class HTTPExporter:
    server: ThreadingHTTPServer
    thread: threading.Thread

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5.0)


def start_http_exporter(args: argparse.Namespace, latest_json: LatestJSON) -> HTTPExporter | None:
    if not args.http_enabled:
        return None

    handler = make_http_handler(latest_json, args.http_path, args.verbose)
    server = ThreadingHTTPServer((args.http_bind, args.http_port), handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, name="g32-http", daemon=True)
    thread.start()
    actual_port = server.server_address[1]
    print(
        f"HTTP JSON endpoint: http://{args.http_bind}:{actual_port}{args.http_path}",
        file=sys.stderr,
        flush=True,
    )
    return HTTPExporter(server, thread)


class MQTTPublisher:
    """Publish only the most recent event, reconnecting in the background."""

    def __init__(self, args: argparse.Namespace) -> None:
        try:
            import paho.mqtt.client as mqtt
        except ImportError as exc:
            raise RuntimeError(
                "MQTT requires paho-mqtt; install it with "
                "'python3 -m pip install paho-mqtt' or your distribution package"
            ) from exc

        self._mqtt = mqtt
        self._topic = args.mqtt_topic
        self._availability_topic = args.mqtt_availability_topic or None
        self._qos = args.mqtt_qos
        self._retain = args.mqtt_retain
        self._verbose = args.verbose
        self._closing = False
        self._connected = False
        self._latest_payload: bytes | None = None
        self._lock = threading.Lock()
        self._last_publish_warning = 0.0

        # Paho 2.x requires an explicit callback API version. Retain support for
        # distribution packages that still ship Paho 1.x.
        try:
            callback_version = mqtt.CallbackAPIVersion.VERSION2
            self._client = mqtt.Client(
                callback_version,
                client_id=args.mqtt_client_id,
                protocol=mqtt.MQTTv311,
            )
        except AttributeError:
            self._client = mqtt.Client(client_id=args.mqtt_client_id, protocol=mqtt.MQTTv311)

        self._client.on_connect = self._on_connect
        self._client.on_disconnect = self._on_disconnect
        self._client.reconnect_delay_set(min_delay=1, max_delay=30)

        if args.mqtt_username:
            password = args.mqtt_password
            if password is None and args.mqtt_password_env:
                password = os.environ.get(args.mqtt_password_env)
            self._client.username_pw_set(args.mqtt_username, password)
        if args.mqtt_tls:
            self._client.tls_set()
        if self._availability_topic:
            # The broker publishes this if the collector vanishes without a
            # clean disconnect (crash, power loss, network failure).
            self._client.will_set(self._availability_topic, b"offline", qos=self._qos, retain=True)

        self._client.connect_async(args.mqtt_host, args.mqtt_port, keepalive=60)
        self._client.loop_start()
        print(
            f"MQTT JSON topic: {args.mqtt_host}:{args.mqtt_port}/{args.mqtt_topic} "
            f"qos={args.mqtt_qos} retain={str(args.mqtt_retain).lower()} "
            f"availability={self._availability_topic or 'disabled'}",
            file=sys.stderr,
            flush=True,
        )

    @staticmethod
    def _connection_succeeded(reason_code: Any) -> bool:
        try:
            return int(reason_code) == 0
        except (TypeError, ValueError):
            return not bool(getattr(reason_code, "is_failure", True))

    def _on_connect(
        self,
        client: Any,
        userdata: Any,
        flags: Any,
        reason_code: Any,
        properties: Any = None,
    ) -> None:
        succeeded = self._connection_succeeded(reason_code)
        with self._lock:
            self._connected = succeeded
            payload = self._latest_payload

        if self._verbose:
            state = "connected" if succeeded else f"connection refused ({reason_code})"
            print(f"MQTT {state}", file=sys.stderr, flush=True)
        if succeeded and self._availability_topic:
            self._client.publish(self._availability_topic, b"online", qos=self._qos, retain=True)
        if succeeded and payload is not None:
            self._publish_now(payload)

    def _on_disconnect(self, client: Any, userdata: Any, *args: Any) -> None:
        with self._lock:
            self._connected = False
        if self._verbose and not self._closing:
            print("MQTT disconnected; reconnecting in background", file=sys.stderr, flush=True)

    def publish(self, payload: bytes) -> None:
        with self._lock:
            self._latest_payload = payload
            connected = self._connected
        if connected:
            self._publish_now(payload)

    def _publish_now(self, payload: bytes) -> None:
        info = self._client.publish(
            self._topic,
            payload=payload,
            qos=self._qos,
            retain=self._retain,
        )
        if info.rc == self._mqtt.MQTT_ERR_SUCCESS:
            return

        now = time.monotonic()
        if self._verbose and now - self._last_publish_warning >= 30:
            print(f"MQTT publish deferred/failed with result {info.rc}", file=sys.stderr, flush=True)
            self._last_publish_warning = now

    def close(self) -> None:
        self._closing = True
        with self._lock:
            connected = self._connected
        if connected and self._availability_topic:
            # A clean disconnect discards the last will, so announce it here.
            info = self._client.publish(self._availability_topic, b"offline", qos=self._qos, retain=True)
            try:
                info.wait_for_publish(timeout=5.0)
            except (RuntimeError, ValueError):
                pass
        self._client.disconnect()
        self._client.loop_stop()


def sequence_delta(sequence: int, expected: int) -> int:
    """Return signed 32-bit TCP sequence difference, including wraparound."""

    return ((sequence - expected + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def parse_tzsp(datagram: bytes) -> bytes:
    """Return the Ethernet frame encapsulated in a TZSP UDP payload."""

    if len(datagram) < 5:
        raise PacketError("TZSP datagram is too short")

    version, packet_type, encapsulation = struct.unpack_from("!BBH", datagram, 0)
    if version != 1:
        raise PacketError(f"unsupported TZSP version {version}")
    if packet_type not in (0, 1):
        raise PacketError(f"TZSP packet type {packet_type} does not contain a captured frame")
    if encapsulation != 1:
        raise PacketError(f"unsupported TZSP encapsulation {encapsulation}; Ethernet is 1")

    offset = 4
    while offset < len(datagram):
        tag_type = datagram[offset]
        offset += 1

        if tag_type == 0:  # Padding tag
            continue
        if tag_type == 1:  # End tag; captured Ethernet follows
            if len(datagram) - offset < 14:
                raise PacketError("TZSP Ethernet frame is truncated")
            return datagram[offset:]

        if offset >= len(datagram):
            raise PacketError("TZSP tag has no length byte")
        tag_length = datagram[offset]
        offset += 1
        if offset + tag_length > len(datagram):
            raise PacketError("TZSP tag extends beyond datagram")
        offset += tag_length

    raise PacketError("TZSP end tag is missing")


def parse_inner_tcp(ethernet: bytes) -> TCPPacket | None:
    """Parse an Ethernet/IPv4/TCP frame, returning None for other traffic."""

    if len(ethernet) < 14:
        raise PacketError("inner Ethernet frame is too short")

    ethertype = struct.unpack_from("!H", ethernet, 12)[0]
    ip_offset = 14

    while ethertype in VLAN_ETHERTYPES:
        if len(ethernet) < ip_offset + 4:
            raise PacketError("truncated VLAN header")
        ethertype = struct.unpack_from("!H", ethernet, ip_offset + 2)[0]
        ip_offset += 4

    if ethertype != 0x0800:
        return None
    if len(ethernet) < ip_offset + 20:
        raise PacketError("truncated IPv4 header")

    version_ihl = ethernet[ip_offset]
    if version_ihl >> 4 != 4:
        return None
    ip_header_length = (version_ihl & 0x0F) * 4
    if ip_header_length < 20 or len(ethernet) < ip_offset + ip_header_length:
        raise PacketError("invalid IPv4 header length")

    total_length = struct.unpack_from("!H", ethernet, ip_offset + 2)[0]
    if total_length < ip_header_length or len(ethernet) < ip_offset + total_length:
        raise PacketError("truncated inner IPv4 packet")

    fragment = struct.unpack_from("!H", ethernet, ip_offset + 6)[0]
    if fragment & 0x3FFF:  # More-fragments flag or non-zero fragment offset
        return None
    if ethernet[ip_offset + 9] != socket.IPPROTO_TCP:
        return None

    src_ip = socket.inet_ntoa(ethernet[ip_offset + 12 : ip_offset + 16])
    dst_ip = socket.inet_ntoa(ethernet[ip_offset + 16 : ip_offset + 20])
    tcp_offset = ip_offset + ip_header_length
    ip_end = ip_offset + total_length

    if ip_end < tcp_offset + 20:
        raise PacketError("truncated TCP header")

    src_port, dst_port, sequence = struct.unpack_from("!HHI", ethernet, tcp_offset)
    tcp_header_length = (ethernet[tcp_offset + 12] >> 4) * 4
    if tcp_header_length < 20 or tcp_offset + tcp_header_length > ip_end:
        raise PacketError("invalid TCP header length")

    return TCPPacket(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        sequence=sequence,
        flags=ethernet[tcp_offset + 13],
        payload=bytes(ethernet[tcp_offset + tcp_header_length : ip_end]),
    )


def pull_g32_frames(buffer: bytearray, expected_device_id: bytes | None = None) -> list[bytes]:
    """Extract complete 50-byte frames and retain any incomplete tail."""

    frames: list[bytes] = []

    while True:
        marker = buffer.find(G32_MAGIC)
        if marker < 0:
            # Preserve a possible first byte of the magic marker across segments.
            keep = 1 if buffer and buffer[-1] == G32_MAGIC[0] else 0
            if len(buffer) > keep:
                del buffer[: len(buffer) - keep]
            break

        if marker:
            del buffer[:marker]
        if len(buffer) < G32_FRAME_LENGTH:
            break

        candidate = bytes(buffer[:G32_FRAME_LENGTH])
        if expected_device_id is not None and candidate[2:6] != expected_device_id:
            # This was a false marker or another grill. Advance one byte and
            # search again rather than discarding an entire possible frame.
            del buffer[0]
            continue

        frames.append(candidate)
        del buffer[:G32_FRAME_LENGTH]

    return frames


def decode_temperature(raw: bytes) -> float | None:
    if len(raw) != 2:
        raise ValueError("temperature field must contain two bytes")
    if raw == b"\x96\x00":
        return None
    return round(raw[0] * 10.0 + raw[1] / 10.0, 1)


def iso_timestamp(timestamp: int, tz: ZoneInfo) -> tuple[str | None, str | None]:
    """Decode a plausible Unix timestamp; return (UTC, local) ISO strings."""

    # Reject zero/uninitialised values and implausible dates.
    if timestamp < 946684800 or timestamp > 4102444800:  # 2000-01-01 .. 2100-01-01
        return None, None
    utc_dt = datetime.fromtimestamp(timestamp, timezone.utc)
    return (
        utc_dt.isoformat().replace("+00:00", "Z"),
        utc_dt.astimezone(tz).isoformat(),
    )


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def offline_heartbeat_due(
    now_monotonic: float,
    last_frame_or_start_monotonic: float,
    last_offline_publish_monotonic: float | None,
    interval: float,
) -> bool:
    if now_monotonic - last_frame_or_start_monotonic < interval:
        return False
    return (
        last_offline_publish_monotonic is None
        or now_monotonic - last_offline_publish_monotonic >= interval
    )


def decode_g32_frame(
    frame: bytes,
    *,
    tare_weight_g: int | None,
    local_timezone: ZoneInfo,
    include_raw: bool,
    include_unknown: bool,
) -> dict[str, Any]:
    if len(frame) != G32_FRAME_LENGTH:
        raise ValueError(f"G32 frame must be {G32_FRAME_LENGTH} bytes")
    if frame[:2] != G32_MAGIC:
        raise ValueError("G32 frame magic is not a33a")

    zone_temperatures = [decode_temperature(frame[i : i + 2]) for i in range(6, 14, 2)]
    probe_temperatures = [decode_temperature(frame[i : i + 2]) for i in range(14, 22, 2)]
    gas_weight_g = int.from_bytes(frame[22:24], "big")
    gas_level_percent = frame[31]
    capacity_g = int.from_bytes(frame[45:47], "big")
    calculated_level = round(gas_weight_g * 100.0 / capacity_g, 2) if capacity_g else None

    probable_timestamp_raw = int.from_bytes(frame[37:41], "little")
    probable_timestamp_utc, probable_timestamp_local = iso_timestamp(
        probable_timestamp_raw, local_timezone
    )

    gas: dict[str, Any] = {
        "weight_kg": round(gas_weight_g / 1000.0, 3),
        "level_percent": gas_level_percent,
        "calculated_level_percent": calculated_level,
        "capacity_kg": round(capacity_g / 1000.0, 3),
    }
    if tare_weight_g is not None:
        gas["tare_weight_kg_configured_locally"] = round(tare_weight_g / 1000.0, 3)
        gas["estimated_gross_weight_kg"] = round((gas_weight_g + tare_weight_g) / 1000.0, 3)

    decoded: dict[str, Any] = {
        "device_id": frame[2:6].hex(),
        "status": "online",
        "temperatures_c": {
            "zone_1": zone_temperatures[0],
            "zone_2": zone_temperatures[1],
            "zone_3": zone_temperatures[2],
            "zone_4": zone_temperatures[3],
            "probe_1": probe_temperatures[0],
            "probe_2": probe_temperatures[1],
            "probe_3": probe_temperatures[2],
            "probe_4": probe_temperatures[3],
        },
        "gas": gas,
        "lid_open": frame[24] == 1,
        "light_on": frame[25] == 1,
        # Confirmed by controlled app tests: lowest=0x00, normal=0x34
        # (52), maximum=0x64 (100). The app uses steps of four.
        "hood_light_sensitivity_percent": frame[33],
        # This interpretation is strongly supported by the captured value and
        # the known bottle-change date, but still needs a controlled confirmation.
        "probable_tank_installed_utc": probable_timestamp_utc,
    }
    if include_unknown:
        decoded["probable_tank_installed_timestamp_raw"] = probable_timestamp_raw
        decoded["probable_tank_installed_local"] = probable_timestamp_local
        decoded["unknown_fields"] = {
            "bytes_26_28_hex": frame[26:29].hex(),
            "bytes_29_30_hex": frame[29:31].hex(),
            "bytes_29_30_u16_be": int.from_bytes(frame[29:31], "big"),
            "byte_32_hex": f"{frame[32]:02x}",
            "bytes_34_36_hex": frame[34:37].hex(),
            "bytes_41_44_hex": frame[41:45].hex(),
            "bytes_47_48_hex": frame[47:49].hex(),
            "byte_49_hex": f"{frame[49]:02x}",
        }
    if include_raw:
        decoded["raw_frame_hex"] = frame.hex()
    return decoded


def format_human(event: dict[str, Any]) -> str:
    decoded = event["g32"]
    if decoded["status"] == "offline":
        published_at = event["status_published_at_utc"]
        last_seen = event.get("received_at_utc", "never")
        return (
            f'{published_at} id={decoded.get("device_id", "unknown")} '
            f'status=offline last_seen={last_seen} '
            f'offline_since={event["offline_since_utc"]}'
        )

    temps = decoded["temperatures_c"]
    zones = ",".join("-" if temps[f"zone_{i}"] is None else f'{temps[f"zone_{i}"]:.1f}' for i in range(1, 5))
    probes = ",".join("-" if temps[f"probe_{i}"] is None else f'{temps[f"probe_{i}"]:.1f}' for i in range(1, 5))
    gas = decoded["gas"]
    tank_time = decoded["probable_tank_installed_utc"] or "unknown"
    parts = [
        f'{event["received_at_utc"]} id={decoded["device_id"]} '
        "status=online "
        f'zones=[{zones}]C probes=[{probes}]C '
        f'gas={gas["weight_kg"]:.3f}kg/{gas["capacity_kg"]:.3f}kg '
        f'level={gas["level_percent"]}% '
        f'lid={"open" if decoded["lid_open"] else "closed"} '
        f'light={"on" if decoded["light_on"] else "off"} '
        f'hood_light_sensitivity={decoded["hood_light_sensitivity_percent"]}% '
        f'probable_tank_installed={tank_time}'
    ]

    if "mirror_sender" in event:
        mirror = event["mirror_sender"]
        tcp = event["inner_tcp"]
        parts.append(
            f' mirror={mirror["ip"]}:{mirror["port"]}'
            f' tcp={tcp["src_ip"]}:{tcp["src_port"]}->{tcp["dst_ip"]}:{tcp["dst_port"]}'
        )

    if "unknown_fields" in decoded:
        unknown = decoded["unknown_fields"]
        parts.append(
            f' tank_installed_local={decoded["probable_tank_installed_local"] or "unknown"}'
            f' tank_installed_unix={decoded["probable_tank_installed_timestamp_raw"]}'
            " unknown="
            f'26-28:{unknown["bytes_26_28_hex"]},'
            f'29-30:{unknown["bytes_29_30_hex"]}/{unknown["bytes_29_30_u16_be"]},'
            f'32:{unknown["byte_32_hex"]},'
            f'34-36:{unknown["bytes_34_36_hex"]},'
            f'41-44:{unknown["bytes_41_44_hex"]},'
            f'47-48:{unknown["bytes_47_48_hex"]},'
            f'49:{unknown["byte_49_hex"]}'
        )

    if "raw_frame_hex" in decoded:
        parts.append(f' raw_frame={decoded["raw_frame_hex"]}')

    return "".join(parts)


def parse_device_id(value: str) -> bytes:
    normalised = value.replace(":", "").replace("-", "").lower()
    if len(normalised) != 8:
        raise argparse.ArgumentTypeError("device ID must contain exactly four bytes, e.g. 84e0422c")
    try:
        return bytes.fromhex(normalised)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("device ID must be hexadecimal") from exc


def load_config(path: str) -> dict[str, Any]:
    """Read command-line defaults from a protected INI file."""

    try:
        file_stat = os.stat(path)
    except OSError as exc:
        raise ValueError(f"cannot read configuration file {path!r}: {exc.strerror}") from exc

    # A normal config containing a password must not be readable by group or
    # others. systemd credentials are handled separately: with DynamicUser,
    # newer systemd versions may expose them as mode 0440 plus a restrictive
    # ACL. The credential directory itself is private and read-only, so testing
    # only the traditional mode bits would incorrectly reject a secure file.
    credential_directory = os.environ.get("CREDENTIALS_DIRECTORY")
    is_systemd_credential = bool(
        credential_directory
        and os.path.dirname(os.path.realpath(path))
        == os.path.realpath(credential_directory)
    )

    if os.name == "posix" and not is_systemd_credential and file_stat.st_mode & 0o077:
        current_mode = file_stat.st_mode & 0o777
        raise ValueError(
            f"configuration file {path!r} must not be readable by group or others "
            f"(current mode {current_mode:04o}; run: chmod 600 {path})"
        )

    config = configparser.ConfigParser(interpolation=None)
    try:
        with open(path, encoding="utf-8") as config_file:
            config.read_file(config_file)
    except (OSError, configparser.Error) as exc:
        raise ValueError(f"cannot parse configuration file {path!r}: {exc}") from exc

    if config.defaults():
        raise ValueError("the [DEFAULT] section is not supported")

    unexpected_sections = sorted(set(config.sections()) - set(CONFIG_SCHEMA))
    if unexpected_sections:
        raise ValueError(
            "unsupported configuration section(s): " + ", ".join(unexpected_sections)
        )

    defaults: dict[str, Any] = {}
    for section_name in config.sections():
        section = config[section_name]
        schema = CONFIG_SCHEMA[section_name]
        unexpected_keys = sorted(set(section) - set(schema))
        if unexpected_keys:
            raise ValueError(
                f"unsupported key(s) in [{section_name}]: " + ", ".join(unexpected_keys)
            )

        for key, (destination, value_type) in schema.items():
            if key not in section:
                continue
            try:
                if value_type == "int":
                    value: Any = section.getint(key)
                elif value_type == "float":
                    value = section.getfloat(key)
                elif value_type == "bool":
                    value = section.getboolean(key)
                else:
                    value = section.get(key).strip()
                    if value_type == "optional_string" and not value:
                        value = None
                    elif value_type == "device_id":
                        value = None if not value else parse_device_id(value)
            except (ValueError, argparse.ArgumentTypeError) as exc:
                raise ValueError(f"invalid [{section_name}] {key}: {exc}") from exc
            defaults[destination] = value

    return defaults


def build_parser(config_defaults: dict[str, Any] | None = None) -> argparse.ArgumentParser:
    config_defaults = config_defaults or {}

    def config_default(name: str, fallback: Any = None) -> Any:
        return config_defaults.get(name, fallback)

    parser = argparse.ArgumentParser(
        description="Decode Otto Wilde G32 telemetry from MikroTik TZSP packets.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Configuration example (for an ordinary file, use chmod 600):
  [listener]
  bind = 0.0.0.0
  port = 37009

  [grill]
  ip = 192.168.6.117
  tcp_port = 4501
  device_id = 84e0422c

  [output]
  timezone = UTC
  human = false
  pretty = false
  rawframe = false
  verbose = false
  offline_after = 60

  [http]
  enabled = true
  bind = 127.0.0.1
  port = 8765
  path = /g32

  [mqtt]
  enabled = true
  host = 192.168.9.12
  port = 1883
  topic = openhab/g32/status
  availability_topic = openhab/g32/availability
  qos = 1
  retain = true
  client_id = g32-telemetry-collector
  username = mqttuser
  password = change-me
  tls = false

Command-line settings override matching file settings. The config password
takes precedence over --mqtt-password-env. There is intentionally no
command-line password option because argv is visible in ps.
""",
    )
    config_group = parser.add_mutually_exclusive_group()
    config_group.add_argument(
        "--config",
        metavar="FILE",
        help="protected INI file containing the complete collector configuration",
    )
    config_group.add_argument(
        "--mqtt-config",
        metavar="FILE",
        help="deprecated alias for --config, retained for compatibility",
    )
    parser.add_argument(
        "--bind",
        default=config_default("bind", "0.0.0.0"),
        help="local address to bind (default: %(default)s)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=config_default("port", DEFAULT_TZSP_PORT),
        help="TZSP UDP port (default: %(default)s)",
    )
    parser.add_argument(
        "--grill-ip",
        default=config_default("grill_ip"),
        help="only accept inner TCP packets from this grill IPv4 address",
    )
    parser.add_argument(
        "--tcp-port",
        type=int,
        default=config_default("tcp_port", DEFAULT_G32_TCP_PORT),
        help="G32 cloud destination TCP port (default: %(default)s)",
    )
    parser.add_argument(
        "--device-id",
        type=parse_device_id,
        default=config_default("device_id"),
        help="optional four-byte device filter, e.g. 84e0422c",
    )
    parser.add_argument(
        "--tare-weight-g",
        type=int,
        default=config_default("tare_weight_g"),
        help="optional local tare weight; adds estimated gross weight (not decoded from frame)",
    )
    parser.add_argument(
        "--timezone",
        default=config_default("timezone", "Europe/Berlin"),
        help="timezone for the probable tank timestamp (default: %(default)s)",
    )
    parser.add_argument(
        "--human",
        action=argparse.BooleanOptionalAction,
        default=config_default("human", False),
        help="print compact human-readable lines",
    )
    parser.add_argument(
        "--pretty",
        action=argparse.BooleanOptionalAction,
        default=config_default("pretty", False),
        help="pretty-print multiline JSON",
    )
    parser.add_argument(
        "--rawframe",
        action=argparse.BooleanOptionalAction,
        default=config_default("rawframe", False),
        help="include the raw 50-byte frame in JSON or human output",
    )
    parser.add_argument(
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=config_default("verbose", False),
        help="include mirror/TCP/unknown fields and log malformed packets and TCP gaps",
    )
    parser.add_argument(
        "--offline-after",
        type=float,
        default=config_default("offline_after", DEFAULT_OFFLINE_SECONDS),
        metavar="SECONDS",
        help=(
            "publish offline after this many seconds without a decoded frame, "
            "then repeat at the same interval (default: %(default)s)"
        ),
    )
    http_group = parser.add_argument_group("HTTP JSON export")
    http_group.add_argument(
        "--http-enabled",
        action=argparse.BooleanOptionalAction,
        default=config_default("http_enabled"),
        help="enable or disable the local HTTP JSON endpoint (disabled by default)",
    )
    http_group.add_argument(
        "--http-port",
        type=int,
        default=config_default("http_port", DEFAULT_HTTP_PORT),
        help="HTTP listen port (default: %(default)s)",
    )
    http_group.add_argument(
        "--http-bind",
        default=config_default("http_bind", "127.0.0.1"),
        help="HTTP listen address (default: %(default)s)",
    )
    http_group.add_argument(
        "--http-path",
        default=config_default("http_path", DEFAULT_HTTP_PATH),
        help="HTTP endpoint path (default: %(default)s)",
    )

    mqtt_group = parser.add_argument_group("MQTT JSON publishing")
    mqtt_group.add_argument(
        "--mqtt-enabled",
        action=argparse.BooleanOptionalAction,
        default=config_default("mqtt_enabled"),
        help="enable or disable MQTT JSON publishing (disabled by default)",
    )
    mqtt_group.add_argument(
        "--mqtt-host",
        default=config_default("mqtt_host"),
        help="MQTT broker hostname or address",
    )
    mqtt_group.add_argument(
        "--mqtt-port",
        type=int,
        default=config_default("mqtt_port", DEFAULT_MQTT_PORT),
        help="MQTT broker port (default: %(default)s)",
    )
    mqtt_group.add_argument(
        "--mqtt-topic",
        default=config_default("mqtt_topic", DEFAULT_MQTT_TOPIC),
        help="topic receiving the complete JSON event (default: %(default)s)",
    )
    mqtt_group.add_argument(
        "--mqtt-availability-topic",
        default=config_default("mqtt_availability_topic", DEFAULT_MQTT_AVAILABILITY_TOPIC),
        help=(
            "retained topic receiving 'online' while the collector is connected and "
            "'offline' (MQTT last will) when it stops or dies; empty disables "
            "(default: %(default)s)"
        ),
    )
    mqtt_group.add_argument(
        "--mqtt-qos",
        type=int,
        choices=(0, 1, 2),
        default=config_default("mqtt_qos", 1),
        help="MQTT publish QoS (default: %(default)s)",
    )
    mqtt_group.add_argument(
        "--mqtt-retain",
        action=argparse.BooleanOptionalAction,
        default=config_default("mqtt_retain", False),
        help="publish the JSON event as a retained MQTT message",
    )
    mqtt_group.add_argument(
        "--mqtt-client-id",
        default=config_default("mqtt_client_id", "g32-telemetry-collector"),
        help="MQTT client ID (default: %(default)s)",
    )
    mqtt_group.add_argument(
        "--mqtt-username",
        default=config_default("mqtt_username"),
        help="optional MQTT username",
    )
    mqtt_group.add_argument(
        "--mqtt-password-env",
        default=config_default("mqtt_password_env", "G32_MQTT_PASSWORD"),
        help="environment variable holding the MQTT password (default: %(default)s)",
    )
    mqtt_group.add_argument(
        "--mqtt-tls",
        action=argparse.BooleanOptionalAction,
        default=config_default("mqtt_tls", False),
        help="enable MQTT TLS using the system CA store",
    )
    parser.add_argument("--self-test", action="store_true", help="decode a built-in captured sample and exit")
    return parser


def output_event(event: dict[str, Any], args: argparse.Namespace) -> None:
    if args.human:
        print(format_human(event), flush=True)
    elif args.pretty:
        print(json.dumps(event, indent=2, sort_keys=True), flush=True)
    else:
        print(json.dumps(event, separators=(",", ":"), sort_keys=True), flush=True)


def make_event(
    decoded: dict[str, Any],
    packet: TCPPacket,
    mirror: tuple[str, int],
    *,
    include_network_metadata: bool,
) -> dict[str, Any]:
    event: dict[str, Any] = {
        "received_at_utc": utc_now_iso(),
        "g32": decoded,
    }
    if include_network_metadata:
        event["mirror_sender"] = {"ip": mirror[0], "port": mirror[1]}
        event["inner_tcp"] = {
            "src_ip": packet.src_ip,
            "src_port": packet.src_port,
            "dst_ip": packet.dst_ip,
            "dst_port": packet.dst_port,
        }
    return event


def make_offline_event(
    last_online_event: dict[str, Any] | None,
    expected_device_id: bytes | None,
    offline_since_utc: str,
) -> dict[str, Any]:
    if last_online_event is None:
        decoded: dict[str, Any] = {"status": "offline"}
        if expected_device_id is not None:
            decoded["device_id"] = expected_device_id.hex()
        event: dict[str, Any] = {"g32": decoded}
    else:
        event = copy.deepcopy(last_online_event)
        event["g32"]["status"] = "offline"

    event["offline_since_utc"] = offline_since_utc
    event["status_published_at_utc"] = utc_now_iso()
    return event


def dispatch_event(
    event: dict[str, Any],
    args: argparse.Namespace,
    latest_json: LatestJSON,
    mqtt_publisher: MQTTPublisher | None,
) -> None:
    payload = latest_json.update(event)
    if mqtt_publisher is not None:
        mqtt_publisher.publish(payload)
    output_event(event, args)


def run_self_test(args: argparse.Namespace, local_timezone: ZoneInfo) -> int:
    frame = bytes.fromhex(
        "a33a84e0422c0214020a020a020a9600960096009600285300000d010405bb"
        "5d0118010001a1bd746a000000002af80001c3"
    )
    # UDP payload received from the TZSP sender for the user's captured packet.
    tzsp = bytes.fromhex(
        "0100000101"
        "00005e000106782184e0422c0800"
        "4500005a030300004006fba3c0a806750378b162"
        "fc5d11957bb293354f33802f501816804c960000"
    ) + frame

    ethernet = parse_tzsp(tzsp)
    packet = parse_inner_tcp(ethernet)
    assert packet is not None
    assert packet.src_ip == "192.168.6.117"
    assert packet.dst_ip == "3.120.177.98"
    assert packet.dst_port == 4501
    assert packet.payload == frame

    # Also verify that a frame split over two TCP segments is reconstructed.
    stream = TCPStream()
    part1 = TCPPacket(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, 1000, 0, frame[:17])
    part2 = TCPPacket(packet.src_ip, packet.dst_ip, packet.src_port, packet.dst_port, 1017, 0, frame[17:])
    stream.append(part1)
    assert not pull_g32_frames(stream.buffer, args.device_id)
    stream.append(part2)
    extracted = pull_g32_frames(stream.buffer, args.device_id)
    assert extracted == [frame]

    decoded = decode_g32_frame(
        extracted[0],
        tare_weight_g=args.tare_weight_g,
        local_timezone=local_timezone,
        include_raw=args.rawframe,
        include_unknown=args.verbose,
    )
    assert decoded["temperatures_c"]["zone_1"] == 22.0
    assert decoded["gas"]["weight_kg"] == 10.323
    assert decoded["gas"]["level_percent"] == 93
    assert decoded["gas"]["capacity_kg"] == 11.0
    assert decoded["status"] == "online"
    assert decoded["hood_light_sensitivity_percent"] == 24
    assert decoded["probable_tank_installed_utc"] == "2026-08-06T17:00:17Z"
    assert ("unknown_fields" in decoded) == args.verbose
    assert ("probable_tank_installed_timestamp_raw" in decoded) == args.verbose
    assert ("probable_tank_installed_local" in decoded) == args.verbose
    assert ("raw_frame_hex" in decoded) == args.rawframe

    event = make_event(
        decoded,
        packet,
        ("192.168.6.251", DEFAULT_TZSP_PORT),
        include_network_metadata=args.verbose,
    )
    assert ("mirror_sender" in event) == args.verbose
    assert ("inner_tcp" in event) == args.verbose

    offline_since = "2026-08-16T10:00:00Z"
    offline_event = make_offline_event(event, args.device_id, offline_since)
    assert offline_event["g32"]["status"] == "offline"
    assert offline_event["received_at_utc"] == event["received_at_utc"]
    assert offline_event["offline_since_utc"] == offline_since
    assert event["g32"]["status"] == "online"
    assert not offline_heartbeat_due(59.9, 0.0, None, 60.0)
    assert offline_heartbeat_due(60.0, 0.0, None, 60.0)
    assert not offline_heartbeat_due(119.9, 0.0, 60.0, 60.0)
    assert offline_heartbeat_due(120.0, 0.0, 60.0, 60.0)
    output_event(event, args)
    print("self-test passed", file=sys.stderr)
    return 0


def stop_on_sigterm(signum: int, frame: Any) -> None:
    """Treat SIGTERM (systemctl stop, docker stop) like Ctrl+C.

    Python's default SIGTERM action ends the process immediately, skipping the
    finally block that disconnects MQTT cleanly and prints the counters.
    """

    raise KeyboardInterrupt


def listen(args: argparse.Namespace, local_timezone: ZoneInfo) -> int:
    signal.signal(signal.SIGTERM, stop_on_sigterm)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
    sock.bind((args.bind, args.port))
    sock.settimeout(min(1.0, args.offline_after))

    streams: dict[tuple[str, int, str, int], TCPStream] = {}
    counters = Counters()
    expected_device_id = args.device_id
    latest_json = LatestJSON()
    http_exporter: HTTPExporter | None = None
    mqtt_publisher: MQTTPublisher | None = None
    listener_started_monotonic = time.monotonic()
    last_frame_monotonic: float | None = None
    last_offline_publish_monotonic: float | None = None
    last_online_event: dict[str, Any] | None = None
    offline_since_utc: str | None = None

    print(
        f"Listening for TZSP on udp://{args.bind}:{args.port}; "
        f"inner filter: src={args.grill_ip or '*'} dst-tcp-port={args.tcp_port}",
        file=sys.stderr,
        flush=True,
    )

    try:
        http_exporter = start_http_exporter(args, latest_json)
        if args.mqtt_enabled:
            mqtt_publisher = MQTTPublisher(args)

        while True:
            now = time.monotonic()
            last_frame_or_start = (
                last_frame_monotonic
                if last_frame_monotonic is not None
                else listener_started_monotonic
            )
            if offline_heartbeat_due(
                now,
                last_frame_or_start,
                last_offline_publish_monotonic,
                args.offline_after,
            ):
                if offline_since_utc is None:
                    offline_since_utc = utc_now_iso()
                offline_event = make_offline_event(
                    last_online_event,
                    expected_device_id,
                    offline_since_utc,
                )
                dispatch_event(offline_event, args, latest_json, mqtt_publisher)
                last_offline_publish_monotonic = now
                counters.offline_events += 1

            try:
                datagram, mirror = sock.recvfrom(65535)
            except socket.timeout:
                now = time.monotonic()
                for key in [key for key, stream in streams.items() if now - stream.last_seen_monotonic > 600]:
                    del streams[key]
                continue

            counters.tzsp_datagrams += 1
            try:
                ethernet = parse_tzsp(datagram)
                packet = parse_inner_tcp(ethernet)
            except PacketError as exc:
                counters.malformed_datagrams += 1
                if args.verbose:
                    print(f"ignored malformed TZSP packet from {mirror[0]}:{mirror[1]}: {exc}", file=sys.stderr)
                continue

            if packet is None:
                continue
            counters.inner_tcp_segments += 1

            if packet.dst_port != args.tcp_port:
                continue
            if args.grill_ip and packet.src_ip != args.grill_ip:
                continue
            counters.matching_tcp_segments += 1

            key = packet.stream_key
            stream = streams.setdefault(key, TCPStream())
            previous_gaps = stream.gaps
            stream.append(packet)
            if stream.gaps != previous_gaps:
                counters.stream_gaps += 1
                if args.verbose:
                    print(f"TCP capture gap on {key}; resynchronising on next a33a header", file=sys.stderr)

            for frame in pull_g32_frames(stream.buffer, expected_device_id):
                decoded = decode_g32_frame(
                    frame,
                    tare_weight_g=args.tare_weight_g,
                    local_timezone=local_timezone,
                    include_raw=args.rawframe,
                    include_unknown=args.verbose,
                )
                event = make_event(
                    decoded,
                    packet,
                    mirror,
                    include_network_metadata=args.verbose,
                )
                last_frame_monotonic = time.monotonic()
                last_offline_publish_monotonic = None
                offline_since_utc = None
                last_online_event = event
                dispatch_event(event, args, latest_json, mqtt_publisher)
                counters.decoded_frames += 1

            if packet.flags & (TCP_FIN | TCP_RST):
                streams.pop(key, None)

    except KeyboardInterrupt:
        pass
    finally:
        if mqtt_publisher is not None:
            mqtt_publisher.close()
        if http_exporter is not None:
            http_exporter.close()
        sock.close()
        print(
            "Stopped: "
            f"tzsp={counters.tzsp_datagrams} "
            f"inner_tcp={counters.inner_tcp_segments} "
            f"matching_tcp={counters.matching_tcp_segments} "
            f"frames={counters.decoded_frames} "
            f"offline_events={counters.offline_events} "
            f"gaps={counters.stream_gaps} "
            f"malformed={counters.malformed_datagrams}",
            file=sys.stderr,
        )
    return 0


def main(argv: list[str] | None = None) -> int:
    command_line = sys.argv[1:] if argv is None else argv

    # Read the config path first so its values can become argparse defaults.
    # Normal command-line options are parsed afterwards and therefore win.
    config_probe = argparse.ArgumentParser(add_help=False)
    config_probe.add_argument("--config")
    config_probe.add_argument("--mqtt-config")
    config_args, _ = config_probe.parse_known_args(command_line)

    if config_args.config and config_args.mqtt_config:
        build_parser().error("--config and --mqtt-config cannot be used together")

    config_path = config_args.config or config_args.mqtt_config
    config_defaults: dict[str, Any] = {}
    if config_path and not ({"-h", "--help"} & set(command_line)):
        try:
            config_defaults = load_config(config_path)
        except ValueError as exc:
            build_parser().error(str(exc))

    parser = build_parser(config_defaults)
    args = parser.parse_args(command_line)
    # The password has deliberately no command-line option, so it never
    # appears in argv or ps output. The existing environment fallback remains.
    args.mqtt_password = config_defaults.get("mqtt_password")

    def command_line_has(option: str) -> bool:
        return any(value == option or value.startswith(f"{option}=") for value in command_line)

    # Compatibility with releases that used the presence of --http-port or
    # --mqtt-host to enable an exporter, and with the former MQTT-only config.
    # A configured or command-line --[no-]*-enabled value always wins.
    if args.http_enabled is None:
        args.http_enabled = command_line_has("--http-port")
    if args.mqtt_enabled is None:
        args.mqtt_enabled = command_line_has("--mqtt-host") or bool(
            config_args.mqtt_config and args.mqtt_host
        )

    if not (1 <= args.port <= 65535):
        parser.error("--port must be between 1 and 65535")
    if not (1 <= args.tcp_port <= 65535):
        parser.error("--tcp-port must be between 1 and 65535")
    if not (1 <= args.http_port <= 65535):
        parser.error("--http-port must be between 1 and 65535")
    if not args.http_path.startswith("/"):
        parser.error("--http-path must start with /")
    if not (1 <= args.mqtt_port <= 65535):
        parser.error("--mqtt-port must be between 1 and 65535")
    if args.mqtt_qos not in (0, 1, 2):
        parser.error("--mqtt-qos must be 0, 1, or 2")
    if args.offline_after <= 0:
        parser.error("--offline-after must be greater than zero")
    if not args.mqtt_topic:
        parser.error("--mqtt-topic cannot be empty")
    if args.mqtt_availability_topic == args.mqtt_topic:
        parser.error("--mqtt-availability-topic must differ from --mqtt-topic")
    if not args.mqtt_client_id:
        parser.error("--mqtt-client-id cannot be empty")
    if args.mqtt_enabled and not args.mqtt_host:
        parser.error("MQTT is enabled but no broker host is configured")
    if args.mqtt_enabled and args.mqtt_password is not None and not args.mqtt_username:
        parser.error("[mqtt] password requires an MQTT username")
    if args.tare_weight_g is not None and args.tare_weight_g < 0:
        parser.error("--tare-weight-g cannot be negative")

    try:
        local_timezone = ZoneInfo(args.timezone)
    except ZoneInfoNotFoundError:
        parser.error(f"unknown timezone: {args.timezone}")

    if args.self_test:
        return run_self_test(args, local_timezone)
    try:
        return listen(args, local_timezone)
    except (OSError, RuntimeError) as exc:
        parser.error(str(exc))


if __name__ == "__main__":
    raise SystemExit(main())
