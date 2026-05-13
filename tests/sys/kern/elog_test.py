#
# Copyright (c) 2026 Netflix, Inc.
#
# SPDX-License-Identifier: BSD-2-Clause
#

"""End-to-end ATF tests for the elog(1) userspace utility.

Validates the full path: elog binary -> /dev/eventlog -> kernel eventlog
framework. Complements kern_eventlog_test (which exercises kernel-internal
APIs via a ktest module) by covering the real character-device + IOCTL
surface.

Most cases require root because /dev/eventlog rejects jailed callers
(kern_eventlog.c eventlog_dev_open) and the CREATE IOCTL needs to allocate
per-CPU buffers.
"""

import os
import socket
import struct
import subprocess
import time
from collections import namedtuple
from contextlib import contextmanager
from pathlib import Path

import pytest
from atf_python.utils import BaseTest

ELOG = "/usr/bin/elog"
EVENTLOG_DEV = "/dev/eventlog"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _sysctl_get(name):
    """Return the current value of sysctl `name` as a string, or None if
    the OID does not exist."""
    r = subprocess.run(
        ["sysctl", "-n", name],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if r.returncode != 0:
        return None
    return r.stdout.decode().strip()


def _sysctl_set(name, value):
    """Set sysctl `name` to `value`. Raises CalledProcessError on failure."""
    subprocess.run(
        ["sysctl", f"{name}={value}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
        check=True)


@contextmanager
def sysctl_override(name, value):
    """Save current value of sysctl `name`, set it to `value`, then
    restore on exit. Skips the test if the OID is missing or the new
    value is rejected."""
    old = _sysctl_get(name)
    if old is None:
        pytest.skip(f"sysctl {name} not present")
    try:
        _sysctl_set(name, value)
    except subprocess.CalledProcessError as e:
        pytest.skip(f"cannot set {name}={value}: "
                    f"{e.stderr.decode().strip()}")
    try:
        yield old
    finally:
        # Restore unconditionally; ignore errors so cleanup can't mask
        # the original assertion failure.
        subprocess.run(
            ["sysctl", f"{name}={old}"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)


def _require_eventlog_dev():
    if not Path(EVENTLOG_DEV).is_char_device():
        pytest.skip(f"{EVENTLOG_DEV} not present")


def _pick_port(salt=0):
    """Pseudo-random high port; deterministic across reruns of the same
    pytest invocation but varies with the test process."""
    return 20000 + ((os.getpid() + salt) % 30000)


def _addr_for(family):
    return "::1" if family == socket.AF_INET6 else "127.0.0.1"


@contextmanager
def loopback_pair(family, port, linger0=False):
    """Open a listener+connected client pair on `(addr, port)` over loopback,
    yield (server-accepted-conn, client) sockets, and close all three on
    exit. Returns once the three-way handshake has completed (accept()
    returns).

    If linger0=True, the client is configured with SO_LINGER {1, 0} so
    that close() emits a TCP RST and the PCB is reclaimed immediately
    instead of going through TIME_WAIT.
    """
    addr = _addr_for(family)
    srv = socket.socket(family, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cli = socket.socket(family, socket.SOCK_STREAM)
    if linger0:
        # struct linger { int l_onoff; int l_linger; }
        cli.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                       struct.pack("ii", 1, 0))
    conn = None
    try:
        srv.bind((addr, port))
        srv.listen(1)
        cli.connect((addr, port))
        conn, _ = srv.accept()
        yield conn, cli
    finally:
        for s in (conn, cli, srv):
            if s is not None:
                try:
                    s.close()
                except OSError:
                    pass


def loopback_oneshot(family, port, payload):
    """Drive a one-shot TCP loopback exchange and return what the server
    received. Closes both ends before returning."""
    addr = _addr_for(family)
    with socket.socket(family, socket.SOCK_STREAM) as srv:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((addr, port))
        srv.listen(1)
        with socket.socket(family, socket.SOCK_STREAM) as cli:
            cli.connect((addr, port))
            conn, _ = srv.accept()
            try:
                cli.sendall(payload)
                cli.shutdown(socket.SHUT_WR)
                data = b""
                while True:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                return data
            finally:
                conn.close()


@contextmanager
def elog_capture(*args, capture_path=None):
    """Start `elog -s [args] [-o capture_path]` in the background. The
    caller supplies all `-c <provider>` subscriptions and any other
    flags. If `capture_path` is None no `-o` is passed (live text mode
    on stdout). Yields the Popen handle. Sends SIGTERM and reaps on
    exit; asserts a clean (rc=0) shutdown.
    """
    cmd = [ELOG, "-s", *args]
    if capture_path is not None:
        cmd += ["-o", str(capture_path)]
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # Give elog a tick to issue CREATE/GET_PROVIDERS before the caller
    # drives traffic.
    time.sleep(1)
    if proc.poll() is not None:
        err = proc.stderr.read().decode()
        raise AssertionError(f"elog exited early: {err}")
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            _, err = proc.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            _, err = proc.communicate()
        if proc.returncode != 0:
            raise AssertionError(
                f"elog exited rc={proc.returncode}; "
                f"stderr={err.decode()}")


def decode_capture(path):
    """Run `elog -e -r <path>` and return its stdout."""
    return subprocess.check_output(
        [ELOG, "-e", "-r", str(path)], text=True)


def decode_capture_or_empty(path):
    """Like decode_capture, but if the binary capture file is 0 bytes
    (no events were ever recorded, so elog never wrote the header)
    return "". elog(1) rejects an empty file with `bad magic number`,
    which is correct behaviour for replay but is not a test failure
    when we deliberately set up a filter that drops every event.
    """
    if Path(path).stat().st_size == 0:
        return ""
    return decode_capture(path)


def _assert_in_decode(decoded, needle, label, *, head_chars=2000):
    """Assert that `needle` is a substring of `decoded`. On failure include
    the head of the decoded text so the failure is self-debugging in the
    kyua report."""
    if needle in decoded:
        return
    pytest.fail(
        f"{label}: missing literal {needle!r} in decoded capture\n"
        f"--- decoded.txt (first {head_chars} chars) ---\n"
        f"{decoded[:head_chars]}\n--- end ---")


# ---------------------------------------------------------------------------
# elog binary-format decoder (in-process, no fork to elog -r)
# ---------------------------------------------------------------------------
#
# On-disk layout (host byte order; we use "<" for amd64):
#
#   elog_binary_header (40 bytes, __packed):
#     char     magic[4]       == "ELOG"
#     uint32_t version        == 1
#     uint64_t capture_start  microseconds since boot at capture start
#     uint64_t start_utc_us   wall-clock UTC microseconds at capture start
#     uint64_t event_count    total events written
#     uint64_t dropped_events events dropped (kernel buffer overflow)
#
#   uint32_t provider_count
#   provider_count x eventlog_provider_info (34 bytes, __packed):
#     uint16_t provider_id
#     char     name[EVENTLOG_PROVIDER_NAME_MAX = 32]
#
#   stream of:
#     eventlog_event_header (32 bytes, naturally aligned, no padding):
#       uint16_t event_length     total record size including header
#       uint16_t cpu
#       uint16_t provider_id
#       uint16_t RESERVED
#       uint64_t timestamp        microseconds since boot
#       uint64_t session_id
#       uint32_t event_id
#       int32_t  thread_id
#     payload                     event_length - 32 bytes
#
# References:
#   FreeBSD/usr.bin/elog/elog.c    elog_binary_header / write_binary_event
#   FreeBSD/sys/sys/eventlog_subscriber.h
#                                 eventlog_event_header / eventlog_provider_info
#   FreeBSD/include/eventlog/tcp_eventlog_schema.src
#                                 STRUCT layouts for payload parsing

ELOG_BINARY_MAGIC = b"ELOG"
ELOG_BINARY_VERSION = 1
EVENTLOG_PROVIDER_NAME_MAX = 32

# Framework-reserved event IDs (FreeBSD/sys/sys/eventlog.h).
EVENTLOG_SESSION_CREATE_ID = 0xFFFFFFFE
EVENTLOG_SESSION_END_ID = 0xFFFFFFFF

# tcp provider event IDs (tcp_eventlog_schema.src).
TCP_EVENT_CONN_SET_IP_V4 = 0
TCP_EVENT_CONN_SET_IP_V6 = 1
TCP_EVENT_CONN_PARAMS = 3
TCP_EVENT_MSS = 4
TCP_EVENT_IN = 100
TCP_EVENT_OUT = 101

ELOG_BINARY_HEADER_FMT = "<4sIQQQQ"
ELOG_BINARY_HEADER_SIZE = struct.calcsize(ELOG_BINARY_HEADER_FMT)  # 40
ELOG_PROVIDER_INFO_FMT = f"<H{EVENTLOG_PROVIDER_NAME_MAX}s"
ELOG_PROVIDER_INFO_SIZE = struct.calcsize(ELOG_PROVIDER_INFO_FMT)  # 34
ELOG_EVENT_HEADER_FMT = "<HHHHQQIi"
ELOG_EVENT_HEADER_SIZE = struct.calcsize(ELOG_EVENT_HEADER_FMT)    # 32
assert ELOG_BINARY_HEADER_SIZE == 40
assert ELOG_PROVIDER_INFO_SIZE == 34
assert ELOG_EVENT_HEADER_SIZE == 32

ElogFileHeader = namedtuple(
    "ElogFileHeader",
    "capture_start start_utc_us event_count dropped_events")
ElogEventHeader = namedtuple(
    "ElogEventHeader",
    "event_length cpu provider_id timestamp session_id event_id thread_id")


def parse_elog_binary(path):
    """Parse a complete elog binary capture file. Returns a tuple
    `(file_header, providers_by_id, events)` where:
      file_header        ElogFileHeader
      providers_by_id    dict[int -> str], e.g. {1: "tcp"}
      events             list of (ElogEventHeader, payload_bytes)

    Raises AssertionError on any structural problem (bad magic,
    truncated event, payload-size mismatch with the recorded
    event_length, etc.).
    """
    data = Path(path).read_bytes()
    off = 0

    if len(data) < ELOG_BINARY_HEADER_SIZE:
        raise AssertionError(
            f"capture {path!s}: only {len(data)} bytes, "
            f"need ≥{ELOG_BINARY_HEADER_SIZE} for the file header")
    (magic, version, capture_start, start_utc_us, event_count,
        dropped_events) = struct.unpack_from(
            ELOG_BINARY_HEADER_FMT, data, off)
    off += ELOG_BINARY_HEADER_SIZE
    if magic != ELOG_BINARY_MAGIC:
        raise AssertionError(
            f"capture {path!s}: bad magic {magic!r} "
            f"(expected {ELOG_BINARY_MAGIC!r})")
    if version != ELOG_BINARY_VERSION:
        raise AssertionError(
            f"capture {path!s}: bad version {version} "
            f"(expected {ELOG_BINARY_VERSION})")
    file_hdr = ElogFileHeader(
        capture_start=capture_start, start_utc_us=start_utc_us,
        event_count=event_count, dropped_events=dropped_events)

    if off + 4 > len(data):
        raise AssertionError(
            f"capture {path!s}: truncated before provider_count")
    (prov_count,) = struct.unpack_from("<I", data, off)
    off += 4
    # The kernel's EVENTLOG_MAX_PROVIDERS is 32; a value above that
    # signals a corrupt header.
    if prov_count > 32:
        raise AssertionError(
            f"capture {path!s}: implausible provider_count={prov_count}")
    providers = {}
    for i in range(prov_count):
        if off + ELOG_PROVIDER_INFO_SIZE > len(data):
            raise AssertionError(
                f"capture {path!s}: truncated provider entry {i}")
        prov_id, name_bytes = struct.unpack_from(
            ELOG_PROVIDER_INFO_FMT, data, off)
        off += ELOG_PROVIDER_INFO_SIZE
        name = name_bytes.split(b"\0", 1)[0].decode("ascii")
        providers[prov_id] = name

    events = []
    while off < len(data):
        if off + ELOG_EVENT_HEADER_SIZE > len(data):
            raise AssertionError(
                f"capture {path!s}: trailing partial event header "
                f"at off={off} (remaining={len(data) - off})")
        (event_length, cpu, provider_id, _reserved, timestamp,
            session_id, event_id, thread_id) = struct.unpack_from(
                ELOG_EVENT_HEADER_FMT, data, off)
        if event_length < ELOG_EVENT_HEADER_SIZE:
            raise AssertionError(
                f"capture {path!s}: event_length {event_length} "
                f"< header size {ELOG_EVENT_HEADER_SIZE} at off={off}")
        if off + event_length > len(data):
            raise AssertionError(
                f"capture {path!s}: event at off={off} runs past EOF "
                f"(event_length={event_length}, "
                f"remaining={len(data) - off})")
        payload = bytes(data[off + ELOG_EVENT_HEADER_SIZE:
                             off + event_length])
        events.append((
            ElogEventHeader(
                event_length=event_length, cpu=cpu,
                provider_id=provider_id, timestamp=timestamp,
                session_id=session_id, event_id=event_id,
                thread_id=thread_id),
            payload,
        ))
        off += event_length

    return file_hdr, providers, events


def parse_session_create_payload(payload):
    """SESSION_CREATE payload (from STRUCT SESSION_CREATE in
    tcp_eventlog_schema.src):
        void *tp;        // 8 bytes on amd64, naturally aligned
    """
    if len(payload) != 8:
        raise AssertionError(
            f"SESSION_CREATE payload size {len(payload)} != 8")
    (tp,) = struct.unpack("<Q", payload)
    return {"tp": tp}


def parse_conn_set_ip_v4_payload(payload):
    """CONN_SET_IP_V4 payload (from STRUCT CONN_SET_IP_V4 in
    tcp_eventlog_schema.src), with C natural alignment:
        struct in_addr src_addr;  // 4 bytes (network byte order)
        uint16_t       src_port;  // 2 bytes (network byte order)
        // 2 bytes padding so the next in_addr is 4-byte aligned
        struct in_addr dst_addr;  // 4 bytes
        uint16_t       dst_port;  // 2 bytes
        // 2 bytes trailing padding so sizeof rounds up to 16
    """
    if len(payload) != 16:
        raise AssertionError(
            f"CONN_SET_IP_V4 payload size {len(payload)} != 16")
    src_addr_bytes = payload[0:4]
    (src_port_n,) = struct.unpack_from("<H", payload, 4)
    dst_addr_bytes = payload[8:12]
    (dst_port_n,) = struct.unpack_from("<H", payload, 12)
    return {
        # in_addr stores the address in network byte order; the raw
        # 4 bytes are exactly what inet_ntoa expects.
        "src_addr": socket.inet_ntoa(src_addr_bytes),
        "dst_addr": socket.inet_ntoa(dst_addr_bytes),
        "src_port": socket.ntohs(src_port_n),
        "dst_port": socket.ntohs(dst_port_n),
    }


# ---------------------------------------------------------------------------
# CLI smoke tests (no kernel touch)
# ---------------------------------------------------------------------------


class TestElogCli(BaseTest):
    """Cheap smoke tests for the elog binary CLI surface. These catch
    packaging regressions (missing binary, broken option parser) without
    needing /dev/eventlog or the kernel framework to be functional."""

    @pytest.mark.require_progs(["elog"])
    def test_help(self):
        # usage() in elog.c calls exit(1), so -h is expected to fail.
        for flag in ("-h", "--help"):
            r = subprocess.run(
                [ELOG, flag], capture_output=True, text=True)
            assert r.returncode == 1, f"elog {flag} returncode"
            assert "usage: elog" in r.stderr, f"elog {flag} stderr"

    @pytest.mark.require_progs(["elog"])
    def test_no_args(self):
        r = subprocess.run([ELOG], capture_output=True, text=True)
        assert r.returncode == 1
        assert "no subscriptions specified" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_unknown_arg(self):
        r = subprocess.run(
            [ELOG, "--not-a-real-flag"], capture_output=True, text=True)
        assert r.returncode == 1
        assert "unknown argument" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_read_missing_file(self, tmp_path):
        target = tmp_path / "does-not-exist.elog"
        r = subprocess.run(
            [ELOG, "-r", str(target)], capture_output=True, text=True)
        assert r.returncode == 1
        assert "fopen" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_read_invalid_magic(self, tmp_path):
        # 64 zero bytes is enough to satisfy the initial header read but
        # fails the ELOG_BINARY_MAGIC check.
        bogus = tmp_path / "bogus.elog"
        bogus.write_bytes(b"\0" * 64)
        r = subprocess.run(
            [ELOG, "-r", str(bogus)], capture_output=True, text=True)
        assert r.returncode == 1
        assert "bad magic number" in r.stderr


# ---------------------------------------------------------------------------
# Tests that touch /dev/eventlog and the tcp eventlog provider
# ---------------------------------------------------------------------------


class TestElogCapture(BaseTest):
    """End-to-end coverage: elog -> /dev/eventlog -> kernel framework.

    Most of these pin net.inet.tcp.functions_default to "freebsd" for
    the duration of the test. Eventlog wiring is per-stack
    (tfb_eventlog_provider on the function-block); pinning to a stack
    that is known to register the tcp eventlog provider keeps the
    tests deterministic regardless of which stack the host happens to
    have configured by default. Cases that need a different stack
    skip cleanly if that stack is not available on the running image
    (sysctl_override -> pytest.skip).
    """

    NEED_ROOT = True

    @pytest.mark.require_user("root")
    def test_dev_eventlog_present(self):
        # Sanity: /dev/eventlog should exist as a character device on any
        # kernel with the eventlog framework compiled in.
        assert Path(EVENTLOG_DEV).is_char_device(), (
            f"{EVENTLOG_DEV} not a character device")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_tcp_brief(self, tmp_path):
        """elog -c tcp subscribes, captures briefly with no traffic, and
        exits cleanly on SIGTERM."""
        _require_eventlog_dev()
        capture = tmp_path / "capture.elog"
        # No traffic; the SIGTERM handler in elog.c sets done=true and
        # the read loop returns 0 from main().
        with elog_capture("-c", "tcp", capture_path=capture) as elog:
            time.sleep(1)
        # Stats output goes to stderr in a "[Stats]\n  Providers: N" block.
        # A successful subscribe always discovers at least one provider.
        # (The elog_capture context manager already asserted rc==0.)
        # We don't validate stats stderr here; the capture context manager
        # would have raised if elog died.
        assert elog.returncode == 0

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    @pytest.mark.parametrize(
        "stack,family",
        [
            pytest.param("freebsd", socket.AF_INET, id="freebsd_inet"),
            pytest.param("freebsd", socket.AF_INET6, id="freebsd_inet6"),
        ],
    )
    def test_capture_tcp_loopback(self, tmp_path, stack, family):
        """Drive a loopback TCP exchange under the given stack and family,
        then verify the captured eventlog contains the events we expect."""
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port()
        payload = b"ping over loopback\n"

        with sysctl_override("net.inet.tcp.functions_default", stack), \
             sysctl_override("kern.eventlog.tcp.default", "1"):

            sessions_created_before = int(_sysctl_get(
                "kern.eventlog.tcp.sessions_created"))

            with elog_capture("-c", "tcp", capture_path=capture):
                # One-shot loopback exchange. Python's socket module
                # makes the handshake/teardown deterministic - no nc
                # process to wait for, no sockstat polling.
                received = loopback_oneshot(family, port, payload)
                assert payload.rstrip(b"\n") in received

                # Let the kernel push remaining events and elog drain
                # its read (the read path's tsleep also has a 1Hz timer).
                time.sleep(2)

            sessions_created_after = int(_sysctl_get(
                "kern.eventlog.tcp.sessions_created"))

        # If no new sessions were created, downstream content assertions
        # are meaningless.
        assert sessions_created_after > sessions_created_before, (
            f"no new tcp sessions during exchange "
            f"(stack={stack}, family={family.name})")

        # --- Decode and validate ---
        decoded = decode_capture(capture)
        assert decoded.strip(), "decoded capture is empty"

        if family == socket.AF_INET6:
            ipver_label = "IPv6 connection"
            loop_addr = "::1"
        else:
            ipver_label = "IPv4 connection"
            loop_addr = "127.0.0.1"

        # Each tuple is (substring, human label). On failure the helper
        # dumps the head of the decoded capture.
        expectations = [
            ("[tcp]",                      "tcp provider tag"),
            ("[SESSION_CREATE]",           "SESSION_CREATE event"),
            ("[SESSION_END]",              "SESSION_END event"),
            (ipver_label,                  f"{ipver_label} literal"),
            (loop_addr,                    f"loopback addr {loop_addr}"),
            (str(port),                    f"chosen port {port}"),
            ("Connection parameters: ISS", "CONN_PARAMS event"),
            ("MSS set to",                 "MSS event"),
            ("[IN]",                       "[IN] data event"),
            ("[OUT]",                      "[OUT] data event"),
            ("flags SYN",                  "SYN-bearing segment"),
            ("in state ESTABLISHED",       "ESTABLISHED-state IN event"),
        ]
        for needle, label in expectations:
            _assert_in_decode(decoded, needle, label)

        # Binary file format integrity: decoding twice must produce
        # byte-identical output. Catches non-deterministic decode bugs
        # (stale reader state, miscomputed offsets, etc.).
        decoded2 = decode_capture(capture)
        assert decoded == decoded2, "elog -r is not deterministic"

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_tcp_dump_state(self, tmp_path):
        """Validate the elog -D (DUMP_STATE) flow.

        Open a tcp connection BEFORE subscribing, then run elog with -D.
        The CREATE IOCTL invokes tcp_eventlog_dump_state inline on this
        thread; the callback walks every TCP PCB and re-emits
        SESSION_CREATE / CONN_SET_IP_V4 / CONN_PARAMS for each
        enabled session. This exercises a meaningfully different code
        path from test_capture_tcp_loopback (where the subscriber
        attaches first and events flow live).
        """
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=1)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):

            # Stand up a long-lived loopback connection FIRST so its
            # session pre-exists when elog subscribes.
            with loopback_pair(socket.AF_INET, port):
                # Subscribe with -D. The dump callback fires inline.
                with elog_capture("-c", "tcp", "-D",
                                  capture_path=capture):
                    # Give elog time to drain the dumped events.
                    time.sleep(2)

        decoded = decode_capture(capture)
        assert decoded.strip(), "decoded capture is empty"

        for needle, label in (
            ("[SESSION_CREATE]", "SESSION_CREATE in dump"),
            ("IPv4 connection",  "CONN_SET_IP_V4 in dump"),
            ("127.0.0.1",        "loopback addr in dump"),
            (str(port),          f"port {port} in dump"),
            ("Connection parameters: ISS", "CONN_PARAMS in dump"),
            (", MSS ",           "MSS field of CONN_PARAMS in dump"),
        ):
            _assert_in_decode(decoded, needle, label)

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_tcp_mass_enable_disable(self, tmp_path):
        """Validate kern.eventlog.tcp.default=2 / -1 transitions.

        Writing 2 means "enable all currently-disabled sessions"; -1
        means "disable all currently-active sessions". Plain 0/1
        transitions only affect future sessions and are covered by
        test_capture_tcp_loopback. The 2/-1 path runs through
        tcp_eventlog_default_changed and eventlog_provider_set_all_sessions
        and otherwise has no end-to-end coverage.

        Strategy: open a long-lived nc-equivalent pair under default=0
        (sessions come up disabled), snapshot sessions_enabled, flip
        default=2 and assert it rose, drive a side connection so we can
        confirm events actually flow under default=2, flip default=-1
        and assert sessions_enabled fell. Counter deltas are robust
        against background tcp activity on the test image.
        """
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=2)
        side_port = _pick_port(salt=3)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "0"):

            with elog_capture("-c", "tcp", capture_path=capture):
                # Long-lived holding pair. Sessions come up disabled
                # because default=0 at the moment they're created.
                with loopback_pair(socket.AF_INET, port):
                    enabled_before = int(_sysctl_get(
                        "kern.eventlog.tcp.sessions_enabled"))

                    # === Phase 1: mass enable ===
                    _sysctl_set("kern.eventlog.tcp.default", "2")
                    enabled_after_enable = int(_sysctl_get(
                        "kern.eventlog.tcp.sessions_enabled"))
                    assert enabled_after_enable > enabled_before, (
                        f"default=2 did not raise sessions_enabled: "
                        f"{enabled_before} -> {enabled_after_enable}")

                    # Drive a side exchange while logging is on so the
                    # capture has observable events for that connection.
                    loopback_oneshot(socket.AF_INET, side_port,
                                     b"mass-enable phase\n")
                    time.sleep(1)

                    # === Phase 2: mass disable ===
                    _sysctl_set("kern.eventlog.tcp.default", "-1")
                    enabled_after_disable = int(_sysctl_get(
                        "kern.eventlog.tcp.sessions_enabled"))
                    assert enabled_after_disable < enabled_after_enable, (
                        f"default=-1 did not lower sessions_enabled: "
                        f"{enabled_after_enable} -> {enabled_after_disable}")

                    # Brief drain before the holding pair tears down.
                    time.sleep(1)

        decoded = decode_capture(capture)
        assert decoded.strip(), "decoded capture is empty"

        # The phase-1 side connection was opened *while* default=2 was in
        # effect, so its sessions started enabled and emitted normal
        # events. We expect SESSION_CREATE plus IN/OUT for that port.
        for needle, label in (
            (str(side_port),     f"side connection port {side_port}"),
            ("[SESSION_CREATE]", "SESSION_CREATE in capture"),
            ("IPv4 connection",  "CONN_SET_IP_V4 in capture"),
            ("[IN]",             "[IN] events in capture"),
            ("[OUT]",            "[OUT] events in capture"),
        ):
            _assert_in_decode(decoded, needle, label)

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    @pytest.mark.parametrize(
        "keyword,expected_present,expected_absent",
        [
            pytest.param("RX", "[IN]", "[OUT]", id="RX_only"),
            pytest.param("TX", "[OUT]", "[IN]", id="TX_only"),
        ],
    )
    def test_capture_tcp_keyword_filter(
            self, tmp_path, keyword, expected_present, expected_absent):
        """Validate `-c tcp <level> <keyword>` keyword filtering.

        IN events are tagged with the RX keyword and OUT events with
        TX (see tcp_eventlog_schema.src). A subscription that
        specifies only RX must produce IN events but no OUT events,
        and vice versa. SESSION_CREATE/SESSION_END are tagged with
        the framework-reserved SESSION keyword which elog(1)
        unconditionally OR's into every subscription, so those still
        appear regardless of the user-specified keyword mask.
        """
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=20)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", "VERBOSE", keyword,
                              capture_path=capture):
                loopback_oneshot(socket.AF_INET, port,
                                 b"keyword-filter\n")
                time.sleep(2)

        decoded = decode_capture(capture)
        assert decoded.strip(), "decoded capture is empty"

        _assert_in_decode(
            decoded, expected_present,
            f"keyword={keyword}: {expected_present} should be present")
        if expected_absent in decoded:
            pytest.fail(
                f"keyword={keyword}: {expected_absent!r} should be "
                f"filtered out but is present in capture\n"
                f"--- decoded.txt (first 2000 chars) ---\n"
                f"{decoded[:2000]}\n--- end ---")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_tcp_level_filter(self, tmp_path):
        """Validate `-c tcp <level>` level filtering.

        Subscribing at ERROR (level=1) requests only events at level
        ERROR or below. All TCP events on a clean exchange are at
        INFO/VERBOSE/TRACE level (see tcp_eventlog_schema.src), so the
        capture must contain none of the normal lifecycle events.
        Compared to a TRACE subscription over the same workload,
        which produces dozens of events.

        Note: when the level filter drops every event the capture
        file is 0 bytes (elog only writes the binary header lazily,
        on the first event). decode_capture_or_empty handles that.
        """
        _require_eventlog_dev()

        port_low = _pick_port(salt=21)
        port_high = _pick_port(salt=22)

        capture_low = tmp_path / "capture-error.elog"
        capture_high = tmp_path / "capture-trace.elog"

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):

            # Pass A: ERROR level - clean traffic should produce no
            # tcp lifecycle/data events at this filter level.
            with elog_capture("-c", "tcp", "ERROR",
                              capture_path=capture_low):
                loopback_oneshot(socket.AF_INET, port_low,
                                 b"level-error\n")
                time.sleep(2)

            # Pass B: TRACE level - same traffic, full event stream.
            with elog_capture("-c", "tcp", "TRACE",
                              capture_path=capture_high):
                loopback_oneshot(socket.AF_INET, port_high,
                                 b"level-trace\n")
                time.sleep(2)

        decoded_low = decode_capture_or_empty(capture_low)
        decoded_high = decode_capture(capture_high)

        # ERROR pass must not contain any of the normal INFO/VERBOSE
        # events. We test for [IN] and [OUT] (VERBOSE) plus
        # CONN_SET_IP_V4's literal output (INFO). All three are absent
        # at ERROR level. (Empty capture trivially satisfies this.)
        for needle in ("[IN]", "[OUT]", "IPv4 connection"):
            if needle in decoded_low:
                pytest.fail(
                    f"level=ERROR capture should not contain "
                    f"{needle!r} but does\n"
                    f"--- decoded-error.txt (first 2000 chars) ---\n"
                    f"{decoded_low[:2000]}\n--- end ---")

        # TRACE pass must contain the full event stream for the same
        # workload. This proves the level filter actually filters
        # (rather than the test's traffic being silently broken).
        for needle, label in (
            ("[IN]",            "[IN] in TRACE capture"),
            ("[OUT]",           "[OUT] in TRACE capture"),
            ("IPv4 connection", "CONN_SET_IP_V4 in TRACE capture"),
        ):
            _assert_in_decode(decoded_high, needle, label)

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_per_session_output_dir(self, tmp_path):
        """Validate `-o dir=PATH -f tcp` per-session output mode.

        elog supports splitting captured events into one binary file
        per session, named by TCP four-tuple when -f tcp is set:
            <log_id>_<local_port>_<remote_ip>_<remote_port>.elog
        This is the operational mode used to debug a single
        connection in the field.

        Drive two distinct loopback connections, then assert:
          1) the output dir is created
          2) at least one per-session file is created for each
             connection (matching the chosen port)
          3) every per-session file decodes successfully and contains
             a SESSION_CREATE event for its session
        """
        _require_eventlog_dev()

        out_dir = tmp_path / "split"
        port_a = _pick_port(salt=30)
        port_b = _pick_port(salt=31)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", "-f", "tcp",
                              "-o", f"dir={out_dir}"):
                # Two distinct connections so we can assert both
                # ports appear in the per-session filenames.
                for port in (port_a, port_b):
                    loopback_oneshot(socket.AF_INET, port,
                                     b"per-session\n")
                time.sleep(2)

        assert out_dir.is_dir(), \
            f"elog did not create output dir {out_dir}"

        files = sorted(out_dir.glob("*.elog"))
        assert files, f"no per-session files under {out_dir}"

        names = [f.name for f in files]
        for port in (port_a, port_b):
            matches = [n for n in names if str(port) in n]
            assert matches, (
                f"no per-session file mentions port {port}; "
                f"got: {names}")

        # Every per-session file must be a valid binary capture and
        # contain a SESSION_CREATE event for the session it represents.
        for path in files:
            decoded = decode_capture(path)
            _assert_in_decode(
                decoded, "[SESSION_CREATE]",
                f"{path.name}: SESSION_CREATE in per-session file")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_sessions_active_no_leak(self):
        """Open and close N TCP loopback pairs; sessions_active must
        return to its baseline. Catches PCB-side eventlog session
        lifecycle leaks (a destroyed PCB whose session record never
        gets freed would inflate sessions_active monotonically).

        We use SO_LINGER {1, 0} on the client so close() emits a TCP
        RST and the kernel reclaims both PCBs immediately, avoiding
        TIME_WAIT and keeping the test runtime bounded.
        """
        _require_eventlog_dev()

        N = 10

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):

            # Settle for a moment then sample baseline. The test image
            # has sshd, possibly other tcp sessions; we tolerate small
            # drift.
            time.sleep(1)
            baseline = int(_sysctl_get(
                "kern.eventlog.tcp.sessions_active"))

            # Each iteration creates exactly two enabled tcp sessions
            # (one per PCB) and immediately destroys both via RST.
            for i in range(N):
                with loopback_pair(socket.AF_INET,
                                   _pick_port(salt=40 + i),
                                   linger0=True):
                    pass

            # Give the kernel a moment to reclaim PCBs and drain any
            # SESSION_END processing.
            time.sleep(2)

            final = int(_sysctl_get(
                "kern.eventlog.tcp.sessions_active"))

        delta = final - baseline
        # A real leak shows up as delta >= 2*N (one session per PCB,
        # two PCBs per pair). Tolerate small ambient growth (e.g.,
        # the test runner's own ssh shell churning) up to N - this
        # is well below the 2*N a leak would produce.
        assert delta < N, (
            f"tcp eventlog sessions_active leak: "
            f"baseline={baseline} -> final={final} "
            f"(delta={delta}, opened={N} pairs)")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_tcp_binary_format(self, tmp_path):
        """Validate the on-disk binary capture format end-to-end by
        decoding it directly in Python (no `elog -r` round-trip).

        `elog -r` is forgiving about its own output: it could trade
        layouts back and forth without anyone noticing. Real
        consumers of the binary stream - external collectors, custom
        analyzers, off-host tooling - aren't, and any change to the
        record layout, header struct, or framework-emitted events is
        an ABI change for them. Parsing the file with a hand-written
        Python decoder catches those changes immediately.

        Asserts on the binary file directly:
          - elog_binary_header magic / version / start_utc_us / counts
            are sane and self-consistent (event_count matches the
            number of records actually walked, dropped_events=0).
          - Provider map contains the tcp provider id.
          - Each event header has provider_id matching the tcp
            provider, event_length is plausible (>= header,
            <= a generous max), and the recorded payload size
            agrees with event_length - sizeof(header).
          - Per-session timestamps are monotonically non-decreasing
            within the same session_id.
          - Loopback creates two PCBs (client + server) so we expect
            >= 2 distinct session_ids that each transit
            SESSION_CREATE -> ... -> SESSION_END, with at least one
            CONN_SET_IP_V4, MSS, and one of IN/OUT in between.
          - SESSION_CREATE payload is exactly 8 bytes (void *tp)
            and tp is non-zero (real PCB pointer from the kernel).
          - CONN_SET_IP_V4 payload is exactly 16 bytes and decodes
            to (127.0.0.1, port, 127.0.0.1, port) for the loopback
            four-tuple, with our chosen port present in at least
            one of the captured CONN_SET_IP_V4 events.
        """
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=50)
        payload = b"binary-format\n"

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", capture_path=capture):
                received = loopback_oneshot(socket.AF_INET, port, payload)
                assert payload.rstrip(b"\n") in received
                # Wait long enough for the kernel to push everything
                # and elog to drain its read; otherwise event_count
                # in the file header may be < the events we expect.
                time.sleep(2)

        file_hdr, providers, events = parse_elog_binary(capture)

        # File-header invariants. event_count is updated in-place at
        # close (update_binary_header in elog.c), so it must equal
        # what we walked.
        assert file_hdr.event_count == len(events), (
            f"event_count in header ({file_hdr.event_count}) != "
            f"events walked ({len(events)})")
        assert file_hdr.dropped_events == 0, (
            f"kernel reported {file_hdr.dropped_events} dropped events "
            f"during the capture")
        assert file_hdr.capture_start > 0, (
            "capture_start should be the boot-relative timestamp at "
            "capture start; got 0")
        assert file_hdr.start_utc_us > 0, (
            "start_utc_us should be the wall-clock UTC microseconds "
            "at capture start; got 0")

        # Provider map invariants: at least one entry named "tcp".
        # Each TCP function block (freebsd, rack, ngen_*) registers its
        # own eventlog_provider and the kernel's name-based subscribe
        # path matches every provider whose name is "tcp", so a single
        # `-c tcp` subscription can pull in multiple provider ids on
        # an image that builds more than one stack. The invariant is
        # that *every* event in the capture came from one of those tcp
        # providers, not that there is exactly one of them.
        tcp_ids = {pid for pid, name in providers.items()
                   if name == "tcp"}
        assert tcp_ids, (
            f"no tcp provider in capture; got {providers!r}")

        # Per-event invariants and per-session bookkeeping. We check
        # invariants on EVERY event in the file but only build the
        # detailed per-session event-id map: VMs always have some
        # background TCP activity, and per-session content assertions
        # only make sense for the sessions we created ourselves
        # (identified below by matching the CONN_SET_IP_V4 four-tuple
        # against `port`).
        assert events, "no events recorded in capture"
        per_session_last_ts = {}
        per_session_event_ids = {}
        for hdr, ev_payload in events:
            assert hdr.provider_id in tcp_ids, (
                f"unexpected provider_id={hdr.provider_id} in event "
                f"(tcp provider ids: {sorted(tcp_ids)}; "
                f"providers: {providers!r})")
            # event_length self-consistency.
            assert (hdr.event_length ==
                    ELOG_EVENT_HEADER_SIZE + len(ev_payload)), (
                f"event_length {hdr.event_length} != header "
                f"({ELOG_EVENT_HEADER_SIZE}) + payload "
                f"({len(ev_payload)})")
            # Sanity: no individual event should be huge. The kernel
            # caps payloads at a few hundred bytes; 4 KiB is a
            # generous upper bound that still flags corruption.
            assert hdr.event_length <= 4096, (
                f"event_length {hdr.event_length} suspiciously large")
            # Timestamp monotonicity within a session_id. Different
            # sessions can interleave (different CPUs), so we don't
            # check globally - only within a session.
            last = per_session_last_ts.get(hdr.session_id)
            if last is not None:
                assert hdr.timestamp >= last, (
                    f"timestamp regression in session "
                    f"{hdr.session_id}: {last} -> {hdr.timestamp}")
            per_session_last_ts[hdr.session_id] = hdr.timestamp
            per_session_event_ids.setdefault(
                hdr.session_id, []).append(hdr.event_id)

        # Identify *our* loopback sessions: the ones whose
        # CONN_SET_IP_V4 four-tuple touches `port`. The VM has
        # incidental TCP activity (e.g. a kernel-internal session
        # that may transit only SESSION_CREATE/SESSION_END), so we
        # can't assume that every session in the capture belongs to
        # this test.
        v4_events = [
            (h, p) for h, p in events
            if h.event_id == TCP_EVENT_CONN_SET_IP_V4]
        assert v4_events, "no CONN_SET_IP_V4 events to validate"

        our_sessions = set()
        seen_ports = set()
        for hdr, ev_payload in v4_events:
            info = parse_conn_set_ip_v4_payload(ev_payload)
            seen_ports.add(info["src_port"])
            seen_ports.add(info["dst_port"])
            if info["src_port"] == port or info["dst_port"] == port:
                # Validate the CONN_SET_IP_V4 payload structure for
                # connections we know are ours: addresses must be
                # loopback. (We don't enforce 127.0.0.1 on every
                # CONN_SET_IP_V4 in the capture; an unrelated kernel
                # session could legitimately have a different IP.)
                assert info["src_addr"] == "127.0.0.1", (
                    f"CONN_SET_IP_V4 src {info['src_addr']!r} != "
                    f"127.0.0.1 in our session {hdr.session_id}")
                assert info["dst_addr"] == "127.0.0.1", (
                    f"CONN_SET_IP_V4 dst {info['dst_addr']!r} != "
                    f"127.0.0.1 in our session {hdr.session_id}")
                our_sessions.add(hdr.session_id)
        assert port in seen_ports, (
            f"chosen port {port} not present in any CONN_SET_IP_V4 "
            f"four-tuple (saw ports: {sorted(seen_ports)})")
        # Loopback creates two PCBs (client + server), each with its
        # own eventlog session, so we expect exactly 2 of "ours". We
        # accept >= 2 to remain robust against unforeseen retries
        # while still catching a "we lost a side" regression.
        assert len(our_sessions) >= 2, (
            f"expected ≥2 loopback sessions touching port {port}, "
            f"got {len(our_sessions)}: {sorted(our_sessions)}")

        # For each session WE created, validate the full lifecycle
        # is present in the binary record stream.
        for sid in sorted(our_sessions):
            ids = per_session_event_ids[sid]
            assert EVENTLOG_SESSION_CREATE_ID in ids, (
                f"session {sid}: no SESSION_CREATE event "
                f"(event_ids: {sorted(set(ids))})")
            assert EVENTLOG_SESSION_END_ID in ids, (
                f"session {sid}: no SESSION_END event "
                f"(event_ids: {sorted(set(ids))})")
            assert TCP_EVENT_CONN_SET_IP_V4 in ids, (
                f"session {sid}: no CONN_SET_IP_V4 event "
                f"(event_ids: {sorted(set(ids))})")
            assert TCP_EVENT_MSS in ids, (
                f"session {sid}: no MSS event "
                f"(event_ids: {sorted(set(ids))})")
            assert (TCP_EVENT_IN in ids) or (TCP_EVENT_OUT in ids), (
                f"session {sid}: no IN or OUT data event "
                f"(event_ids: {sorted(set(ids))})")

        # Validate the SESSION_CREATE payload structure for the
        # SESSION_CREATE events of our loopback sessions: 8-byte tp
        # pointer that the kernel passes from
        # tcp_eventlog_session_init must be non-zero.
        our_sc_events = [
            (h, p) for h, p in events
            if (h.event_id == EVENTLOG_SESSION_CREATE_ID
                and h.session_id in our_sessions)]
        assert len(our_sc_events) >= 2, (
            f"expected ≥2 SESSION_CREATE events for our loopback "
            f"sessions, got {len(our_sc_events)}")
        for hdr, ev_payload in our_sc_events:
            sc = parse_session_create_payload(ev_payload)
            assert sc["tp"] != 0, (
                f"SESSION_CREATE for session {hdr.session_id}: "
                f"tp pointer is 0 (kernel did not record tcpcb)")
