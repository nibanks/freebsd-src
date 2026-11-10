# SPDX-License-Identifier: BSD-2-Clause
#
# Copyright (c) 2026 Netflix, Inc.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

"""End-to-end ATF tests for the elog(1) userspace utility.

Validates the full path: elog binary -> /dev/eventlog -> kernel eventlog
framework. Complements kern_eventlog_test (which exercises kernel-internal
APIs via a ktest module) by covering the real character-device + IOCTL
surface.

Most cases require root because /dev/eventlog rejects jailed callers
(kern_eventlog.c eventlog_dev_open) and the CREATE IOCTL needs to allocate
per-CPU buffers.
"""

import ctypes
import errno
import fcntl
import gzip
import hashlib
import mmap
import os
import re
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
    # drives traffic. 2s, not 1s: under a loaded CI machine running many
    # kyua tests in parallel this startup can lag past a single tick.
    time.sleep(2)
    if proc.poll() is not None:
        err = proc.stderr.read().decode()
        raise AssertionError(f"elog exited early: {err}")
    try:
        yield proc
    finally:
        if proc.poll() is None:
            proc.terminate()
        try:
            out, err = proc.communicate(timeout=20)
        except subprocess.TimeoutExpired:
            proc.kill()
            out, err = proc.communicate()
        proc.captured_stdout = out.decode()
        proc.captured_stderr = err.decode()
        if proc.returncode != 0:
            raise AssertionError(
                f"elog exited rc={proc.returncode}; "
                f"stderr={err.decode()}")


def _spawn_elog(*args):
    """Start `elog -s [args]` without waiting for it. Caller reaps via
    `_finish_elog`."""
    return subprocess.Popen(
        [ELOG, "-s", *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def _finish_elog(proc, timeout=60):
    """SIGTERM `proc` if it is still running and require a clean exit.
    Unlike `elog_capture`, this does not sleep for startup first, so a
    test can signal several processes before waiting on any of them."""
    if proc.poll() is None:
        proc.terminate()
    try:
        _out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        proc.kill()
        _out, err = proc.communicate()
        raise AssertionError(
            f"elog did not exit on SIGTERM within {timeout}s; "
            f"stderr={err.decode()}")
    if proc.returncode != 0:
        raise AssertionError(
            f"elog exited rc={proc.returncode}; stderr={err.decode()}")
    return err.decode()


def decode_capture(path):
    """Run `elog -e -r <path>` and return its stdout."""
    return subprocess.check_output(
        [ELOG, "-e", "-r", str(path)], text=True)


def event_count_of_capture(path):
    """File-header event_count. `.gz` captures are decompressed into a
    sibling file first; parse_elog_binary() reads plain bytes."""
    data = Path(path).read_bytes()
    if path.name.endswith(".gz"):
        data = gzip.decompress(data)
    plain = path.with_name(path.name + ".parsed")
    plain.write_bytes(data)
    try:
        file_hdr, _, _, _ = parse_elog_binary(plain)
    finally:
        plain.unlink()
    return file_hdr.event_count


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


def _proc_forks(path):
    """Return {child_pid: parent_pid} for every process.PROC_FORK event."""
    _, providers, events, _ = parse_elog_binary(path)
    process_ids = {pid for pid, name in providers.items()
                   if name == "process"}
    forks = {}
    for eh, payload in events:
        if eh.provider_id not in process_ids:
            continue
        if eh.event_id != PROCESS_EVENT_PROC_FORK:
            continue
        if len(payload) < PROCESS_PROC_FORK_SIZE:
            continue
        pid, ppid = struct.unpack_from(PROCESS_PROC_FORK_FMT, payload, 0)
        forks[pid] = ppid
    return forks


def _proc_titles(path):
    """Return [(pid, title), ...] for every process.PROC_TITLE event."""
    _, providers, events, _ = parse_elog_binary(path)
    process_ids = {pid for pid, name in providers.items()
                   if name == "process"}
    titles = []
    for eh, payload in events:
        if eh.provider_id not in process_ids:
            continue
        if eh.event_id != PROCESS_EVENT_PROC_TITLE:
            continue
        if len(payload) < PROCESS_PROC_TITLE_SIZE:
            continue
        pid, raw = struct.unpack_from(PROCESS_PROC_TITLE_FMT, payload, 0)
        titles.append((pid, raw.split(b"\0", 1)[0].decode("ascii", "replace")))
    return titles


# ---------------------------------------------------------------------------
# elog binary-format decoder (in-process, no fork to elog -r)
# ---------------------------------------------------------------------------
#
# On-disk layout (host byte order; we use "<" for amd64):
#
#   elog_binary_header (36 bytes, __packed, current version 3):
#     char     magic[4]       == "ELOG"
#     uint32_t version           1 obsolete, no longer read; 2 and 3 read
#     uint64_t capture_start  microseconds since boot at capture start
#     uint64_t start_utc_us   wall-clock UTC microseconds at capture start
#     uint64_t event_count    total events written
#     uint32_t counter_count  number of trailing uint64_t counters below
#
#   counter_count x uint64_t counters[] (append-only by index; a reader
#   ignores indices beyond what it knows and treats a shorter array as
#   zero for the rest; see elog.c's ELOG_COUNTER_* defines). New in v3 --
#   v1 and v2 used a fixed 40-byte header with a single dropped_events
#   scalar in this field's place instead:
#     [0] kernel_dropped_events  kernel per-CPU buffer-full drops
#     [1] user_dropped_full      user-stream buffer-full drops
#     [2] user_dropped_prejoin   user events older than the join point
#     [3] user_dropped_late      user events older than stream's last delivered
#
#   uint32_t provider_count
#   provider_count x eventlog_provider_info (__packed):
#     uint16_t provider_id
#     char     name[EVENTLOG_PROVIDER_NAME_MAX = 32]
#     uint8_t  schema_id[16]              (version >= 2 only; SHA-256-trunc of blob)
#     => 34 bytes in v1 files, 50 bytes in v2+ files
#
#   decode-blob section (version >= 2 only), deduplicated by schema_id:
#     uint32_t blob_count                 (0 when --no-embed-decode is used)
#     blob_count x:
#       uint8_t  schema_id[16]            content-addressed key
#       uint32_t blob_size
#       uint8_t  blob[blob_size]          per sys/eventlog_decode.h ("EDB1")
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
ELOG_BINARY_VERSION = 3
# Oldest version elog(1) still reads (elog.c ELOG_BINARY_VERSION_MIN_READ).
ELOG_BINARY_VERSION_MIN_READ = 2
EVENTLOG_PROVIDER_NAME_MAX = 32
EVENTLOG_DECODE_SCHEMA_ID_LEN = 16
EVENTLOG_DECODE_MAGIC = b"EDB1"

# Framework-reserved event IDs (FreeBSD/sys/sys/eventlog.h).
EVENTLOG_SESSION_CREATE_ID = 0xFFFFFFFE
EVENTLOG_SESSION_END_ID = 0xFFFFFFFF

# elog(1)-internal bookkeeping event IDs (elog.c): in-band provider-table /
# decode-blob announcements for a provider that registered after the file's
# header was already written. Never emitted by the kernel; see elog.5's
# "Provider Announcement Records".
ELOG_EVENT_PROVIDER_INFO_ID = 0xFFFFFFFC
ELOG_EVENT_PROVIDER_BLOB_ID = 0xFFFFFFFB

# tcp provider event IDs (tcp_eventlog_schema.src).
TCP_EVENT_CONN_SET_IP_V4 = 0
TCP_EVENT_CONN_SET_IP_V6 = 1
TCP_EVENT_CONN_PARAMS = 3
TCP_EVENT_MSS = 4
TCP_EVENT_IN = 100
TCP_EVENT_OUT = 101

# process provider event IDs (process_eventlog_schema.src).
PROCESS_EVENT_PROC_FORK = 5
PROCESS_EVENT_PROC_TITLE = 6
# STRUCT PROC_FORK: pid, ppid
PROCESS_PROC_FORK_FMT = "<II"
PROCESS_PROC_FORK_SIZE = struct.calcsize(PROCESS_PROC_FORK_FMT)
assert PROCESS_PROC_FORK_SIZE == 8
# STRUCT PROC_TITLE: pid, title[32]
PROCESS_PROC_TITLE_FMT = "<I32s"
PROCESS_PROC_TITLE_SIZE = struct.calcsize(PROCESS_PROC_TITLE_FMT)
assert PROCESS_PROC_TITLE_SIZE == 36

# tcp keyword bits. The schema names bit indices (KEYWORD RX 1 => bit 0);
# eventlog_gen.awk expands them into the masks the decode blob carries.
TCP_KEYWORD_RX = 0x1
TCP_KEYWORD_CONN = 0x80

# Fixed prefix only; the counter_count x uint64_t counters[] tail is
# variable-length and parsed separately in parse_elog_binary() below.
ELOG_BINARY_HEADER_FMT = "<4sIQQQI"
ELOG_BINARY_HEADER_SIZE = struct.calcsize(ELOG_BINARY_HEADER_FMT)  # 36
# v1/v2's shared layout (fixed dropped_events scalar, no counters array);
# still current for v2, and used to build the v1/v2 fixtures below.
ELOG_BINARY_HEADER_FMT_LEGACY = "<4sIQQQQ"
ELOG_BINARY_HEADER_SIZE_LEGACY = \
    struct.calcsize(ELOG_BINARY_HEADER_FMT_LEGACY)  # 40
# Indices into the header's trailing counters[] array; must match elog.c's
# ELOG_COUNTER_* defines exactly.
ELOG_COUNTER_KERNEL_DROPPED = 0
ELOG_COUNTER_USER_DROPPED_FULL = 1
ELOG_COUNTER_USER_DROPPED_PREJOIN = 2
ELOG_COUNTER_USER_DROPPED_LATE = 3
ELOG_COUNTER_COUNT = 4
# v1 provider entry: provider_id + name. v2 appends schema_id[16].
ELOG_PROVIDER_INFO_FMT_V1 = f"<H{EVENTLOG_PROVIDER_NAME_MAX}s"
ELOG_PROVIDER_INFO_SIZE_V1 = struct.calcsize(ELOG_PROVIDER_INFO_FMT_V1)  # 34
ELOG_PROVIDER_INFO_FMT_V2 = \
    f"<H{EVENTLOG_PROVIDER_NAME_MAX}s{EVENTLOG_DECODE_SCHEMA_ID_LEN}s"
ELOG_PROVIDER_INFO_SIZE_V2 = struct.calcsize(ELOG_PROVIDER_INFO_FMT_V2)  # 50
ELOG_EVENT_HEADER_FMT = "<HHHHQQIi"
ELOG_EVENT_HEADER_SIZE = struct.calcsize(ELOG_EVENT_HEADER_FMT)    # 32
ELOG_ZERO_SCHEMA_ID = bytes(EVENTLOG_DECODE_SCHEMA_ID_LEN)
assert ELOG_BINARY_HEADER_SIZE == 36
assert ELOG_BINARY_HEADER_SIZE_LEGACY == 40
assert ELOG_PROVIDER_INFO_SIZE_V1 == 34
assert ELOG_PROVIDER_INFO_SIZE_V2 == 50
assert ELOG_EVENT_HEADER_SIZE == 32

# elog.c's ELOG_INBAND_BLOB_MAX: the biggest decode blob that fits in one
# ELOG_EVENT_PROVIDER_BLOB_ID record, bounded by event_length being a
# uint16_t.
ELOG_INBAND_BLOB_MAX = (0xFFFF - ELOG_EVENT_HEADER_SIZE -
                        EVENTLOG_DECODE_SCHEMA_ID_LEN - 4)
assert ELOG_INBAND_BLOB_MAX == 65483
# kern_eventlog.c's EVENTLOG_USER_DECODE_BLOB_MAX: REGISTER_PROVIDER's own
# cap on a user-space provider's decode_blob_size, smaller than (and
# unrelated to) EVENTLOG_DECODE_BLOB_MAX. A blob has to clear
# ELOG_INBAND_BLOB_MAX but stay under this to test "too big to embed"
# without the kernel itself rejecting the registration.
EVENTLOG_USER_DECODE_BLOB_MAX = 64 * 1024
assert ELOG_INBAND_BLOB_MAX < EVENTLOG_USER_DECODE_BLOB_MAX

ElogFileHeader = namedtuple(
    "ElogFileHeader",
    "capture_start start_utc_us event_count kernel_dropped_events "
    "user_dropped_full user_dropped_prejoin user_dropped_late")
ElogEventHeader = namedtuple(
    "ElogEventHeader",
    "event_length cpu provider_id timestamp session_id event_id thread_id")
# Schema-id bindings recovered from a capture: version, provider_id->schema_id
# (16 raw bytes; all-zero for v1 / no-blob providers) and the set of schema_ids
# carried by the embedded decode-blob section (the header's section plus any
# in-band ELOG_EVENT_PROVIDER_BLOB_ID announcements). header_provider_ids and
# inband_provider_ids partition provider_schema_ids' keys by where they came
# from, so a test can tell a provider that was live at header-write time
# apart from one only ever seen via a mid-stream announcement -- except
# provider_id is reused (alloc_unr(9)), so the same id can legitimately be
# in both sets for two unrelated providers. header_provider_names -- the
# header table's names, snapshotted before any in-band announcement can
# overwrite an id's entry -- is the reuse-proof way to ask "was *this named
# provider* (not just this id) live when the header was written?".
ElogCaptureMeta = namedtuple(
    "ElogCaptureMeta",
    "version provider_schema_ids embedded_schema_ids header_provider_ids "
    "header_provider_names inband_provider_ids")


def parse_elog_binary(path):
    """Parse a complete elog binary capture file. Returns a tuple
    `(file_header, providers_by_id, events, meta)` where:
      file_header        ElogFileHeader
      providers_by_id    dict[int -> str], e.g. {1: "tcp"}; merges the
                          header's provider table with any in-band
                          ELOG_EVENT_PROVIDER_INFO_ID announcements
      events             list of (ElogEventHeader, payload_bytes) for real
                          captured events only -- ELOG_EVENT_PROVIDER_*_ID
                          announcements are consumed into `meta` instead,
                          mirroring elog -r's own print_eventlog_event()
      meta               ElogCaptureMeta (version + schema_id bindings)

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
        counter_count) = struct.unpack_from(
            ELOG_BINARY_HEADER_FMT, data, off)
    off += ELOG_BINARY_HEADER_SIZE
    if magic != ELOG_BINARY_MAGIC:
        raise AssertionError(
            f"capture {path!s}: bad magic {magic!r} "
            f"(expected {ELOG_BINARY_MAGIC!r})")
    if not ELOG_BINARY_VERSION_MIN_READ <= version <= ELOG_BINARY_VERSION:
        raise AssertionError(
            f"capture {path!s}: bad version {version} (expected "
            f"{ELOG_BINARY_VERSION_MIN_READ}-{ELOG_BINARY_VERSION})")

    if version < 3:
        # v2's header tail is a single dropped_events scalar, equivalent to
        # a one-entry counters array.
        if len(data) < ELOG_BINARY_HEADER_SIZE_LEGACY:
            raise AssertionError(
                f"capture {path!s}: only {len(data)} bytes, "
                f"need ≥{ELOG_BINARY_HEADER_SIZE_LEGACY} for a v{version} "
                f"file header")
        off = ELOG_BINARY_HEADER_SIZE_LEGACY
        counters = struct.unpack_from(
            "<Q", data, ELOG_BINARY_HEADER_SIZE_LEGACY - 8)
    else:
        # Header counters[]: append-only by index (see elog.c's
        # ELOG_COUNTER_*). A file with fewer entries than we know about
        # reads the rest as 0; one with more (a newer writer) just has its
        # extra entries ignored here.
        if off + counter_count * 8 > len(data):
            raise AssertionError(
                f"capture {path!s}: truncated header counters array "
                f"(claims {counter_count} entries)")
        counters = struct.unpack_from(f"<{counter_count}Q", data, off)
        off += counter_count * 8

    def _counter(idx):
        return counters[idx] if idx < len(counters) else 0

    file_hdr = ElogFileHeader(
        capture_start=capture_start, start_utc_us=start_utc_us,
        event_count=event_count,
        kernel_dropped_events=_counter(ELOG_COUNTER_KERNEL_DROPPED),
        user_dropped_full=_counter(ELOG_COUNTER_USER_DROPPED_FULL),
        user_dropped_prejoin=_counter(ELOG_COUNTER_USER_DROPPED_PREJOIN),
        user_dropped_late=_counter(ELOG_COUNTER_USER_DROPPED_LATE))

    if off + 4 > len(data):
        raise AssertionError(
            f"capture {path!s}: truncated before provider_count")
    (prov_count,) = struct.unpack_from("<I", data, off)
    off += 4
    # Provider count is now unbounded by a fixed cap; an absurd value still
    # signals a corrupt header.
    if prov_count > 65536:
        raise AssertionError(
            f"capture {path!s}: implausible provider_count={prov_count}")
    if version >= 2:
        info_fmt, info_size = ELOG_PROVIDER_INFO_FMT_V2, \
            ELOG_PROVIDER_INFO_SIZE_V2
    else:
        info_fmt, info_size = ELOG_PROVIDER_INFO_FMT_V1, \
            ELOG_PROVIDER_INFO_SIZE_V1
    providers = {}
    provider_schema_ids = {}
    for i in range(prov_count):
        if off + info_size > len(data):
            raise AssertionError(
                f"capture {path!s}: truncated provider entry {i}")
        if version >= 2:
            prov_id, name_bytes, schema_id = struct.unpack_from(
                info_fmt, data, off)
        else:
            prov_id, name_bytes = struct.unpack_from(info_fmt, data, off)
            schema_id = ELOG_ZERO_SCHEMA_ID
        off += info_size
        name = name_bytes.split(b"\0", 1)[0].decode("ascii")
        providers[prov_id] = name
        provider_schema_ids[prov_id] = schema_id
    header_provider_ids = set(providers.keys())
    header_provider_names = set(providers.values())

    # Version >= 2: optional embedded decode-blob section, keyed by schema_id. We
    # don't interpret the blob bytes here (elog -r does that); we validate the
    # framing/magic and record the schema_ids so callers can check that a
    # provider's recorded schema_id is actually embedded.
    embedded_schema_ids = []
    if version >= 2:
        if off + 4 > len(data):
            raise AssertionError(
                f"capture {path!s}: truncated before blob_count")
        (blob_count,) = struct.unpack_from("<I", data, off)
        off += 4
        if blob_count > 32:
            raise AssertionError(
                f"capture {path!s}: implausible blob_count={blob_count}")
        for i in range(blob_count):
            if off + EVENTLOG_DECODE_SCHEMA_ID_LEN + 4 > len(data):
                raise AssertionError(
                    f"capture {path!s}: truncated blob entry {i} header")
            schema_id = data[off:off + EVENTLOG_DECODE_SCHEMA_ID_LEN]
            off += EVENTLOG_DECODE_SCHEMA_ID_LEN
            (blob_size,) = struct.unpack_from("<I", data, off)
            off += 4
            if off + blob_size > len(data):
                raise AssertionError(
                    f"capture {path!s}: truncated blob entry {i} body")
            blob = data[off:off + blob_size]
            off += blob_size
            if blob[:4] != EVENTLOG_DECODE_MAGIC:
                raise AssertionError(
                    f"capture {path!s}: blob entry {i} bad magic "
                    f"{blob[:4]!r} (expected {EVENTLOG_DECODE_MAGIC!r})")
            embedded_schema_ids.append(schema_id)

    inband_provider_ids = set()
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
        off += event_length

        # In-band provider/decode-blob announcements: applied to the
        # provider/schema maps, not surfaced as a captured event -- same
        # split elog -r's print_eventlog_event() makes on the read path.
        if event_id == ELOG_EVENT_PROVIDER_INFO_ID:
            if len(payload) != ELOG_PROVIDER_INFO_SIZE_V2:
                raise AssertionError(
                    f"capture {path!s}: malformed provider-info "
                    f"announcement ({len(payload)} bytes, expected "
                    f"{ELOG_PROVIDER_INFO_SIZE_V2})")
            (prov_id, name_bytes, schema_id) = struct.unpack_from(
                ELOG_PROVIDER_INFO_FMT_V2, payload)
            providers[prov_id] = name_bytes.split(b"\0", 1)[0].decode(
                "ascii")
            provider_schema_ids[prov_id] = schema_id
            inband_provider_ids.add(prov_id)
            continue
        if event_id == ELOG_EVENT_PROVIDER_BLOB_ID:
            prefix = EVENTLOG_DECODE_SCHEMA_ID_LEN + 4
            if len(payload) < prefix:
                raise AssertionError(
                    f"capture {path!s}: truncated provider-blob "
                    f"announcement ({len(payload)} bytes)")
            schema_id = payload[:EVENTLOG_DECODE_SCHEMA_ID_LEN]
            (blob_size,) = struct.unpack_from(
                "<I", payload, EVENTLOG_DECODE_SCHEMA_ID_LEN)
            if len(payload) != prefix + blob_size:
                raise AssertionError(
                    f"capture {path!s}: provider-blob announcement size "
                    f"mismatch (blob_size={blob_size}, "
                    f"payload={len(payload)})")
            blob = payload[prefix:prefix + blob_size]
            if blob[:4] != EVENTLOG_DECODE_MAGIC:
                raise AssertionError(
                    f"capture {path!s}: provider-blob announcement bad "
                    f"magic {blob[:4]!r} "
                    f"(expected {EVENTLOG_DECODE_MAGIC!r})")
            embedded_schema_ids.append(schema_id)
            continue

        events.append((
            ElogEventHeader(
                event_length=event_length, cpu=cpu,
                provider_id=provider_id, timestamp=timestamp,
                session_id=session_id, event_id=event_id,
                thread_id=thread_id),
            payload,
        ))

    meta = ElogCaptureMeta(
        version=version, provider_schema_ids=provider_schema_ids,
        embedded_schema_ids=embedded_schema_ids,
        header_provider_ids=header_provider_ids,
        header_provider_names=header_provider_names,
        inband_provider_ids=inband_provider_ids)
    return file_hdr, providers, events, meta


def downgrade_capture_to_v2(src, dst):
    """Rewrite a v3 capture in the v2 layout, byte-for-byte identical from
    the provider table on. Lets the v2 read path be exercised against a real
    capture without keeping a stale binary fixture in the tree."""
    data = Path(src).read_bytes()
    (magic, version, capture_start, start_utc_us, event_count,
        counter_count) = struct.unpack_from(ELOG_BINARY_HEADER_FMT, data, 0)
    assert magic == ELOG_BINARY_MAGIC, f"bad magic {magic!r}"
    assert version == ELOG_BINARY_VERSION, f"expected v3, got v{version}"
    counters = struct.unpack_from(f"<{counter_count}Q", data,
                                  ELOG_BINARY_HEADER_SIZE)
    dropped = counters[ELOG_COUNTER_KERNEL_DROPPED] if counters else 0
    body = data[ELOG_BINARY_HEADER_SIZE + counter_count * 8:]
    Path(dst).write_bytes(struct.pack(
        ELOG_BINARY_HEADER_FMT_LEGACY, ELOG_BINARY_MAGIC, 2, capture_start,
        start_utc_us, event_count, dropped) + body)


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
    tcp_eventlog_schema.src). The generated event structs are __packed,
    so the wire layout is dense with no inter-field or trailing padding:
        struct in_addr src_addr;  // 4 bytes (network byte order)
        uint16_t       src_port;  // 2 bytes (network byte order)
        struct in_addr dst_addr;  // 4 bytes
        uint16_t       dst_port;  // 2 bytes
        // total 12 bytes, no padding
    """
    if len(payload) != 12:
        raise AssertionError(
            f"CONN_SET_IP_V4 payload size {len(payload)} != 12")
    src_addr_bytes = payload[0:4]
    (src_port_n,) = struct.unpack_from("<H", payload, 4)
    dst_addr_bytes = payload[6:10]
    (dst_port_n,) = struct.unpack_from("<H", payload, 10)
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


# ---------------------------------------------------------------------------
# EVENTLOG_IOCTL_GET_DECODE_BLOB ABI (sys/sys/eventlog_subscriber.h)
# ---------------------------------------------------------------------------
#
# The elog binary only ever drives the happy paths of this ioctl (fetch by
# name for keyword resolution / decode-blob embedding, fetch by schema_id for
# live decode). These helpers issue it directly so the error branches
# (EINVAL/ENOENT/ENOSPC) and the two-call size probe are covered too.

EVENTLOG_DECODE_LOOKUP_NAME = 0
EVENTLOG_DECODE_LOOKUP_SCHEMA_ID = 1


class _GetDecodeBlobReq(ctypes.Structure):
    # Mirrors struct eventlog_get_decode_blob_req (not __packed: natural
    # alignment, so the uint64_t forces 7 bytes of padding after lookup_kind).
    _fields_ = [
        ("provider_name", ctypes.c_char * EVENTLOG_PROVIDER_NAME_MAX),
        ("schema_id", ctypes.c_uint8 * EVENTLOG_DECODE_SCHEMA_ID_LEN),
        ("lookup_kind", ctypes.c_uint8),
        ("buf", ctypes.c_uint64),
        ("buf_size", ctypes.c_uint32),
        ("blob_size", ctypes.c_uint32),
    ]


# This must match sizeof(struct eventlog_get_decode_blob_req) so the _IOWR
# length the kernel decodes matches what we pass.
assert ctypes.sizeof(_GetDecodeBlobReq) == 72


def _freebsd_iowr(group, num, size):
    """Encode a FreeBSD _IOWR(group, num, size) request number."""
    IOCPARM_MASK = 0x1FFF
    IOC_IN = 0x80000000
    IOC_OUT = 0x40000000
    return ((IOC_IN | IOC_OUT) | ((size & IOCPARM_MASK) << 16) |
            (ord(group) << 8) | num)


_EVENTLOG_IOCTL_GET_DECODE_BLOB = _freebsd_iowr(
    "E", 6, ctypes.sizeof(_GetDecodeBlobReq))


def _get_decode_blob(fd, *, name=None, schema_id=None, lookup_kind=None,
                     out_buf=None):
    """Issue EVENTLOG_IOCTL_GET_DECODE_BLOB. Returns the (mutated) request
    struct; raises OSError (with .errno) on failure. With out_buf=None this
    is the size probe (buf == 0); otherwise the blob is copied into out_buf."""
    req = _GetDecodeBlobReq()
    if lookup_kind is None:
        lookup_kind = (EVENTLOG_DECODE_LOOKUP_SCHEMA_ID
                       if schema_id is not None
                       else EVENTLOG_DECODE_LOOKUP_NAME)
    req.lookup_kind = lookup_kind
    if name is not None:
        req.provider_name = name.encode()
    if schema_id is not None:
        ctypes.memmove(req.schema_id, schema_id, len(schema_id))
    if out_buf is not None:
        req.buf = ctypes.addressof(out_buf)
        req.buf_size = len(out_buf)
    fcntl.ioctl(fd, _EVENTLOG_IOCTL_GET_DECODE_BLOB, req, True)
    return req


@contextmanager
def _open_eventlog():
    # The device is read-only (eventlog_dev_open rejects FWRITE); the _IOWR
    # GET_DECODE_BLOB ioctl still works on a read-only fd, which is how elog
    # itself uses it.
    _require_eventlog_dev()
    fd = os.open(EVENTLOG_DEV, os.O_RDONLY)
    try:
        yield fd
    finally:
        os.close(fd)


# ---------------------------------------------------------------------------
# Raw user-space provider (register + submission ring), bypassing
# libeventlog entirely so tests can push records with hand-picked
# timestamps to force specific drop conditions. Mirrors do_register() /
# ring_setup() / do_push() in eventlog_user_provider_test.c.
# ---------------------------------------------------------------------------

EVENTLOG_LEVEL_INFO = 3
EVENTLOG_RING_CACHELINE = 64


def _freebsd_io(group, num):
    """Encode a FreeBSD _IO(group, num) request number (no payload)."""
    IOC_VOID = 0x20000000
    return IOC_VOID | (ord(group) << 8) | num


def _freebsd_ior(group, num, size):
    """Encode a FreeBSD _IOR(group, num, size) request number."""
    IOCPARM_MASK = 0x1FFF
    IOC_OUT = 0x40000000
    return IOC_OUT | ((size & IOCPARM_MASK) << 16) | (ord(group) << 8) | num


class _ProviderRegReq(ctypes.Structure):
    # Mirrors struct eventlog_provider_reg_req (not __packed).
    _fields_ = [
        ("name", ctypes.c_char * EVENTLOG_PROVIDER_NAME_MAX),
        ("default_enabled", ctypes.c_int),
        ("flags", ctypes.c_uint32),
        ("expected_cadence_us", ctypes.c_uint64),
        ("decode_blob", ctypes.c_uint64),
        ("decode_blob_size", ctypes.c_uint32),
        ("provider_id", ctypes.c_uint16),
        ("enable_offset", ctypes.c_uint16),
        ("RESERVED", ctypes.c_uint32),
    ]


assert ctypes.sizeof(_ProviderRegReq) == 72


class _RingSetupReq(ctypes.Structure):
    # Mirrors struct eventlog_ring_setup_req.
    _fields_ = [
        ("size", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("mmap_offset", ctypes.c_uint64),
        ("mmap_size", ctypes.c_uint64),
    ]


assert ctypes.sizeof(_RingSetupReq) == 24


class _EventlogStatsReq(ctypes.Structure):
    # Mirrors struct eventlog_stats.
    _fields_ = [
        ("dropped_events", ctypes.c_uint64),
        ("user_dropped_full", ctypes.c_uint64),
        ("user_dropped_prejoin", ctypes.c_uint64),
        ("user_dropped_late", ctypes.c_uint64),
    ]


_EVENTLOG_IOCTL_REGISTER_PROVIDER = _freebsd_iowr(
    "E", 5, ctypes.sizeof(_ProviderRegReq))
_EVENTLOG_IOCTL_SETUP_RING = _freebsd_iowr(
    "E", 10, ctypes.sizeof(_RingSetupReq))
_EVENTLOG_IOCTL_KICK = _freebsd_io("E", 12)
_EVENTLOG_IOCTL_GET_STATS = _freebsd_ior(
    "E", 3, ctypes.sizeof(_EventlogStatsReq))

# struct eventlog_push_record (40 bytes, naturally aligned, no padding
# for this field order).
_PUSH_RECORD_FMT = "<QQIIiHHBBH4s"
_PUSH_RECORD_SIZE = struct.calcsize(_PUSH_RECORD_FMT)
assert _PUSH_RECORD_SIZE == 40

# struct eventlog_ring_hdr field offsets. version/data_size/data_offset/
# RESERVED0 occupy the first 16 bytes; head/watermark_us/dropped/stream_id
# start at the next EVENTLOG_RING_CACHELINE boundary (producer-owned cache
# line), and tail/flags start at the cache line after that (kernel-owned).
def _roundup(x, align):
    return (x + align - 1) & ~(align - 1)


_RING_HEAD_OFF = _roundup(16, EVENTLOG_RING_CACHELINE)
_RING_WATERMARK_OFF = _RING_HEAD_OFF + 8
_RING_DROPPED_OFF = _RING_WATERMARK_OFF + 8
_RING_STREAM_ID_OFF = _RING_DROPPED_OFF + 8
_RING_TAIL_OFF = _roundup(_RING_STREAM_ID_OFF + 8, EVENTLOG_RING_CACHELINE)


class _UserRingProvider:
    """A raw user-space provider: registers by name, sets up and mmaps its
    submission ring, and lets the caller push records with arbitrary
    timestamps directly - no libeventlog involved. One stream (stream_id
    0) per instance."""

    def __init__(self, name, decode_blob=None):
        self.fd = os.open(EVENTLOG_DEV, os.O_RDWR)
        req = _ProviderRegReq()
        req.name = name.encode()
        req.default_enabled = 1
        if decode_blob is not None:
            # Kept alive on self past the ioctl call, just in case.
            self._decode_blob_buf = ctypes.create_string_buffer(decode_blob)
            req.decode_blob = ctypes.addressof(self._decode_blob_buf)
            req.decode_blob_size = len(decode_blob)
        fcntl.ioctl(self.fd, _EVENTLOG_IOCTL_REGISTER_PROVIDER, req, True)
        self.provider_id = req.provider_id
        self._extra_blobs = []

        setup = _RingSetupReq()
        fcntl.ioctl(self.fd, _EVENTLOG_IOCTL_SETUP_RING, setup, True)
        self._mmap = mmap.mmap(self.fd, setup.mmap_size,
                                prot=mmap.PROT_READ | mmap.PROT_WRITE,
                                offset=setup.mmap_offset)
        (self._data_size, self._data_off) = struct.unpack_from(
            "<II", self._mmap, 4)
        self._mask = self._data_size - 1

    def register_another(self, name, decode_blob=None):
        """Register another provider on this fd. Records from every
        provider on the fd share one submission ring and one merge
        stream (channel_id, stream 0)."""
        req = _ProviderRegReq()
        req.name = name.encode()
        req.default_enabled = 1
        if decode_blob is not None:
            buf = ctypes.create_string_buffer(decode_blob)
            self._extra_blobs.append(buf)
            req.decode_blob = ctypes.addressof(buf)
            req.decode_blob_size = len(decode_blob)
        fcntl.ioctl(self.fd, _EVENTLOG_IOCTL_REGISTER_PROVIDER, req, True)
        return req.provider_id

    def _ring_put(self, pos, data):
        off = pos & self._mask
        n1 = self._data_size - off
        base = self._data_off
        if n1 >= len(data):
            self._mmap[base + off:base + off + len(data)] = data
        else:
            self._mmap[base + off:base + self._data_size] = data[:n1]
            self._mmap[base:base + len(data) - n1] = data[n1:]

    def push(self, records, provider_ids=None):
        """records: list of (timestamp_us, event_id, keywords, level,
        session_id, payload) tuples. Publishes them as a single batch at
        the current head, then issues KICK to force an immediate drain.
        provider_ids, when given, is one id per record; otherwise every
        record uses this instance's first provider."""
        (head,) = struct.unpack_from("<Q", self._mmap, _RING_HEAD_OFF)
        wp = head
        watermark_us = 0
        for i, (ts, event_id, keywords, level, session_id,
                payload) in enumerate(records):
            pid = (self.provider_id if provider_ids is None
                   else provider_ids[i])
            rec = struct.pack(
                _PUSH_RECORD_FMT, ts, session_id, event_id, keywords, 0,
                len(payload), pid, level, 0, 0, b"\0" * 4)
            self._ring_put(wp, rec)
            wp += _PUSH_RECORD_SIZE
            if payload:
                self._ring_put(wp, payload)
                wp += len(payload)
            watermark_us = ts
        struct.pack_into("<H", self._mmap, _RING_STREAM_ID_OFF, 0)
        struct.pack_into("<Q", self._mmap, _RING_WATERMARK_OFF, watermark_us)
        struct.pack_into("<Q", self._mmap, _RING_HEAD_OFF, wp)
        fcntl.ioctl(self.fd, _EVENTLOG_IOCTL_KICK)

    def wait_dump_request(self, timeout_ms=2000):
        """Poll EVENTLOG_IOCTL_WAIT_CONTROL until a DUMP_REQUEST control
        event arrives (up to timeout_ms) and return its target
        subscriber_id. Each ioctl blocks in the kernel up to 50 ms, so the
        loop is a poll with an overall deadline."""
        cap = 4
        buf = bytearray(_EVENTLOG_WAIT_CONTROL_HDR_SIZE +
                        cap * _EVENTLOG_CONTROL_EVENT_SIZE)
        waited = 0
        while True:
            struct.pack_into(_EVENTLOG_WAIT_CONTROL_HDR_FMT, buf, 0,
                             50000, cap, 0)
            fcntl.ioctl(self.fd, _eventlog_ioctl_wait_control(cap),
                        buf, True)
            (count,) = struct.unpack_from("<I", buf, 8)
            for i in range(count):
                ev = struct.unpack_from(
                    _EVENTLOG_CONTROL_EVENT_FMT, buf,
                    _EVENTLOG_WAIT_CONTROL_HDR_SIZE +
                    i * _EVENTLOG_CONTROL_EVENT_SIZE)
                if ev[0] == _EVENTLOG_CONTROL_DUMP_REQUEST:
                    return ev[3]
            if waited >= timeout_ms:
                raise AssertionError(
                    f"no DUMP_REQUEST control event within {timeout_ms}ms")
            waited += 50

    def dump_done(self, subscriber_id):
        """EVENTLOG_IOCTL_DUMP_DONE with no PUSH_DUMP first, so the
        kernel synthesises a bare DUMP_COMPLETE for the subscriber."""
        fcntl.ioctl(self.fd, _EVENTLOG_IOCTL_DUMP_DONE,
                    struct.pack("<QHHI", subscriber_id, self.provider_id,
                                0, 0))

    def close(self):
        self._mmap.close()
        os.close(self.fd)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.close()


def _prime_binary_header(name):
    """Register a disposable provider under `name`, push one event through
    it, and unregister it again. A binary capture's header is written
    lazily on its first event (write_binary_event() needs that event's
    timestamp), and the provider_id lookup for *that* event runs before
    the "header written yet?" check -- so if the capture's only-ever
    provider were the late-binding one under test, its own first event
    would get swept directly into the header instead of exercising the
    in-band announcement path. Call this (with `name` subscribed via `-c`
    alongside the real provider under test) to commit the header first.

    The sleep here has to outlast elog(1)'s own startup -- not just cover
    the kernel accepting this event, but cover elog(1) getting through
    subscription setup, its initial GET_PROVIDERS, and decode-blob
    prefetch and actually reaching its read() loop, since that is what
    determines whether it processes this event before `name` unregisters.
    elog_capture()'s fixed 1s grace period is sized for uncontended
    startup; under a loaded CI machine running many kyua tests in
    parallel, elog(1) can still be mid-startup well past that. There is
    no way to observe this from outside: the output file is buffered and
    isn't flushed until the capture ends (SIGINT/SIGTERM/exit), so
    polling the file is not an option either. If `name` unregisters
    (freeing its provider_id back to the kernel's alloc_unr(9) pool)
    before elog(1) has processed its event, the real provider under test
    can grab that same id and register before elog(1) ever looks `name`'s
    id up -- at which point the GET_PROVIDERS refresh triggered by that
    lookup resolves the real provider, not `name`, and the header ends up
    with the real provider in it after all. A generous margin here trades
    a slower test for not chasing that race.
    """
    with _UserRingProvider(name) as early:
        ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
        early.push([(ts, 0, 0x1, EVENTLOG_LEVEL_INFO, 0, b"")])
        time.sleep(8)


def get_eventlog_stats(fd):
    stats = _EventlogStatsReq()
    fcntl.ioctl(fd, _EVENTLOG_IOCTL_GET_STATS, stats, True)
    return stats


# ---------------------------------------------------------------------------
# EVENTLOG_IOCTL_CREATE_BASE / EVENTLOG_IOCTL_TRIGGER_DUMP_STATE ABI
# ---------------------------------------------------------------------------
#
# elog(1) does not issue EVENTLOG_IOCTL_TRIGGER_DUMP_STATE yet (that lands
# with the --roll-time integration); these helpers drive the raw
# character-device + IOCTL surface directly so the ioctl itself has
# coverage in the meantime, in the same style as _get_decode_blob above.

EVENTLOG_SUBSCRIPTION_DUMP_STATE = 0x00000001
EVENTLOG_LEVEL_VERBOSE = 4
EVENTLOG_BUFFER_SIZE_MIN = 64 * 1024


class _EventlogSubscriptionReq(ctypes.Structure):
    # Mirrors struct eventlog_subscription_req (sys/eventlog_subscriber.h).
    _fields_ = [
        ("level", ctypes.c_int),
        ("keywords", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("provider_name", ctypes.c_char * EVENTLOG_PROVIDER_NAME_MAX),
    ]


assert ctypes.sizeof(_EventlogSubscriptionReq) == 44


def _make_create_req_type(count):
    """Build a ctypes.Structure type mirroring struct eventlog_create_req
    with exactly `count` fixed subscription entries in place of its
    flexible array member."""
    class _EventlogCreateReq(ctypes.Structure):
        _fields_ = [
            ("buffer_size_per_cpu", ctypes.c_uint32),
            ("count", ctypes.c_uint32),
            ("subscriptions", _EventlogSubscriptionReq * count),
        ]
    return _EventlogCreateReq


def _freebsd_iow(group, num, size):
    """Encode a FreeBSD _IOW(group, num, size) request number."""
    IOCPARM_MASK = 0x1FFF
    IOC_IN = 0x80000000
    return IOC_IN | ((size & IOCPARM_MASK) << 16) | (ord(group) << 8) | num

# Control-channel ABI (sys/sys/eventlog_dev.h): DUMP_REQUEST events from
# the kernel, DUMP_DONE back. struct eventlog_control_event is 16 bytes
# (u16 type, u16 provider_id, i32 value, u64 subscriber_id); struct
# eventlog_wait_control_req's header (timeout_us, count, RESERVED) is 16
# bytes with events[] following, and EVENTLOG_IOCTL_WAIT_CONTROL_SIZE
# encodes header + event slots as the _IOWR length. Mirrors
# wait_control()/do_dump_done() in eventlog_user_provider_test.c.
_EVENTLOG_CONTROL_DUMP_REQUEST = 1
_EVENTLOG_CONTROL_EVENT_FMT = "<HHiq"
_EVENTLOG_CONTROL_EVENT_SIZE = struct.calcsize(_EVENTLOG_CONTROL_EVENT_FMT)
assert _EVENTLOG_CONTROL_EVENT_SIZE == 16
_EVENTLOG_WAIT_CONTROL_HDR_FMT = "<QII"
_EVENTLOG_WAIT_CONTROL_HDR_SIZE = struct.calcsize(
    _EVENTLOG_WAIT_CONTROL_HDR_FMT)
assert _EVENTLOG_WAIT_CONTROL_HDR_SIZE == 16


def _eventlog_ioctl_wait_control(count):
    return _freebsd_iowr(
        "E", 7, _EVENTLOG_WAIT_CONTROL_HDR_SIZE +
        count * _EVENTLOG_CONTROL_EVENT_SIZE)


# struct eventlog_dump_done_req is 16 bytes (u64 subscriber_id, u16
# provider_id, u16 RESERVED16, u32 RESERVED).
_EVENTLOG_IOCTL_DUMP_DONE = _freebsd_iow("E", 9, 16)

_EVENTLOG_IOCTL_DESTROY = _freebsd_io("E", 2)
# EVENTLOG_IOCTL_TRIGGER_DUMP_STATE is ioctl 13 in this branch's numbering
# (sys/sys/eventlog_dev.h); GET_DECODE_BLOB already claims 6 here, unlike
# on master where TRIGGER_DUMP_STATE was assigned 6.
_EVENTLOG_IOCTL_TRIGGER_DUMP_STATE = _freebsd_io("E", 13)


@contextmanager
def _raw_subscribe(provider_name, *, level=EVENTLOG_LEVEL_VERBOSE,
                    keywords=0xFFFFFFFF, flags=0,
                    buffer_size_per_cpu=EVENTLOG_BUFFER_SIZE_MIN):
    """Open /dev/eventlog and issue a single-subscription
    EVENTLOG_IOCTL_CREATE_BASE directly, bypassing elog(1). Yields the
    fd; issues DESTROY and closes it on exit."""
    _require_eventlog_dev()
    req_type = _make_create_req_type(1)
    req = req_type()
    req.buffer_size_per_cpu = buffer_size_per_cpu
    req.count = 1
    req.subscriptions[0].level = level
    req.subscriptions[0].keywords = keywords
    req.subscriptions[0].flags = flags
    req.subscriptions[0].provider_name = provider_name.encode()

    ioctl_create = _freebsd_iow("E", 1, ctypes.sizeof(req_type))
    fd = os.open(EVENTLOG_DEV, os.O_RDONLY)
    try:
        fcntl.ioctl(fd, ioctl_create, req, True)
        yield fd
    finally:
        try:
            fcntl.ioctl(fd, _EVENTLOG_IOCTL_DESTROY)
        except OSError:
            pass
        os.close(fd)


def _read_raw_events(fd, timeout_s):
    """Read the bare kernel event stream off an already-subscribed
    /dev/eventlog fd for up to timeout_s seconds. Unlike parse_elog_binary
    there is no file header or provider table here -- just back-to-back
    ElogEventHeader + payload records -- so this reuses the same event
    framing but starts parsing at offset 0. Returns a list of
    (ElogEventHeader, payload_bytes)."""
    fcntl.fcntl(fd, fcntl.F_SETFL, os.O_NONBLOCK)
    events = []
    buf = b""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            chunk = os.read(fd, 1 << 20)
        except BlockingIOError:
            time.sleep(0.05)
            continue
        if not chunk:
            time.sleep(0.05)
            continue
        buf += chunk
        while len(buf) >= ELOG_EVENT_HEADER_SIZE:
            (event_length, cpu, provider_id, _reserved, timestamp,
                session_id, event_id, thread_id) = struct.unpack_from(
                    ELOG_EVENT_HEADER_FMT, buf, 0)
            if event_length < ELOG_EVENT_HEADER_SIZE or \
                    len(buf) < event_length:
                break
            payload = bytes(buf[ELOG_EVENT_HEADER_SIZE:event_length])
            events.append((
                ElogEventHeader(
                    event_length=event_length, cpu=cpu,
                    provider_id=provider_id, timestamp=timestamp,
                    session_id=session_id, event_id=event_id,
                    thread_id=thread_id),
                payload,
            ))
            buf = buf[event_length:]
    return events


def _has_conn_for_port(events, port):
    """True if `events` contains a TCP CONN_SET_IP_V4 event for `port`
    (as either side of the connection)."""
    for hdr, payload in events:
        if hdr.event_id != TCP_EVENT_CONN_SET_IP_V4:
            continue
        info = parse_conn_set_ip_v4_payload(payload)
        if info["src_port"] == port or info["dst_port"] == port:
            return True
    return False


_TCP_FUNCTION_BLK = 8192


def _tcp_function_entries():
    """(name, alias) rows from net.inet.tcp.functions_available."""
    raw = _sysctl_get("net.inet.tcp.functions_available")
    if not raw:
        return []
    entries = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith(("Stack", "-")):
            continue
        toks = line.split()
        if len(toks) < 2:
            continue
        name = toks[0]
        if toks[1] == "*":
            alias = toks[2] if len(toks) > 2 else "-"
        else:
            alias = toks[1]
        if alias == "-":
            alias = None
        entries.append((name, alias))
    return entries


def _frozen_quarter_key(name):
    """Sort key for frozen snapshots (ngen_23q12p14, ngen_26q32), else None."""
    m = re.match(r"^[a-z]+_(\d+)q(\d+)(?:p(\d+))?$", name)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3) or 0))


def _pick_alt_tcp_stack(exclude=None):
    """A loaded ngen/rack stack with an eventlog provider, not `exclude`."""
    entries = _tcp_function_entries()
    if exclude is None:
        exclude = _sysctl_get("net.inet.tcp.functions_default")
    if not entries or exclude is None:
        return None
    aliases_by_name = {}
    for name, alias in entries:
        aliases_by_name.setdefault(name, set()).add(alias)
    exact, latest, current, frozen = [], [], [], []
    for name, aliases in aliases_by_name.items():
        if name == exclude:
            continue
        base = name.split("_", 1)[0]
        if base not in ("ngen", "rack"):
            continue
        if name == base:
            exact.append(name)
        elif aliases & {"ngen_latest", "rack_latest"} or \
                name.endswith("_latest"):
            latest.append(name)
        elif _frozen_quarter_key(name) is None:
            current.append(name)
        else:
            frozen.append(name)
    for group in (exact, latest, current):
        if group:
            return sorted(group)[0]
    if frozen:
        # Older frozen snapshots have no eventlog provider; take the newest.
        return max(frozen, key=_frozen_quarter_key)
    return None


def _tcp_switch_stack(sock, stack_name):
    fsn = struct.pack("32sI", stack_name.encode("ascii"), 0)
    sock.setsockopt(socket.IPPROTO_TCP, _TCP_FUNCTION_BLK, fsn)


def _fetch_tcp_decode_blob():
    """The real "tcp" decode blob, for user-space providers that want a
    schema elog can genuinely resolve keyword names against (KEYWORD CONN 8
    => bit 7 => 0x80 in tcp_eventlog_schema.src)."""
    with _open_eventlog() as fd:
        probe = _get_decode_blob(fd, name="tcp")
        out = (ctypes.c_char * probe.blob_size)()
        _get_decode_blob(fd, name="tcp", out_buf=out)
        return bytes(out)


class _SetSubscriptionKeywordsReq(ctypes.Structure):
    # Mirrors struct eventlog_set_subscription_keywords_req.
    _fields_ = [
        ("provider_name", ctypes.c_char * EVENTLOG_PROVIDER_NAME_MAX),
        ("keywords", ctypes.c_uint32),
    ]


_EVENTLOG_IOCTL_SET_SUBSCRIPTION_KEYWORDS = _freebsd_iow(
    "E", 14, ctypes.sizeof(_SetSubscriptionKeywordsReq))


def _set_subscription_keywords(fd, provider_name, keywords):
    req = _SetSubscriptionKeywordsReq()
    req.provider_name = provider_name.encode()
    req.keywords = keywords
    fcntl.ioctl(fd, _EVENTLOG_IOCTL_SET_SUBSCRIPTION_KEYWORDS, req, True)


class TestTcpEventlogStackSwitchDump(BaseTest):
    """Regression for auto_ratio sessions that switch TCP stacks."""

    @pytest.mark.require_user("root")
    @pytest.mark.timeout(60)
    def test_auto_ratio_session_dumps_conn_on_stack_switch(self):
        """auto_ratio enables a session without TF2_EVENTLOG_ENABLED.
        After a mid-connection stack switch the new session must still
        get CONN_SET_IP_* from tcp_eventlog_dump_session()."""
        _require_eventlog_dev()
        alt_stack = _pick_alt_tcp_stack(exclude="freebsd")
        if alt_stack is None:
            pytest.skip("need ngen/rack with an eventlog provider")
        port = _pick_port(salt=71)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "0"), \
             sysctl_override("kern.eventlog.tcp.auto_ratio", "1"):
            with _raw_subscribe("tcp") as fd:
                with loopback_pair(socket.AF_INET, port) as (_conn, cli):
                    _read_raw_events(fd, timeout_s=1.0)
                    _tcp_switch_stack(cli, alt_stack)
                    after = _read_raw_events(fd, timeout_s=3.0)
                    assert _has_conn_for_port(after, port), (
                        f"no CONN_SET_IP_V4 for port {port} after "
                        f"stack switch to {alt_stack}")

class TestEventlogSetSubscriptionKeywordsIoctl(BaseTest):
    """Direct ioctl-level coverage for
    EVENTLOG_IOCTL_SET_SUBSCRIPTION_KEYWORDS, which elog(1) uses to narrow
    a name-based keyword filter once the provider publishes a blob."""

    @pytest.mark.require_user("root")
    @pytest.mark.timeout(60)
    def test_narrows_delivery_on_live_subscription(self):
        """Subscribe to everything, then set a single keyword and confirm
        the kernel stops delivering events tagged with the others."""
        _require_eventlog_dev()

        pname = "uprov_kwset"
        with _UserRingProvider(pname) as prov:
            with _raw_subscribe(pname) as fd:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 1)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 2)),
                ])
                wide = _read_raw_events(fd, timeout_s=2.0)
                payloads = [p for _, p in wide]
                assert struct.pack("<I", 1) in payloads, (
                    "CONN-tagged event missing before narrowing")
                assert struct.pack("<I", 2) in payloads, (
                    "RX-tagged event missing before narrowing")

                _set_subscription_keywords(fd, pname, TCP_KEYWORD_CONN)

                ts += 1000
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 3)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 4)),
                ])
                narrowed = [p for _, p in _read_raw_events(fd, timeout_s=2.0)]
                assert struct.pack("<I", 3) in narrowed, (
                    "CONN-tagged event lost after narrowing to CONN")
                assert struct.pack("<I", 4) not in narrowed, (
                    "RX-tagged event still delivered after narrowing "
                    "to CONN")

    @pytest.mark.require_user("root")
    @pytest.mark.timeout(30)
    def test_unsubscribed_provider_enoent(self):
        """A provider name this fd never subscribed to has no mask to
        set."""
        _require_eventlog_dev()

        with _raw_subscribe("uprov_kwset_a") as fd:
            with pytest.raises(OSError) as excinfo:
                _set_subscription_keywords(fd, "uprov_kwset_b", 0x1)
            assert excinfo.value.errno == errno.ENOENT


class TestEventlogTriggerDumpStateIoctl(BaseTest):
    """Direct ioctl-level coverage for EVENTLOG_IOCTL_TRIGGER_DUMP_STATE.
    Complements the kernel-internal dump_state_manual_trigger_* ktest
    cases (kern_eventlog_test.c) by exercising the real character-device
    ioctl dispatch in eventlog_dev_ioctl(), which those ktests can't
    reach (no devfs cdevpriv in the ktest harness)."""

    @pytest.mark.require_user("root")
    @pytest.mark.timeout(60)
    def test_trigger_refires_tcp_dump_on_existing_subscription(self):
        """Subscribe to tcp with no DUMP_STATE flag (so the initial read
        is clean), then issue EVENTLOG_IOCTL_TRIGGER_DUMP_STATE on that
        same fd and confirm the pre-existing loopback session's identity
        (SESSION_CREATE / CONN_SET_IP_V4) gets replayed -- without a
        second subscribe/fd."""
        _require_eventlog_dev()
        port = _pick_port(salt=21)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with loopback_pair(socket.AF_INET, port):
                with _raw_subscribe("tcp") as fd:
                    baseline = _read_raw_events(fd, timeout_s=1.0)
                    assert not _has_conn_for_port(baseline, port), (
                        "saw a dump replay before any trigger was issued")

                    fcntl.ioctl(fd, _EVENTLOG_IOCTL_TRIGGER_DUMP_STATE)

                    replayed = _read_raw_events(fd, timeout_s=3.0)
                    assert _has_conn_for_port(replayed, port), (
                        f"no dump replay for port {port} after "
                        f"EVENTLOG_IOCTL_TRIGGER_DUMP_STATE")

    @pytest.mark.require_user("root")
    @pytest.mark.timeout(60)
    def test_trigger_not_fanned_out_to_other_subscriber(self):
        """A second, independent tcp subscriber must not see a replay
        triggered on the first one's fd -- the kernel scopes the replay
        to the calling subscriber only (evl.dump_target/evl.dump_thread)."""
        _require_eventlog_dev()
        port = _pick_port(salt=22)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with loopback_pair(socket.AF_INET, port):
                with _raw_subscribe("tcp") as fd_a, \
                     _raw_subscribe("tcp") as fd_b:
                    # Drain each fd's own initial (dump-less) backlog.
                    _read_raw_events(fd_a, timeout_s=0.5)
                    _read_raw_events(fd_b, timeout_s=0.5)

                    fcntl.ioctl(fd_a, _EVENTLOG_IOCTL_TRIGGER_DUMP_STATE)

                    replayed_a = _read_raw_events(fd_a, timeout_s=3.0)
                    replayed_b = _read_raw_events(fd_b, timeout_s=1.0)

                    assert _has_conn_for_port(replayed_a, port), (
                        "triggering fd did not see its own dump replay")
                    assert not _has_conn_for_port(replayed_b, port), (
                        "un-triggered fd saw a dump replay meant for "
                        "another subscriber")


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
            assert "--scenario" in r.stderr, f"elog {flag} lists --scenario"

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
    def test_unknown_scenario(self):
        r = subprocess.run(
            [ELOG, "-S", "not-a-scenario"], capture_output=True, text=True)
        assert r.returncode == 1
        assert "unknown scenario" in r.stderr
        assert "cpu" in r.stderr
        assert "net" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_unknown_scenario_in_list(self):
        r = subprocess.run(
            [ELOG, "-S", "cpu|not-a-scenario"], capture_output=True, text=True)
        assert r.returncode == 1
        assert "unknown scenario: not-a-scenario" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_empty_scenario_token(self):
        r = subprocess.run(
            [ELOG, "-S", "cpu|"], capture_output=True, text=True)
        assert r.returncode == 1
        assert "empty scenario" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_scenario_cpu_is_subscribe(self, tmp_path):
        """-S cpu registers cpu/process/symbols subscriptions, so -r
        rejects it on the subscribe-options conflict. The cpu preset
        takes every provider at its default level/keywords, so this
        stays hermetic -- unlike the net preset, whose keyword names
        resolve against the live tcp decode blob (see
        test_scenario_net_keywords_resolve)."""
        target = tmp_path / "does-not-exist.elog"
        r = subprocess.run(
            [ELOG, "-S", "cpu", "-r", str(target)],
            capture_output=True, text=True)
        assert r.returncode == 1
        assert "cannot be used with subscribe" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_scenario_net_advertised(self):
        r = subprocess.run([ELOG, "-h"], capture_output=True, text=True)
        assert "net:" in r.stderr
        assert "SAMPLE|SAMPLE_HIST" in r.stderr
        assert "(alias: network)" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_gzip_invalid_level(self, tmp_path):
        capture = tmp_path / "cap.elog"
        r = subprocess.run(
            [ELOG, "-c", "tcp", "-o", str(capture), "--gzip=0"],
            capture_output=True, text=True)
        assert r.returncode == 1
        assert "--gzip" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_gzip_requires_binary_output(self):
        r = subprocess.run(
            [ELOG, "-c", "tcp", "--gzip"], capture_output=True, text=True)
        assert r.returncode == 1
        assert "--gzip requires binary output" in r.stderr

    @pytest.mark.require_progs(["elog"])
    @pytest.mark.parametrize(
        "operand",
        [
            pytest.param("capture.elog", id="filename"),
            pytest.param("CONN||RX", id="empty_token"),
            pytest.param("|CONN", id="leading_pipe"),
            pytest.param("CONN|", id="trailing_pipe"),
            pytest.param("CONN RX", id="space_separated"),
        ],
    )
    def test_keywords_operand_must_look_like_names(self, operand):
        """Only '|'-separated identifiers are taken as a keyword list.
        Anything else stays with the next option, which then rejects it —
        without a decode blob there is nothing else to tell the two apart.
        """
        r = subprocess.run(
            [ELOG, "-s", "-c", "tcp", "INFO", operand],
            capture_output=True, text=True, timeout=20)
        assert r.returncode == 1, f"stdout={r.stdout} stderr={r.stderr}"
        assert "unexpected argument" in r.stderr, r.stderr

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

    @pytest.mark.require_progs(["elog"])
    def test_read_rejects_v1(self, tmp_path):
        """The obsolete v1 format (no schema_id, no decode-blob section) is
        no longer read: elog must reject it cleanly rather than try to
        decode it by provider name."""
        f = tmp_path / "v1.elog"
        buf = bytearray()
        buf += struct.pack(ELOG_BINARY_HEADER_FMT_LEGACY, ELOG_BINARY_MAGIC,
                           1, 0, 0, 0, 0)
        buf += struct.pack("<I", 1)                      # provider_count
        buf += struct.pack(ELOG_PROVIDER_INFO_FMT_V1, 1, b"tcp")
        f.write_bytes(buf)
        r = subprocess.run(
            [ELOG, "-r", str(f)], capture_output=True, text=True)
        assert r.returncode != 0
        assert "Unsupported file version" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_read_accepts_v2(self, tmp_path):
        """The v2 format (schema_id + decode-blob section, but a fixed
        40-byte header with a scalar dropped_events field instead of the
        counter array) shipped in a release and is still read. A non-zero
        dropped_events makes the fixture fail loudly if the header tail is
        parsed as if it were v3."""
        f = tmp_path / "v2.elog"
        buf = bytearray()
        buf += struct.pack(ELOG_BINARY_HEADER_FMT_LEGACY, ELOG_BINARY_MAGIC,
                           2, 0, 0, 1, 0x1122334455667788)
        buf += struct.pack("<I", 0)                      # provider_count
        buf += struct.pack("<I", 0)                      # blob_count
        buf += struct.pack(ELOG_EVENT_HEADER_FMT, ELOG_EVENT_HEADER_SIZE,
                           0, 1, 0, 1000, 42, 7, 99)
        f.write_bytes(buf)
        r = subprocess.run(
            [ELOG, "-r", str(f)], capture_output=True, text=True)
        assert r.returncode == 0, r.stderr
        assert "Unsupported file version" not in r.stderr
        assert r.stdout.strip(), "v2 file decoded to no output"

    @pytest.mark.require_progs(["elog"])
    def test_read_rejects_future_version(self, tmp_path):
        f = tmp_path / "v99.elog"
        f.write_bytes(struct.pack(
            ELOG_BINARY_HEADER_FMT, ELOG_BINARY_MAGIC, 99, 0, 0, 0, 0))
        r = subprocess.run(
            [ELOG, "-r", str(f)], capture_output=True, text=True)
        assert r.returncode != 0
        assert "Unsupported file version" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_read_rejects_oversized_embedded_blob(self, tmp_path):
        """An embedded blob whose size exceeds EVENTLOG_DECODE_BLOB_MAX is
        rejected before any allocation (bounds the read of untrusted data)."""
        sid = bytes(range(EVENTLOG_DECODE_SCHEMA_ID_LEN))
        buf = bytearray()
        buf += struct.pack(ELOG_BINARY_HEADER_FMT, ELOG_BINARY_MAGIC,
                           ELOG_BINARY_VERSION, 0, 0, 0, 0)  # counter_count=0
        buf += struct.pack("<I", 1)
        buf += struct.pack(ELOG_PROVIDER_INFO_FMT_V2, 1, b"tcp", sid)
        buf += struct.pack("<I", 1)              # blob_count
        buf += sid                               # blob schema_id
        buf += struct.pack("<I", 0x7FFFFFFF)     # blob_size >> 16 MiB max
        f = tmp_path / "bigblob.elog"
        f.write_bytes(buf)
        r = subprocess.run(
            [ELOG, "-r", str(f)], capture_output=True, text=True)
        assert r.returncode != 0
        assert "Invalid embedded decode-blob size" in r.stderr

    @pytest.mark.require_progs(["elog"])
    def test_read_rejects_truncated_embedded_blob(self, tmp_path):
        """A blob section that claims more bytes than the file holds must
        fail cleanly (no over-read, no crash)."""
        sid = bytes(range(EVENTLOG_DECODE_SCHEMA_ID_LEN))
        buf = bytearray()
        buf += struct.pack(ELOG_BINARY_HEADER_FMT, ELOG_BINARY_MAGIC,
                           ELOG_BINARY_VERSION, 0, 0, 0, 0)  # counter_count=0
        buf += struct.pack("<I", 1)
        buf += struct.pack(ELOG_PROVIDER_INFO_FMT_V2, 1, b"tcp", sid)
        buf += struct.pack("<I", 1)              # blob_count
        buf += sid
        buf += struct.pack("<I", 4096)           # claims 4096 bytes...
        buf += EVENTLOG_DECODE_MAGIC + b"\0" * 4  # ...but only 8 present
        f = tmp_path / "truncblob.elog"
        f.write_bytes(buf)
        r = subprocess.run(
            [ELOG, "-r", str(f)], capture_output=True, text=True)
        assert r.returncode != 0
        # Clean diagnostic, not a crash/over-read.
        assert "Unexpected end of file" in r.stderr


class TestGetDecodeBlobIoctl(BaseTest):
    """Exercise the EVENTLOG_IOCTL_GET_DECODE_BLOB ABI directly, including
    the error branches the elog binary never hits. The kernel's "tcp"
    providers register a decode blob and live on the global provider list
    without any subscription, so they back these lookups."""

    @pytest.mark.require_user("root")
    def test_by_name_size_probe_then_fetch(self):
        with _open_eventlog() as fd:
            # Two-call protocol: probe first (buf == 0) for the size.
            probe = _get_decode_blob(fd, name="tcp")
            assert probe.blob_size > 0
            n = probe.blob_size
            out = (ctypes.c_char * n)()
            got = _get_decode_blob(fd, name="tcp", out_buf=out)
            assert got.blob_size == n
            assert bytes(out)[:len(EVENTLOG_DECODE_MAGIC)] == \
                EVENTLOG_DECODE_MAGIC

    @pytest.mark.require_user("root")
    def test_by_schema_id_matches_by_name(self):
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            n = probe.blob_size
            out = (ctypes.c_char * n)()
            _get_decode_blob(fd, name="tcp", out_buf=out)
            blob = bytes(out)
            # The schema_id is the content-addressed key; recompute it and
            # confirm the by-schema_id lookup returns the identical blob.
            sid = hashlib.sha256(blob).digest()[
                :EVENTLOG_DECODE_SCHEMA_ID_LEN]
            probe2 = _get_decode_blob(fd, schema_id=sid)
            assert probe2.blob_size == n
            out2 = (ctypes.c_char * n)()
            _get_decode_blob(fd, schema_id=sid, out_buf=out2)
            assert bytes(out2) == blob

    @pytest.mark.require_user("root")
    def test_unknown_name_enoent(self):
        with _open_eventlog() as fd:
            with pytest.raises(OSError) as ei:
                _get_decode_blob(fd, name="no_such_provider_xyz")
            assert ei.value.errno == errno.ENOENT

    @pytest.mark.require_user("root")
    def test_unknown_schema_id_enoent(self):
        with _open_eventlog() as fd:
            # An all-zero schema_id is what a blob-less provider reports, and
            # such providers are skipped, so nothing matches.
            with pytest.raises(OSError) as ei:
                _get_decode_blob(fd, schema_id=ELOG_ZERO_SCHEMA_ID)
            assert ei.value.errno == errno.ENOENT

    @pytest.mark.require_user("root")
    def test_bad_lookup_kind_einval(self):
        with _open_eventlog() as fd:
            with pytest.raises(OSError) as ei:
                _get_decode_blob(fd, name="tcp", lookup_kind=2)
            assert ei.value.errno == errno.EINVAL

    @pytest.mark.require_user("root")
    def test_buffer_too_small_enospc(self):
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            assert probe.blob_size > 1
            out = (ctypes.c_char * 1)()
            with pytest.raises(OSError) as ei:
                _get_decode_blob(fd, name="tcp", out_buf=out)
            assert ei.value.errno == errno.ENOSPC


class _EventHeader(ctypes.Structure):
    """Mirrors struct eventlog_event_header (sys/eventlog_subscriber.h)."""
    _fields_ = [
        ("event_length", ctypes.c_uint16),
        ("cpu", ctypes.c_uint16),
        ("provider_id", ctypes.c_uint16),
        ("RESERVED", ctypes.c_uint16),
        ("timestamp", ctypes.c_uint64),
        ("session_id", ctypes.c_uint64),
        ("event_id", ctypes.c_uint32),
        ("thread_id", ctypes.c_int32),
    ]


class _UserFilePayload(ctypes.Structure):
    """Mirrors struct symbols_eventlog_user_file
    (lib/libelog_user_symbols/libelog_user_symbols.c)."""
    _fields_ = [
        ("user_file_id", ctypes.c_uint32),
        ("build_id", ctypes.c_char * 41),
        ("pathname", ctypes.c_char * 128),
    ]


_EmitFn = ctypes.CFUNCTYPE(
    None, ctypes.POINTER(_EventHeader), ctypes.c_void_p, ctypes.c_size_t,
    ctypes.c_void_p)

# Must match the SYMBOLS_EVENTLOG_*_ID values in libelog_user_symbols.c.
_SYMBOLS_EVENTLOG_USER_FILE_ID = 3
_SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID = 4
_SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID = 7


class _UserSymbolRange(ctypes.Structure):
    """Packed mirror of symbols_eventlog_user_symbol_range."""
    _pack_ = 1
    _fields_ = [
        ("user_file_id", ctypes.c_uint32),
        ("offset", ctypes.c_uint64),
        ("size", ctypes.c_uint32),
        ("name", ctypes.c_char * 96),
    ]


def _write_go_pclntab_elf(path, gnu_note=False):
    """Minimal ET_DYN whose only functions live in a Go 1.20 .gopclntab."""

    def u16(v):
        return v.to_bytes(2, "little")

    def u32(v):
        return v.to_bytes(4, "little")

    def u64(v):
        return v.to_bytes(8, "little")

    func_names = b"main.main\0main.helper\0"
    hdr_sz = 8 + 8 * 8
    funcname_off = hdr_sz
    pcln_off = funcname_off + len(func_names)
    functab_sz = (2 * 2 + 1) * 4
    func0_off = functab_sz
    func1_off = functab_sz + 24
    functab = (u32(0) + u32(func0_off) + u32(0x20) + u32(func1_off) +
               u32(0x30))
    funcs = (u32(0) + u32(0) + b"\0" * 16 +
             u32(0x20) + u32(len(b"main.main") + 1) + b"\0" * 16)
    pcln = functab + funcs
    blob = bytearray(pcln_off + len(pcln))
    blob[0:4] = u32(0xfffffff1)
    blob[4:8] = bytes((0, 0, 1, 8))

    def put(word, val):
        blob[8 + word * 8:8 + word * 8 + 8] = u64(val)

    put(0, 2)
    put(2, 0x400000)
    put(3, funcname_off)
    put(7, pcln_off)
    blob[funcname_off:funcname_off + len(func_names)] = func_names
    blob[pcln_off:] = pcln

    go_note = u32(3) + u32(8) + u32(4) + b"Go\0" + b"buildid!"
    gnu_bytes = b""
    if gnu_note:
        gnu_bytes = u32(4) + u32(20) + u32(3) + b"GNU\0" + (b"\xab" * 20)

    text = b"\x90" * 0x30
    shstr = bytearray(b"\0")

    def add_name(name):
        idx = len(shstr)
        shstr.extend(name + b"\0")
        return idx

    name_text = add_name(b".text")
    name_pcln = add_name(b".gopclntab")
    name_gonote = add_name(b".note.go.buildid")
    name_gnunote = add_name(b".note.gnu.build-id") if gnu_note else None
    name_shstr = add_name(b".shstrtab")

    text_off = 0x1000
    pcln_file = text_off + len(text)
    gonote_file = pcln_file + len(blob)
    gnunote_file = gonote_file + len(go_note)
    shstr_file = gnunote_file + len(gnu_bytes)
    shoff = shstr_file + len(shstr)
    if shoff % 8:
        shoff += 8 - (shoff % 8)

    def shdr(name, typ, flags, addr, off, size):
        return (u32(name) + u32(typ) + u64(flags) + u64(addr) + u64(off) +
                u64(size) + u32(0) + u32(0) + u64(1) + u64(0))

    shdrs = [b"\0" * 64]
    shdrs.append(shdr(name_text, 1, 6, 0x400000, text_off, len(text)))
    shdrs.append(shdr(name_pcln, 1, 2, 0, pcln_file, len(blob)))
    shdrs.append(shdr(name_gonote, 7, 0, 0, gonote_file, len(go_note)))
    if gnu_note:
        shdrs.append(shdr(name_gnunote, 7, 0, 0, gnunote_file, len(gnu_bytes)))
    shdrs.append(shdr(name_shstr, 3, 0, 0, shstr_file, len(shstr)))

    ehdr = bytearray(64)
    ehdr[0:4] = b"\x7fELF"
    ehdr[4] = 2
    ehdr[5] = 1
    ehdr[6] = 1
    ehdr[16:18] = u16(3)
    ehdr[18:20] = u16(62)
    ehdr[20:24] = u32(1)
    ehdr[24:32] = u64(0x400000)
    ehdr[32:40] = u64(64)
    ehdr[40:48] = u64(shoff)
    ehdr[52:54] = u16(64)
    ehdr[54:56] = u16(56)
    ehdr[56:58] = u16(1)
    ehdr[58:60] = u16(64)
    ehdr[60:62] = u16(len(shdrs))
    ehdr[62:64] = u16(len(shdrs) - 1)
    phdr = (u32(1) + u32(5) + u64(text_off) + u64(0x400000) + u64(0x400000) +
            u64(len(text)) + u64(len(text)) + u64(0x1000))

    out = bytearray(shoff + 64 * len(shdrs))
    out[0:64] = ehdr
    out[64:120] = phdr
    out[text_off:text_off + len(text)] = text
    out[pcln_file:pcln_file + len(blob)] = blob
    out[gonote_file:gonote_file + len(go_note)] = go_note
    if gnu_note:
        out[gnunote_file:gnunote_file + len(gnu_bytes)] = gnu_bytes
    out[shstr_file:shstr_file + len(shstr)] = shstr
    for i, s in enumerate(shdrs):
        out[shoff + i * 64:shoff + (i + 1) * 64] = s
    path.write_bytes(out)


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
    def test_capture_embed_decode(self, tmp_path):
        """A plain binary capture (no --no-embed-decode) embeds provider
        decode blobs by default, and the file decodes from its embedded
        blobs."""
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=7)
        payload = b"embed decode blob\n"

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", capture_path=capture):
                received = loopback_oneshot(socket.AF_INET, port, payload)
                assert payload.rstrip(b"\n") in received
                time.sleep(2)

        # Parse the raw file: it must be the current version (so the blob
        # section is present) and carry a "tcp" decode blob with the EDB1
        # magic.
        data = Path(capture).read_bytes()
        assert data[:4] == ELOG_BINARY_MAGIC, "bad capture magic"
        (version,) = struct.unpack_from("<I", data, 4)
        assert version == ELOG_BINARY_VERSION, (
            f"expected v{ELOG_BINARY_VERSION}, got {version}")

        # parse_elog_binary validates the blob-section framing/magic; also
        # confirm at least one blob was actually embedded for "tcp".
        file_hdr, providers, events, meta = parse_elog_binary(capture)
        assert "tcp" in providers.values(), "tcp provider missing from file"
        assert meta.embedded_schema_ids, \
            "no decode blobs embedded by default"

        # Each tcp provider must carry a non-zero schema_id, and that
        # schema_id must resolve to an embedded blob: this is the durable
        # provider_id -> schema_id -> blob binding the capture relies on to
        # decode later without the originating kernel.
        tcp_ids = {pid for pid, name in providers.items() if name == "tcp"}
        assert tcp_ids, "tcp provider missing from file"
        embedded = set(meta.embedded_schema_ids)
        for pid in tcp_ids:
            schema_id = meta.provider_schema_ids[pid]
            assert schema_id != ELOG_ZERO_SCHEMA_ID, (
                f"tcp provider id={pid} has a zero schema_id")
            assert schema_id in embedded, (
                f"tcp provider id={pid} schema_id not embedded "
                f"(embedded={[s.hex() for s in embedded]})")

        # And the capture still decodes (here, from the embedded blobs).
        decoded = decode_capture(capture)
        _assert_in_decode(decoded, "[tcp]", "tcp provider tag")
        _assert_in_decode(decoded, "[SESSION_CREATE]", "SESSION_CREATE event")

        # The same capture rewritten with a v2 header must decode
        # identically: only the header tail changed between the versions.
        v2 = tmp_path / "capture-v2.elog"
        downgrade_capture_to_v2(capture, v2)
        _, v2_providers, v2_events, v2_meta = parse_elog_binary(v2)
        assert v2_meta.version == 2
        assert v2_providers == providers
        assert v2_events == events
        assert decode_capture(v2) == decoded, \
            "v2 capture decoded differently from the v3 original"

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_no_embed_decode(self, tmp_path):
        """elog -N suppresses the default decode-blob embedding: the file is
        still the current version, but its blob section is empty."""
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=17)
        payload = b"no embed decode blob\n"

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-N", "-c", "tcp", capture_path=capture):
                received = loopback_oneshot(socket.AF_INET, port, payload)
                assert payload.rstrip(b"\n") in received
                time.sleep(2)

        data = Path(capture).read_bytes()
        assert data[:4] == ELOG_BINARY_MAGIC, "bad capture magic"
        (version,) = struct.unpack_from("<I", data, 4)
        assert version == ELOG_BINARY_VERSION, (
            f"expected v{ELOG_BINARY_VERSION}, got {version}")

        file_hdr, providers, events, meta = parse_elog_binary(capture)
        assert "tcp" in providers.values(), "tcp provider missing from file"
        assert not meta.embedded_schema_ids, \
            "decode blobs embedded despite --no-embed-decode"

        # The provider table's schema_id is still populated (it is not
        # conditional on embedding); only the blob bytes themselves are
        # withheld. Decoding falls back to the live kernel by schema_id.
        tcp_ids = {pid for pid, name in providers.items() if name == "tcp"}
        assert tcp_ids, "tcp provider missing from file"
        for pid in tcp_ids:
            assert meta.provider_schema_ids[pid] != ELOG_ZERO_SCHEMA_ID, (
                f"tcp provider id={pid} has a zero schema_id")

        decoded = decode_capture(capture)
        _assert_in_decode(decoded, "[tcp]", "tcp provider tag")
        _assert_in_decode(decoded, "[SESSION_CREATE]", "SESSION_CREATE event")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_tampered_embedded_blob_falls_back(self, tmp_path):
        """An embedded decode blob is self-verifying: its bytes must hash to
        the schema_id recorded in the provider table. If the blob is
        tampered with, elog rejects it (warns) and falls back to resolving
        the schema live by schema_id - it never decodes with the wrong
        blob."""
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=11)
        payload = b"tamper embedded blob\n"

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", capture_path=capture):
                received = loopback_oneshot(socket.AF_INET, port, payload)
                assert payload.rstrip(b"\n") in received
                time.sleep(2)

        # Baseline: the untouched capture decodes from its embedded blob.
        _assert_in_decode(decode_capture(capture), "[SESSION_CREATE]",
                          "baseline decode")

        # Flip a byte inside the first embedded blob body (past the EDB1
        # magic) so it no longer hashes to its recorded schema_id, while
        # leaving the provider table's schema_id intact.
        data = bytearray(Path(capture).read_bytes())
        edb1 = data.find(EVENTLOG_DECODE_MAGIC)
        assert edb1 > ELOG_BINARY_HEADER_SIZE, "no embedded blob found"
        data[edb1 + len(EVENTLOG_DECODE_MAGIC) + 2] ^= 0xFF
        Path(capture).write_bytes(data)

        # The live tcp provider still has the real blob, so decode succeeds
        # via the by-schema_id fallback, and elog warns about the bad blob.
        r = subprocess.run(
            [ELOG, "-e", "-r", str(capture)], capture_output=True, text=True)
        assert r.returncode == 0, f"stderr={r.stderr}"
        assert "does not match its schema_id" in r.stderr
        _assert_in_decode(r.stdout, "[SESSION_CREATE]", "fallback decode")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_tcp_dump_state(self, tmp_path):
        """Validate the elog -D (DUMP_STATE) flow.

        Open a tcp connection BEFORE subscribing, then run elog with -D.
        The CREATE IOCTL invokes tcp_eventlog_dump_state inline on this
        thread; the callback walks every TCP PCB and re-emits
        SESSION_CREATE / CONN_SET_IP_V4 / CONN_PARAMS_V2 for each
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
            ("Connection parameters: ISS", "CONN_PARAMS_V2 in dump"),
            (", MSS ",           "MSS field of CONN_PARAMS_V2 in dump"),
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
    def test_capture_multi_provider(self, tmp_path):
        """Subscribe to two providers in one elog invocation and
        verify the multi-subscription path works end-to-end.

        `elog -c tcp -c hpts` issues a single CREATE IOCTL with two
        subscription requests. Each becomes its own kernel-side
        eventlog_subscriber, but they share one consumer (the cdev
        file descriptor). This test exercises the kernel's
        multi-subscription dispatch fan-out and the userland
        decoder's ability to interleave events from different
        providers in one output stream.

        We assert that elog accepts the multi-`-c` syntax cleanly
        (elog_capture's clean-exit check), that the capture isn't
        empty (events arrived through at least one subscriber), and
        that tcp events appear (tcp dispatch works alongside an hpts
        subscription).

        We do NOT require [hpts] events to appear. The hpts provider
        only emits live events from stacks that schedule on HPTS for
        timer-driven output (rack, bbr); the default `freebsd` stack
        sends inline and never schedules on HPTS, so a freebsd-stack
        loopback exchange typically produces zero hpts events. The
        invariant we care about - that the multi-subscription path
        doesn't crash and routes events for at least one of the two
        providers - is fully validated by the assertions below.
        """
        _require_eventlog_dev()

        # Both providers must be registered. Skip if hpts isn't built
        # into the running kernel.
        if _sysctl_get("kern.eventlog.hpts.sessions_active") is None:
            pytest.skip("hpts eventlog provider not registered")

        capture = tmp_path / "capture.elog"
        port = _pick_port(salt=4)

        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", "-c", "hpts",
                              capture_path=capture):
                received = loopback_oneshot(
                    socket.AF_INET, port, b"multi-provider\n")
                assert b"multi-provider" in received
                time.sleep(2)

        decoded = decode_capture(capture)
        assert decoded.strip(), "decoded capture is empty"
        _assert_in_decode(decoded, "[tcp]", "tcp provider tag in capture")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_cpu_samples(self, tmp_path):
        """elog -c cpu arms the hwpmc sampler and captures CPU_SAMPLE
        events.

        Exercises the full pmc_sample path end-to-end: the provider's
        pmchz sysctl arms a per-CPU CPU_CYCLES PMC, overflows deliver
        callchains through pmc_sampler_deliver, and the events land in
        the capture. This is the test that would have caught the arm64
        path returning ENOTSUP (no pmc_md_resolve_sample_event) or
        silently dropping samples (the x86-only KERNEL_SAMPLER gate in
        hwpmc_mod.c).

        Skips cleanly when the cpu provider isn't registered (kernel
        built without hwpmc) or when the platform can't arm a cycles
        PMC (e.g. a VM with no PMU passthrough) -- in the latter case
        the provider emits ARM_FAILED instead of CPU_SAMPLE, which the
        test detects and reports as a skip rather than a failure.
        """
        _require_eventlog_dev()

        # The cpu provider registers kern.eventlog.cpu.pmchz only when
        # hwpmc is compiled in.
        if _sysctl_get("kern.eventlog.cpu.pmchz") is None:
            pytest.skip("cpu eventlog provider not registered")

        capture = tmp_path / "capture.elog"
        with sysctl_override("kern.eventlog.cpu.pmchz", "100"):
            with elog_capture("-c", "cpu", capture_path=capture):
                # 100 Hz/CPU for ~3s: hundreds of samples even on an
                # idle machine.
                time.sleep(3)

        decoded = decode_capture_or_empty(capture)
        if "hwpmc arm failed" in decoded:
            vm_guest = _sysctl_get("kern.vm_guest")
            if vm_guest is not None and vm_guest != "none":
                pytest.skip("hwpmc could not arm a cycles PMC in this "
                            f"{vm_guest} guest")
            # EBUSY (16): every programmable PMC row is already taken.
            # That is an environment condition, not the missing-pc_clock
            # regression this test is meant to catch.
            if re.search(r"hwpmc arm failed: error=16\b", decoded):
                pytest.skip("hwpmc arm failed with EBUSY (PMC rows busy)")
            pytest.fail("hwpmc could not arm a cycles PMC on physical "
                        f"hardware:\n{decoded[:2000]}")
        _assert_in_decode(decoded, "[cpu]", "cpu provider tag in capture")
        _assert_in_decode(decoded, "sample tid=",
                          "CPU_SAMPLE events in capture")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    @pytest.mark.parametrize(
        "keyword,expected_present,expected_absent",
        [
            pytest.param("RX", "[IN]", "[OUT]", id="RX_only"),
            pytest.param("TX", "[OUT]", "[IN]", id="TX_only"),
            pytest.param("^RX", "[OUT]", "[IN]", id="negate_RX"),
            pytest.param("^TX", "[IN]", "[OUT]", id="negate_TX"),
            pytest.param("RX|^TX", "[IN]", "[OUT]", id="RX_minus_TX"),
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

        A keyword name prefixed with '^' is negated: '^RX' subscribes
        to every keyword except RX, so OUT events appear but IN events
        do not. Mixing positive and negated names subtracts the
        negated ones from the positive set, so 'RX|^TX' is equivalent
        to plain 'RX'.
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
    def test_scenario_net_keywords_resolve(self, tmp_path):
        """`-S net` spells its tcp filter as the keyword names
        SAMPLE|SAMPLE_HIST and resolves them against the live decode
        blob, the same path `-c tcp SAMPLE|SAMPLE_HIST` takes. A name
        that no longer exists in tcp_eventlog_schema.src makes elog(1)
        exit during argument parsing, which elog_capture reports as an
        early exit -- so this fails loudly on a schema rename instead
        of quietly subscribing to the wrong bits.
        """
        _require_eventlog_dev()

        capture = tmp_path / "capture.elog"
        with elog_capture("-S", "net", capture_path=capture):
            time.sleep(1)

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
          3) every per-session file decodes successfully, and every
             per-connection file contains a SESSION_CREATE event
             (provider-wide sessions such as the aggregate sampler
             predate the capture and are exempt)
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

        # Every per-session file must decode. Per-connection sessions are
        # created live during the capture and must announce themselves with
        # SESSION_CREATE. Provider-wide sessions (e.g. the aggregate
        # TCP_SAMPLE session) never get a TCP-tuple rename, so they keep
        # elog's default "<provider>_<session_id>" name with the top bit
        # of the session id set; they are created at boot before any
        # capture, so they carry no in-capture SESSION_CREATE and are
        # exempt.
        for path in files:
            decoded = decode_capture(path)
            session_id = path.stem.rpartition("_")[2]
            if session_id.isdigit() and (int(session_id) >> 63) != 0:
                continue
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
            number of records actually walked, kernel_dropped_events=0).
          - Provider map contains the tcp provider id.
          - Each event header has provider_id matching a tcp
            provider or the synthesised machine provider,
            event_length is plausible (>= header, <= a generous
            max), and the recorded payload size agrees with
            event_length - sizeof(header).
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

        file_hdr, providers, events, meta = parse_elog_binary(capture)

        # File-header invariants. event_count is updated in-place at
        # close (update_binary_header in elog.c), so it must equal
        # what we walked.
        assert file_hdr.event_count == len(events), (
            f"event_count in header ({file_hdr.event_count}) != "
            f"events walked ({len(events)})")
        assert file_hdr.kernel_dropped_events == 0, (
            f"kernel reported {file_hdr.kernel_dropped_events} dropped "
            f"events during the capture")
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
        # an image that builds more than one stack. Events come from
        # those tcp providers, plus the elog-synthesised `machine`
        # provider written at capture start.
        tcp_ids = {pid for pid, name in providers.items()
                   if name == "tcp"}
        assert tcp_ids, (
            f"no tcp provider in capture; got {providers!r}")
        machine_ids = {pid for pid, name in providers.items()
                       if name == "machine"}
        known_ids = tcp_ids | machine_ids

        # v2 captures bind each provider_id to a content-addressed schema_id
        # (even with --no-embed-decode), so a later decode can resolve the
        # exact schema. The tcp providers register a decode blob, so theirs
        # must be non-zero.
        assert meta.version == ELOG_BINARY_VERSION, (
            f"expected v{ELOG_BINARY_VERSION} capture, got {meta.version}")
        for pid in tcp_ids:
            assert meta.provider_schema_ids[pid] != ELOG_ZERO_SCHEMA_ID, (
                f"tcp provider id={pid} has a zero schema_id")

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
            assert hdr.provider_id in known_ids, (
                f"unexpected provider_id={hdr.provider_id} in event "
                f"(tcp provider ids: {sorted(tcp_ids)}; "
                f"machine provider ids: {sorted(machine_ids)}; "
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

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_userspace_drop_counters(self, tmp_path):
        """Real user-space drops land in the file header's user_dropped_*
        fields, and elog's -s stderr summary agrees with the header.

        Pushes directly into a raw submission ring (_UserRingProvider),
        bypassing libeventlog, so timestamps are fully controlled: a
        first batch establishes the stream's last-delivered timestamp,
        then a second batch with earlier timestamps is guaranteed to be
        counted as user_dropped_late (mirrors out_of_order_drop_stats in
        eventlog_user_provider_test.c, driven through the real elog(1)
        binary instead of a raw subscriber fd).
        """
        _require_eventlog_dev()

        pname = "uprov_dropctr"
        capture = tmp_path / "capture.elog"
        base = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)

        with elog_capture("-c", pname, capture_path=capture) as elog:
            with _UserRingProvider(pname) as prov:
                hi = [(base + i, 10 + i, 0x1, EVENTLOG_LEVEL_INFO, 0, b"")
                      for i in range(3)]
                prov.push(hi)
                # Let the high batch drain on its own before the late one
                # arrives, so the stream's last-delivered timestamp has
                # actually advanced past it.
                time.sleep(1)

                lo = [(base + j, 20 + j, 0x1, EVENTLOG_LEVEL_INFO, 0, b"")
                      for j in range(2)]
                prov.push(lo)
                time.sleep(1)

        assert "User dropped (late): 2" in elog.captured_stderr, (
            f"expected the -s summary to report 2 late drops; "
            f"stderr:\n{elog.captured_stderr}")

        file_hdr, _providers, _events, _meta = parse_elog_binary(capture)
        assert file_hdr.user_dropped_late == 2, (
            f"expected header user_dropped_late == 2, "
            f"got {file_hdr.user_dropped_late}")
        assert file_hdr.kernel_dropped_events == 0, (
            f"unexpected kernel per-CPU drops: "
            f"{file_hdr.kernel_dropped_events}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_start_anchors_to_a_clock_read(self, tmp_path):
        """The header's capture_start and start_utc_us name the same
        instant even when the first event drained predates the capture.

        elog(1) used to take capture_start from that first event's
        timestamp while taking start_utc_us from gettimeofday(), which
        only agree when the event is live. A user-space producer writes
        its identity record when it registers with libeventlog, and a
        stream that joins before the subscriber has consumed anything
        joins armed (eventlog_user_stream_get), so records far older than
        the subscription are delivered rather than prejoin-dropped --
        backdating the anchor by the producer's uptime.

        Pushes a backdated record through a raw ring, bypassing
        libeventlog for full control of the timestamp.
        """
        _require_eventlog_dev()

        pname = "uprov_anchor"
        capture = tmp_path / "capture.elog"

        with elog_capture("-c", pname, capture_path=capture):
            with _UserRingProvider(pname) as prov:
                uptime_us = int(
                    time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                wall_us = int(time.time() * 1_000_000)
                # Half the uptime: as old as a real timestamp can be on
                # a host that may have booted moments ago.
                record_ts = uptime_us // 2
                prov.push([(record_ts, 10, 0x1,
                            EVENTLOG_LEVEL_INFO, 0, b"")])
                time.sleep(1)

        file_hdr, _providers, events, _meta = parse_elog_binary(capture)
        ours = [h for h, _p in events if h.event_id == 10]
        assert ours, (
            f"backdated record never reached the capture; got "
            f"{[h.event_id for h, _p in events]}")

        # Taking the anchor from the first drained event makes these equal.
        assert int(file_hdr.capture_start) > record_ts, (
            f"capture_start ({file_hdr.capture_start}) did not advance past "
            f"the backdated record ({record_ts}); it is coming from the first "
            f"event rather than the clock")
        skew_us = abs(int(file_hdr.capture_start) - uptime_us)
        assert skew_us < 30 * 1_000_000, (
            f"capture_start ({file_hdr.capture_start}) is {skew_us / 1e6:.1f}s "
            f"from the uptime read at capture time ({uptime_us})")
        assert abs(int(file_hdr.start_utc_us) - wall_us) < 30 * 1_000_000, (
            f"start_utc_us ({file_hdr.start_utc_us}) is far from the wall "
            f"clock read at capture time ({wall_us})")

        # The documented conversion places the record before capture start.
        event_utc_us = (int(file_hdr.start_utc_us) +
                        (int(ours[0].timestamp) - int(file_hdr.capture_start)))
        assert event_utc_us < int(file_hdr.start_utc_us), (
            f"backdated record converts to {event_utc_us}, at or after the "
            f"capture start ({file_hdr.start_utc_us})")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_announcement_only_read_keeps_join_armed(self, tmp_path):
        """A subscriber that has only drained announcements still joins a
        new stream armed, so the provider's first record reaches the
        capture even when backdated.

        Late registration injects a PROVIDER_INFO announcement stamped at
        "now" and wakes blocked subscribers. Before the consumer_wc fix,
        that announcement-only read advanced consumer_wc, so the next
        stream to join did so unarmed and prejoin-dropped its first
        record -- pushed here at half uptime, as old as a real timestamp
        can be -- leaving the capture empty. That race is what made
        test_capture_start_anchors_to_a_clock_read flaky; sleeping after
        registration, before the push, forces the announcement-only read
        to complete first and makes the interleaving deterministic.
        """
        _require_eventlog_dev()

        pname = "uprov_announce"
        capture = tmp_path / "capture.elog"

        with elog_capture("-c", pname, capture_path=capture):
            with _UserRingProvider(pname) as prov:
                # elog must have drained the PROVIDER_INFO announcement
                # before the first real record arrives.
                time.sleep(1)
                uptime_us = int(
                    time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                record_ts = uptime_us // 2
                prov.push([(record_ts, 10, 0x1,
                            EVENTLOG_LEVEL_INFO, 0, b"")])
                time.sleep(1)

        _file_hdr, _providers, events, _meta = parse_elog_binary(capture)
        ours = [h for h, _p in events if h.event_id == 10]
        assert ours, (
            f"first record after an announcement-only read never reached "
            f"the capture; got {[h.event_id for h, _p in events]}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_dump_complete_only_read_keeps_join_armed(self, tmp_path):
        """A read that drained only a DUMP_COMPLETE marker must not move
        the join point either.

        DUMP_COMPLETE is synthesised at "now" through the same write path
        as the provider announcements (eventlog_emit_dump_complete).
        Subscribing with -D posts a DUMP_REQUEST; answering it with an
        immediate DUMP_DONE and no replayed records leaves elog's next
        read carrying only that marker. Without DUMP_COMPLETE in the
        announcements_only filter, that read still advances consumer_wc
        and the backdated record below is prejoin-dropped.
        """
        _require_eventlog_dev()

        pname = "uprov_dumpwc"
        capture = tmp_path / "capture.elog"

        with _UserRingProvider(pname) as prov:
            with elog_capture("-c", pname, "-D", capture_path=capture):
                sub_id = prov.wait_dump_request()
                prov.dump_done(sub_id)
                # elog must have drained the DUMP_COMPLETE-only read
                # before the first real record arrives.
                time.sleep(1)
                uptime_us = int(
                    time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                record_ts = uptime_us // 2
                prov.push([(record_ts, 10, 0x1,
                            EVENTLOG_LEVEL_INFO, 0, b"")])
                time.sleep(1)

        _file_hdr, _providers, events, _meta = parse_elog_binary(capture)
        ours = [h for h, _p in events if h.event_id == 10]
        assert ours, (
            f"first record after a DUMP_COMPLETE-only read never reached "
            f"the capture; got {[h.event_id for h, _p in events]}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_decodes(self):
        """A provider that registers after elog has already subscribed to
        its name still gets its events decoded, instead of "[no decode
        blob for provider ?]".

        elog(1) prefetches provider_id -> schema_id via GET_PROVIDERS once
        at subscribe time; "uprov_late" doesn't exist yet then, so its id
        is missing from that snapshot -- the "elog subscribe-ordering" bug
        this test guards against.
        """
        _require_eventlog_dev()

        pname = "uprov_late"
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            out = (ctypes.c_char * probe.blob_size)()
            _get_decode_blob(fd, name="tcp", out_buf=out)
            # Reuse the real "tcp" schema: elog decodes by schema_id, not
            # provider name, so this exercises the real decode path.
            tcp_blob = bytes(out)

        with elog_capture("-c", pname) as elog:
            with _UserRingProvider(pname, decode_blob=tcp_blob) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                # MSS event (id 4): single uint32_t "mss" field, formatted
                # as "MSS set to %1 bytes".
                prov.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 1234))])
                time.sleep(1)

        assert "no decode blob" not in elog.captured_stdout, (
            f"late-registered provider's event never got decoded; "
            f"stdout:\n{elog.captured_stdout}")
        assert "MSS set to 1234 bytes" in elog.captured_stdout, (
            f"expected decoded MSS event in stdout:\n"
            f"{elog.captured_stdout}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(90)
    def test_capture_many_same_name_providers_decode(self):
        """More same-name providers than the legacy GET_PROVIDERS
        IOCPARM_LEN cap (~163) must all decode via GET_PROVIDERS2.
        nginx registers one provider per worker; a 96-core box with a
        worker reload easily crosses that boundary.

        Up to 64 providers share one submission ring (the kernel's
        per-fd cap), so this set is three merge streams. Each stream's
        records are stamped a little ahead of the push so they stay
        past that stream's join watermark.
        """
        _require_eventlog_dev()

        pname = "uprov_many"
        nprov = 180
        per_fd = 64  # EVENTLOG_USER_PROVIDERS_PER_FD
        tcp_blob = _fetch_tcp_decode_blob()

        channels = []
        try:
            left = nprov
            while left:
                ch = _UserRingProvider(pname, decode_blob=tcp_blob)
                pids = [ch.provider_id]
                left -= 1
                while left and len(pids) < per_fd:
                    pids.append(ch.register_another(
                        pname, decode_blob=tcp_blob))
                    left -= 1
                channels.append((ch, pids))
            idx = 0
            with elog_capture("-c", pname) as elog:
                for ch, pids in channels:
                    base = int(time.clock_gettime(
                        time.CLOCK_UPTIME) * 1_000_000) + 50_000
                    records = []
                    for _pid in pids:
                        records.append((
                            base + len(records), 4, 0x1,
                            EVENTLOG_LEVEL_INFO, 0,
                            struct.pack("<I", 1000 + idx)))
                        idx += 1
                    ch.push(records, provider_ids=pids)
                time.sleep(2)
        finally:
            for ch, _pids in channels:
                ch.close()

        assert "no decode blob" not in elog.captured_stdout
        for i in range(nprov):
            assert f"MSS set to {1000 + i} bytes" in elog.captured_stdout

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_late_provider_announced_before_exit(self, tmp_path):
        """A provider that registers after subscribe, emits one event, and
        unregisters immediately must still be named in the binary capture.
        The bind-time announcement updates elog's map before the file
        header is written, so the name lands in the header; an in-band
        record is the same fact when the file was already open.
        """
        _require_eventlog_dev()

        pname = "uprov_ephemeral"
        tcp_blob = _fetch_tcp_decode_blob()
        capture = tmp_path / "ephemeral.elog"

        with elog_capture("-c", pname, capture_path=capture) as elog:
            with _UserRingProvider(pname, decode_blob=tcp_blob) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 4242))])
                time.sleep(0.5)
            # Provider is gone; give elog a tick to drain.
            time.sleep(1)

        assert capture.stat().st_size > 0, "empty capture"
        _hdr, providers_by_id, events, meta = parse_elog_binary(capture)
        assert pname in providers_by_id.values(), (
            f"provider {pname!r} missing from capture provider map "
            f"(header+inband); ids={providers_by_id} "
            f"header={meta.header_provider_ids} "
            f"inband={meta.inband_provider_ids}")
        text = decode_capture(capture)
        assert "MSS set to 4242 bytes" in text, (
            f"event not decodable after provider exit; stdout:\n{text}")
        assert "never resolved" not in elog.captured_stderr, (
            f"elog warned about unknown providers:\n{elog.captured_stderr}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_keyword_hex(self):
        """A hex mask needs no schema, so a not-yet-registered provider is
        filtered from the first event rather than after a narrowing pass."""
        _require_eventlog_dev()

        pname = "uprov_kwhex"
        tcp_blob = _fetch_tcp_decode_blob()

        with elog_capture("-c", pname, "VERBOSE", "0x80") as elog:
            with _UserRingProvider(pname, decode_blob=tcp_blob) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 1234)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 4321)),
                ])
                time.sleep(1)

        assert "MSS set to 1234 bytes" in elog.captured_stdout, (
            f"CONN-tagged event missing;\nstdout:\n{elog.captured_stdout}\n"
            f"stderr:\n{elog.captured_stderr}")
        assert "MSS set to 4321 bytes" not in elog.captured_stdout, (
            f"RX-tagged event should never have been delivered;\n"
            f"stdout:\n{elog.captured_stdout}")
        assert "not registered yet" not in elog.captured_stderr, (
            f"a hex mask needs no deferred resolution;\n"
            f"stderr:\n{elog.captured_stderr}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_unknown_keyword_name(self):
        """A name the provider turns out not to declare is a warning once a
        capture is running, and the names it does declare still filter."""
        _require_eventlog_dev()

        pname = "uprov_kwunknown"
        tcp_blob = _fetch_tcp_decode_blob()

        with elog_capture("-c", pname, "VERBOSE", "CONN|NOSUCHKW") as elog:
            with _UserRingProvider(pname, decode_blob=tcp_blob) as prov:
                time.sleep(2)
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 1234)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 4321)),
                ])
                time.sleep(1)

        assert "NOSUCHKW" in elog.captured_stderr, (
            f"expected a warning naming the unknown keyword;\n"
            f"stderr:\n{elog.captured_stderr}")
        assert "MSS set to 1234 bytes" in elog.captured_stdout, (
            f"CONN should still filter after dropping the unknown name;\n"
            f"stdout:\n{elog.captured_stdout}\n"
            f"stderr:\n{elog.captured_stderr}")
        assert "MSS set to 4321 bytes" not in elog.captured_stdout, (
            f"RX-tagged event should have been filtered out;\n"
            f"stdout:\n{elog.captured_stdout}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(45)
    def test_capture_two_late_providers_keyword_names(self):
        """Each pending subscription resolves against its own provider, so
        two late providers narrow to different masks."""
        _require_eventlog_dev()

        tcp_blob = _fetch_tcp_decode_blob()

        with elog_capture("-c", "uprov_kwtwo_a", "VERBOSE", "CONN",
                          "-c", "uprov_kwtwo_b", "VERBOSE", "RX") as elog:
            with _UserRingProvider("uprov_kwtwo_a",
                                   decode_blob=tcp_blob) as prov_a, \
                 _UserRingProvider("uprov_kwtwo_b",
                                   decode_blob=tcp_blob) as prov_b:
                time.sleep(2)
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov_a.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 11)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 12)),
                ])
                prov_b.push([
                    (ts + 2, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 21)),
                    (ts + 3, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 22)),
                ])
                time.sleep(1)

        out = elog.captured_stdout
        for mss, want in ((11, True), (12, False), (21, False), (22, True)):
            present = f"MSS set to {mss} bytes" in out
            assert present == want, (
                f"MSS {mss}: present={present}, expected {want};\n"
                f"stdout:\n{out}\nstderr:\n{elog.captured_stderr}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_keyword_names_without_a_decode_blob(self):
        """A provider registered without a blob is indistinguishable from
        one that has not registered at all (GET_DECODE_BLOB skips both), so
        it takes the same deferred path: warn, capture wide, never narrow.
        """
        _require_eventlog_dev()

        pname = "uprov_kwnoblob"
        with _UserRingProvider(pname) as prov:
            with elog_capture("-c", pname, "VERBOSE", "CONN") as elog:
                time.sleep(2)
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 4321)),
                ])
                time.sleep(1)

        assert "no decode blob" in elog.captured_stderr, (
            f"expected a warning that the names cannot resolve yet;\n"
            f"stderr:\n{elog.captured_stderr}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_keyword_names_too_long_for_deferral(self):
        """Deferred names are held in a fixed-size buffer, so an
        over-long list is rejected rather than silently truncated."""
        _require_eventlog_dev()

        names = "|".join(f"KW{i:02d}" for i in range(30))
        assert len(names) > 128
        r = subprocess.run(
            [ELOG, "-s", "-c", "uprov_kwneverreg", "VERBOSE", names],
            capture_output=True, text=True, timeout=20)
        assert r.returncode == 1, f"stdout={r.stdout} stderr={r.stderr}"
        assert "keyword list too long" in r.stderr, r.stderr

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_keyword_names(self):
        """`-c <provider> <level> <keyword-name>` works for a provider that
        has not registered yet: elog subscribes unfiltered and narrows once
        the blob appears. Both events below carry the same event id and
        differ only in keywords, so only the CONN-tagged one may appear.
        """
        _require_eventlog_dev()

        pname = "uprov_kwlate"
        tcp_blob = _fetch_tcp_decode_blob()

        with elog_capture("-c", pname, "VERBOSE", "CONN") as elog:
            with _UserRingProvider(pname, decode_blob=tcp_blob) as prov:
                # elog narrows on its next capture-loop pass, which a
                # blocking read bounds at ~1s.
                time.sleep(2)
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 1234)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 4321)),
                ])
                time.sleep(1)

        assert "MSS set to 1234 bytes" in elog.captured_stdout, (
            f"CONN-tagged event missing: the keyword name never resolved "
            f"for the late-registering provider;\n"
            f"stdout:\n{elog.captured_stdout}\n"
            f"stderr:\n{elog.captured_stderr}")
        assert "MSS set to 4321 bytes" not in elog.captured_stdout, (
            f"RX-tagged event should have been filtered out once the "
            f"subscription narrowed;\n"
            f"stdout:\n{elog.captured_stdout}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_keyword_negation_empty(self):
        """A deferred filter that resolves to no keywords (RX|^RX) must
        warn and leave the subscription unfiltered, matching the
        registered-provider path which rejects that filter outright.
        """
        _require_eventlog_dev()

        pname = "uprov_kwempty"
        tcp_blob = _fetch_tcp_decode_blob()

        with elog_capture("-c", pname, "VERBOSE", "RX|^RX") as elog:
            with _UserRingProvider(pname, decode_blob=tcp_blob) as prov:
                time.sleep(2)
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([
                    (ts, TCP_EVENT_MSS, TCP_KEYWORD_CONN,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 1234)),
                    (ts + 1, TCP_EVENT_MSS, TCP_KEYWORD_RX,
                     EVENTLOG_LEVEL_INFO, 0, struct.pack("<I", 4321)),
                ])
                time.sleep(1)

        assert "excludes every keyword" in elog.captured_stderr, (
            f"expected a warning that the deferred filter is empty;\n"
            f"stderr:\n{elog.captured_stderr}")
        assert "MSS set to 1234 bytes" in elog.captured_stdout, (
            f"subscription should have stayed unfiltered;\n"
            f"stdout:\n{elog.captured_stdout}\n"
            f"stderr:\n{elog.captured_stderr}")
        assert "MSS set to 4321 bytes" in elog.captured_stdout, (
            f"RX-tagged event should still appear (no narrowing);\n"
            f"stdout:\n{elog.captured_stdout}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_binary_embeds_decode_info(
            self, tmp_path):
        """A binary capture (-o) written before a provider registers still
        embeds that provider's table entry and decode blob in-band, so the
        file replays correctly with no live kernel involved at all -- not
        just while the originating provider process is still running (see
        test_capture_late_provider_decodes for the live-kernel text-mode
        case).
        """
        _require_eventlog_dev()

        pname = "uprov_latebin"
        early_name = f"{pname}_early"
        capture = tmp_path / "capture.elog"
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            out = (ctypes.c_char * probe.blob_size)()
            _get_decode_blob(fd, name="tcp", out_buf=out)
            # Base the schema on the real "tcp" blob (so decode.c parses a
            # genuine, well-formed schema and the MSS event formats
            # correctly), but pad it so its hash -- and thus schema_id --
            # differs from "tcp"'s own. "tcp" is always registered before
            # this test runs, so its schema is already in the file header;
            # padding forces a schema elog has never seen before, so
            # embedding it can only happen via the in-band announcement
            # this test is checking, not by reusing the header's copy.
            # decode_provider_parse() reads a fixed sequence of counted
            # records and never checks for trailing bytes, so the padding
            # does not disturb parsing.
            late_blob = bytes(out) + b"\0" * 4

        with elog_capture("-c", early_name, "-c", pname,
                          capture_path=capture):
            _prime_binary_header(early_name)
            with _UserRingProvider(pname, decode_blob=late_blob) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                # MSS event (id 4): single uint32_t "mss" field, formatted
                # as "MSS set to %1 bytes".
                prov.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 1234))])
                time.sleep(1)
            # `prov` (and its registration) is gone by the time we decode
            # below: any successful decode must come from what got
            # embedded in the file, not from asking a live kernel.

        file_hdr, providers, events, meta = parse_elog_binary(capture)
        assert file_hdr.event_count >= 1, "no events recorded"

        late_ids = {pid for pid, name in providers.items()
                    if name == pname}
        assert late_ids, f"{pname} missing from capture entirely"
        # The whole point: it was NOT in the file header's provider table
        # (the provider didn't exist yet when elog wrote the header) --
        # it only shows up via an in-band announcement mid-stream. Checked
        # by name, not id: _prime_binary_header()'s disposable provider is
        # expected to free an id that pname's registration immediately
        # reuses (alloc_unr(9)), so late_ids.isdisjoint(header_provider_ids)
        # would false-positive on that unrelated, expected id collision.
        assert pname not in meta.header_provider_names, (
            f"{pname} unexpectedly present in the file header's provider "
            f"table; header_provider_names={meta.header_provider_names}")
        assert late_ids <= meta.inband_provider_ids, (
            f"{pname} not announced in-band; "
            f"inband_provider_ids={meta.inband_provider_ids}")

        embedded = set(meta.embedded_schema_ids)
        for pid in late_ids:
            schema_id = meta.provider_schema_ids[pid]
            assert schema_id != ELOG_ZERO_SCHEMA_ID, (
                f"{pname} id={pid} has a zero schema_id")
            assert schema_id in embedded, (
                f"{pname} id={pid} schema_id not embedded in-band "
                f"(embedded={[s.hex() for s in embedded]})")

        decoded = decode_capture(capture)
        _assert_in_decode(decoded, f"[{pname}]", f"{pname} provider tag")
        _assert_in_decode(decoded, "MSS set to 1234 bytes",
                          "decoded late-provider MSS event")
        # Scoped to pname, not a blanket "no decode blob" anywhere: the
        # capture also carries _prime_binary_header()'s own priming event
        # from early_name, which never registers a decode blob and is
        # expected to show up undecoded -- that's unrelated to whether
        # pname's in-band-embedded blob did its job. The trailing ";"
        # matches the "; event %u]" that always follows the name in
        # elog.c's format string, so early_name (which has pname as a
        # literal prefix) can't satisfy this check by accident.
        assert f"no decode blob for provider {pname};" not in decoded, (
            f"late-registered provider fell back to a live-kernel lookup "
            f"that should not have been needed; decoded:\n{decoded}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_oversized_blob_is_not_embedded(
            self, tmp_path):
        """A late-registering provider whose decode blob doesn't fit in one
        ELOG_EVENT_PROVIDER_BLOB_ID record (event_length is a uint16_t, so
        ELOG_INBAND_BLOB_MAX caps it at 65483 bytes) still gets its
        ELOG_EVENT_PROVIDER_INFO_ID announcement, but the blob itself is
        skipped with a warning instead of embedded. Once the provider is
        gone, replay can't fall back to a live kernel lookup either, so
        the event comes back undecoded rather than mis-decoded or crashing.
        """
        _require_eventlog_dev()

        pname = "uprov_toobig"
        early_name = f"{pname}_early"
        capture = tmp_path / "capture.elog"
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            out = (ctypes.c_char * probe.blob_size)()
            _get_decode_blob(fd, name="tcp", out_buf=out)
            # Padded just past ELOG_INBAND_BLOB_MAX -- but still under the
            # kernel's own REGISTER_PROVIDER cap (EVENTLOG_USER_DECODE_
            # BLOB_MAX), a separate, smaller limit -- so registration
            # succeeds and it's elog(1) that has to judge this one too
            # big to embed. decode_provider_parse() never checks for
            # trailing bytes (see the sibling test), so this is still a
            # well-formed blob, just an oversized one.
            pad = ELOG_INBAND_BLOB_MAX + 1 - len(out)
            assert 0 < pad < EVENTLOG_USER_DECODE_BLOB_MAX, (
                f"tcp blob is {len(out)} bytes; no padding fits both "
                f"past ELOG_INBAND_BLOB_MAX and under the kernel's "
                f"registration cap")
            big_blob = bytes(out) + b"\0" * pad

        with elog_capture("-c", early_name, "-c", pname,
                          capture_path=capture) as elog:
            _prime_binary_header(early_name)
            with _UserRingProvider(pname, decode_blob=big_blob) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 1234))])
                time.sleep(1)
            # `prov` is gone once we decode below, so the kernel no longer
            # has this schema_id to fall back to either.

        assert "too large to embed" in elog.captured_stderr, (
            f"expected an oversized in-band decode-blob warning; "
            f"stderr:\n{elog.captured_stderr}")

        file_hdr, providers, events, meta = parse_elog_binary(capture)
        late_ids = {pid for pid, name in providers.items() if name == pname}
        assert late_ids, f"{pname} missing from capture entirely"
        # Checked by name, not id -- see the sibling assert in
        # test_capture_late_provider_binary_embeds_decode_info for why.
        assert pname not in meta.header_provider_names, (
            f"{pname} unexpectedly present in the file header's provider "
            f"table; header_provider_names={meta.header_provider_names}")
        assert late_ids <= meta.inband_provider_ids, (
            f"{pname}'s provider-info announcement should still be "
            f"written even though its blob is too big to embed; "
            f"inband_provider_ids={meta.inband_provider_ids}")

        embedded = set(meta.embedded_schema_ids)
        for pid in late_ids:
            schema_id = meta.provider_schema_ids[pid]
            assert schema_id not in embedded, (
                f"{pname} id={pid} schema_id unexpectedly embedded despite "
                f"exceeding ELOG_INBAND_BLOB_MAX "
                f"(embedded={[s.hex() for s in embedded]})")

        decoded = decode_capture(capture)
        _assert_in_decode(decoded,
                          f"no decode blob for provider {pname}",
                          "undecoded late-provider event")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_roll_restart_continues_seq(self, tmp_path):
        """A restarted time-rolling elog continues the interval's seq from
        .<prefix>.seq, so its first file does not reuse the name of one an
        uploader already moved away.
        """
        _require_eventlog_dev()

        pname = "uprov_rollseq"
        out_dir = tmp_path / "roll"
        moved = tmp_path / "moved"
        moved.mkdir()
        names = []
        for run in range(2):
            with elog_capture("-c", pname, "-o", f"dir={out_dir}",
                              "--roll-time", "1h"):
                with _UserRingProvider(pname) as prov:
                    ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                    prov.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                        struct.pack("<I", run))])
                    time.sleep(1)
            files = sorted(out_dir.glob("eventlog-*.elog"))
            assert len(files) == 1, sorted(p.name for p in out_dir.iterdir())
            names.append(files[0].name)
            files[0].rename(moved / files[0].name)

        assert (out_dir / ".eventlog.seq").exists()
        assert names[0] != names[1], names
        stamp0, seq0 = names[0].rsplit("-", 1)
        stamp1, seq1 = names[1].rsplit("-", 1)
        if stamp0 == stamp1:
            assert int(seq1.split(".")[0]) == int(seq0.split(".")[0]) + 1, names

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_roll_idle_close(self, tmp_path):
        """A quiet capture still publishes its last interval: once the
        wall clock passes the interval's end plus the grace, the open file
        is renamed to its final name while elog keeps running. Intervals
        with no events produce no file.
        """
        _require_eventlog_dev()

        pname = "uprov_rollidle"
        out_dir = tmp_path / "roll"
        with elog_capture("-c", pname, "-o", f"dir={out_dir}",
                          "--roll-time", "2s"):
            with _UserRingProvider(pname) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 1))])
                # Interval end (<= 2 s) + grace (0.5 s) + read timeout (~1 s).
                deadline = time.monotonic() + 15
                files = []
                while time.monotonic() < deadline and not files:
                    time.sleep(0.25)
                    files = sorted(out_dir.glob("eventlog-*.elog"))
                assert len(files) == 1, (
                    f"expected the quiet interval to be published; "
                    f"got {sorted(p.name for p in out_dir.iterdir())}")
                # Two more quiet intervals add nothing.
                time.sleep(5)
                assert sorted(out_dir.glob("eventlog-*.elog")) == files
                assert not list(out_dir.glob(".tmp.*"))

        _, _, events, _ = parse_elog_binary(files[0])
        assert events, f"{files[0].name} has no events"

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_persists_across_roll(self, tmp_path):
        """A provider announced at bind time is in elog's map before the
        first rolled file opens, so every file's header names it. The
        next file (--roll-size) must still carry that map entry.
        """
        _require_eventlog_dev()

        pname = "uprov_rollbin"
        out_dir = tmp_path / "roll"
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            out = (ctypes.c_char * probe.blob_size)()
            _get_decode_blob(fd, name="tcp", out_buf=out)
            late_blob = bytes(out) + b"\0" * 8

        with elog_capture("-c", pname, "-o", f"dir={out_dir}",
                          "--roll-size", "1"):
            with _UserRingProvider(pname, decode_blob=late_blob) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                # roll-size=1 forces a fresh file on every event past the
                # first. The bind-time announcement is applied before
                # either file's header is written.
                prov.push([(ts + i, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 1000 + i)) for i in range(3)])
                time.sleep(1)

        files = sorted(out_dir.glob("eventlog-*.elog"))
        assert len(files) >= 2, (
            f"expected --roll-size 1 to split into >= 2 files; got {files}")

        _, providers0, _, meta0 = parse_elog_binary(files[0])
        ids0 = {pid for pid, name in providers0.items() if name == pname}
        assert ids0, f"{pname} missing from {files[0].name}"
        assert ids0 <= meta0.header_provider_ids, (
            f"{pname} missing from {files[0].name}'s header; "
            f"header_provider_ids={meta0.header_provider_ids}")

        _, providers1, _, meta1 = parse_elog_binary(files[1])
        ids1 = {pid for pid, name in providers1.items() if name == pname}
        assert ids1, f"{pname} missing from {files[1].name}"
        assert ids1 <= meta1.header_provider_ids, (
            f"{pname} should be in {files[1].name}'s own header -- "
            f"provider_map already knew about it by the time this file "
            f"was opened; header_provider_ids={meta1.header_provider_ids}")

        for path in files[:2]:
            decoded = decode_capture(path)
            assert "no decode blob" not in decoded, (
                f"{path.name} failed to decode {pname}'s event(s); "
                f"decoded:\n{decoded}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_late_provider_id_reuse_gets_own_announcement(
            self, tmp_path):
        """The kernel hands out provider_id via alloc_unr(9): the lowest
        free number, reused immediately once its previous owner
        unregisters. So a provider_id already recorded in this file's
        embedded_set (via one provider) can be handed to a completely
        different provider moments later. write_provider_announcement()
        must recognize the reused id as a *new* provider (matching by
        full identity, not just the numeric id) and announce it too,
        instead of treating the id as already covered and silently
        dropping the second provider from the capture.
        """
        _require_eventlog_dev()

        early_name = "uprov_reuse_early"
        aname = "uprov_reuse_a"
        bname = "uprov_reuse_b"
        capture = tmp_path / "capture.elog"
        with _open_eventlog() as fd:
            probe = _get_decode_blob(fd, name="tcp")
            out = (ctypes.c_char * probe.blob_size)()
            _get_decode_blob(fd, name="tcp", out_buf=out)
            tcp_blob = bytes(out)
            # Different padding -> different schema_id, so a's and b's
            # blobs are distinguishable in the capture.
            a_blob = tcp_blob + b"\0" * 4
            b_blob = tcp_blob + b"\0" * 8

        with elog_capture("-c", early_name, "-c", aname, "-c", bname,
                          capture_path=capture):
            _prime_binary_header(early_name)

            with _UserRingProvider(aname, decode_blob=a_blob) as prov_a:
                a_id = prov_a.provider_id
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov_a.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 1111))])
                # Long enough elog(1) has surely processed this event (and
                # thus resolved its provider_id to `aname`, not whatever
                # registers next) before it unregisters below and frees
                # the id -- see _prime_binary_header()'s docstring for why
                # this can't be observed directly and has to be a margin.
                time.sleep(3)
            # `prov_a` is gone: its id is now free for alloc_unr(9) to
            # hand back out.

            with _UserRingProvider(bname, decode_blob=b_blob) as prov_b:
                assert prov_b.provider_id == a_id, (
                    f"test assumes alloc_unr(9) hands {aname}'s just-freed "
                    f"id={a_id} to {bname}; got {prov_b.provider_id} "
                    f"instead -- kernel id allocation must have changed")
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov_b.push([(ts, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                    struct.pack("<I", 2222))])
                time.sleep(3)

        file_hdr, providers, events, meta = parse_elog_binary(capture)
        assert file_hdr.event_count >= 1, "no events recorded"

        b_ids = {pid for pid, name in providers.items() if name == bname}
        assert b_ids == {a_id}, (
            f"{bname} (reusing id={a_id}) missing its own in-band "
            f"announcement; providers={providers}")
        assert a_id in meta.inband_provider_ids, (
            f"{bname}'s announcement for reused id={a_id} not in-band; "
            f"inband_provider_ids={meta.inband_provider_ids}")

        b_schema_id = meta.provider_schema_ids[a_id]
        assert b_schema_id in meta.embedded_schema_ids, (
            f"{bname}'s decode blob not embedded despite reusing "
            f"{aname}'s id={a_id}; embedded_schema_ids="
            f"{[s.hex() for s in meta.embedded_schema_ids]}")

        decoded = decode_capture(capture)
        _assert_in_decode(decoded, "MSS set to 2222 bytes",
                          f"{bname}'s event (reused id={a_id})")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_proc_fork(self, tmp_path):
        """fork() without exec must emit process.PROC_FORK(child, parent)
        so consumers can copy the parent's PROC_MAP set onto the child
        pid. dump_state (-D) is not enough: it only covers processes
        that already exist at subscribe time.
        """
        _require_eventlog_dev()

        capture = tmp_path / "fork.elog"
        with elog_capture("-c", "process", capture_path=capture):
            parent_pid = os.getpid()
            child_pid = os.fork()
            if child_pid == 0:
                time.sleep(0.25)
                os._exit(0)
            waited_pid, status = os.waitpid(child_pid, 0)
            assert waited_pid == child_pid
            assert os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0
            time.sleep(1)

        forks = _proc_forks(capture)
        assert forks.get(child_pid) == parent_pid, (
            f"missing PROC_FORK pid={child_pid} ppid={parent_pid}; "
            f"got {sorted(forks.items())}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_proc_title(self, tmp_path):
        """setproctitle must emit process.PROC_TITLE so consumers can
        name a perl/$0 process after the script rather than p_comm.
        """
        _require_eventlog_dev()

        title = "elog_title_test"
        capture = tmp_path / "title.elog"
        with elog_capture("-c", "process", capture_path=capture):
            libc = ctypes.CDLL(None)
            libc.setproctitle.argtypes = [ctypes.c_char_p]
            # Leading '-' skips the "progname: " prefix setproctitle adds.
            libc.setproctitle(("-" + title).encode("ascii"))
            time.sleep(1)

        titles = _proc_titles(capture)
        mine = [t for pid, t in titles if pid == os.getpid()]
        assert title in mine, (
            f"missing PROC_TITLE pid={os.getpid()} title={title!r}; "
            f"got {titles}")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(150)
    def test_capture_roll_user_symbols(self, tmp_path):
        """Regression test: -U/--user-symbols must resolve user-mode
        symbols under --roll-time (`-o dir=`), not just the single-file
        `-o <path>` mode.

        write_binary_event() has two branches -- roll (write_roll_event)
        and non-roll -- and previously only the non-roll branch called
        into libelog_user_symbols, so USER_FILE events written via a
        rolling capture never got a matching USER_SYMBOL_RANGE. -D makes
        the process/symbols dump_state fire inline on subscribe, so this
        needs no synthetic traffic: the running system always has
        processes backed by real, resolvable ELF files.
        """
        _require_eventlog_dev()

        with elog_capture("-D", "-U", "-c", "process", "-c", "symbols",
                          "-o", f"dir={tmp_path}", "--roll-time", "60s"):
            # The roll file's ".tmp.*" dotfile appears the instant the
            # first event is written, so poll for it instead of a fixed
            # sleep. 40s wasn't enough: build #17340 still timed out with
            # zero events after 40+s, traced to the CI pooler co-scheduling
            # this test's VM on the same physical cores as thrash_zfs (see
            # LOG.md 2026-09-07) -- a scheduler-level stall this test can't
            # bound from inside the VM. Widened to 90s, with the class
            # timeout raised to match, to ride out that contention instead
            # of chasing an exact bound. pytest.fail() on timeout instead
            # of falling through so the failure blames the right thing
            # (elog never wrote an event) instead of "no rolled .elog
            # files produced", which reads like the roll/rename step
            # failed instead.
            deadline = time.monotonic() + 90
            while time.monotonic() < deadline:
                if any(tmp_path.glob(".tmp.*")):
                    break
                time.sleep(0.1)
            else:
                pytest.fail(f"timed out after 90s: no .tmp.* roll file "
                            f"appeared in {tmp_path} (elog never wrote "
                            f"an event)")

        files = sorted(tmp_path.glob("*.elog"))
        assert files, f"no rolled .elog files produced in {tmp_path}"

        decoded = decode_capture(files[0])
        _assert_in_decode(decoded, "[USER_FILE]",
                          "USER_FILE event in rolled capture")
        _assert_in_decode(decoded, "[USER_SYMBOL_RANGE]",
                          "USER_SYMBOL_RANGE event in rolled capture "
                          "(regression: -U must work under --roll-time)")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(30)
    def test_capture_machine_metadata(self, tmp_path):
        """Binary captures include elog-synthesised machine metadata by
        default: a `machine` provider row in the file header and a
        decodable MachineInfo event at the start of the stream."""
        _require_eventlog_dev()

        out = tmp_path / "meta.elog"
        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", "-o", str(out)):
                loopback_oneshot(socket.AF_INET, _pick_port(salt=77),
                                 b"machine-meta\n")
                time.sleep(1)

        _, providers, _, _ = parse_elog_binary(out)
        machine_ids = {pid for pid, name in providers.items()
                       if name == "machine"}
        assert machine_ids, "machine provider missing from capture"

        decoded = decode_capture(out)
        _assert_in_decode(decoded, "MachineInfo",
                          "MachineInfo metadata event in capture")

        no_meta = tmp_path / "no-meta.elog"
        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", "-o", str(no_meta),
                              "--no-metadata"):
                loopback_oneshot(socket.AF_INET, _pick_port(salt=78),
                                 b"no-meta\n")
                time.sleep(1)

        _, providers2, _, _ = parse_elog_binary(no_meta)
        assert "machine" not in providers2.values(), (
            "--no-metadata should omit the machine provider")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_capture_machine_metadata_per_session(self, tmp_path):
        """Per-session `-o dir=` files each carry their own machine
        metadata preamble, not just the first file opened."""
        _require_eventlog_dev()

        out_dir = tmp_path / "split-meta"
        port = _pick_port(salt=79)
        with sysctl_override("net.inet.tcp.functions_default", "freebsd"), \
             sysctl_override("kern.eventlog.tcp.default", "1"):
            with elog_capture("-c", "tcp", "-f", "tcp",
                              "-o", f"dir={out_dir}"):
                loopback_oneshot(socket.AF_INET, port, b"split-meta\n")
                time.sleep(2)

        files = sorted(out_dir.glob("*.elog"))
        assert files, f"no per-session files under {out_dir}"
        for path in files:
            _, providers, _, _ = parse_elog_binary(path)
            assert "machine" in providers.values(), (
                f"{path.name}: machine provider missing")
            decoded = decode_capture(path)
            _assert_in_decode(decoded, "MachineInfo",
                              f"{path.name}: MachineInfo event")

    @pytest.mark.timeout(15)
    def test_user_symbols_replay_on_repeat_sighting(self):
        """Regression test: libelog_user_symbols must replay a repeat
        USER_FILE sighting's cached USER_SYMBOL_RANGE payloads instead
        of silently dropping them.

        A single subscriber can only ever see a given user_file_id
        once per dump_state trigger under the current kernel (the
        global intern table's first-sighting dedup means at most one
        provider ends up emitting each file, and there's currently no
        way to re-trigger dump_state on an already-open subscriber),
        so this can't be reproduced end-to-end through /dev/eventlog
        without also depending on process-scheduling timing. Test the
        library's own dedup logic directly instead: feed the same
        USER_FILE event to elog_user_symbols_observe() twice, exactly
        as would happen if the kernel ever did emit a duplicate (e.g.
        after a roll-boundary dump_state re-trigger elsewhere in the
        stack), and check the second call replays from cache rather
        than silently returning nothing.
        """
        try:
            lib = ctypes.CDLL("libelog_user_symbols.so.1")
        except OSError as e:
            pytest.skip(f"libelog_user_symbols.so.1 not loadable: {e}")
        lib.elog_user_symbols_init.restype = None
        lib.elog_user_symbols_shutdown.restype = None
        lib.elog_user_symbols_files_parsed.restype = ctypes.c_uint64
        lib.elog_user_symbols_ranges_emitted.restype = ctypes.c_uint64
        lib.elog_user_symbols_files_replayed.restype = ctypes.c_uint64
        lib.elog_user_symbols_ranges_replayed.restype = ctypes.c_uint64
        lib.elog_user_symbols_observe.restype = None
        lib.elog_user_symbols_observe.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(_EventHeader),
            ctypes.c_void_p, ctypes.c_size_t, _EmitFn, ctypes.c_void_p]

        emitted_eids = []
        emit_cb = _EmitFn(lambda hdr_p, payload, size, cookie:
                           emitted_eids.append(hdr_p.contents.event_id))

        lib.elog_user_symbols_init()
        try:
            hdr = _EventHeader(event_length=0, cpu=0, provider_id=1,
                                RESERVED=0, timestamp=0, session_id=0,
                                event_id=_SYMBOLS_EVENTLOG_USER_FILE_ID,
                                thread_id=0)
            # libc.so.7 always retains its .dynsym (a shared library needs
            # exported dynamic symbols to be linkable at all), unlike thin
            # base-system binaries which may be fully stripped in a NanoBSD
            # image.
            payload = _UserFilePayload(user_file_id=4242, build_id=b"",
                                        pathname=b"/lib/libc.so.7")

            lib.elog_user_symbols_observe(b"symbols", ctypes.byref(hdr),
                ctypes.byref(payload), ctypes.sizeof(payload), emit_cb, None)

            files_parsed = lib.elog_user_symbols_files_parsed()
            ranges_emitted = lib.elog_user_symbols_ranges_emitted()
            assert files_parsed == 1, (
                f"expected libc.so.7 to be parsed exactly once on first "
                f"sighting, got {files_parsed}")
            assert ranges_emitted > 0, (
                "expected at least one USER_SYMBOL_RANGE from libc.so.7")
            # The first sighting emits one SYMBOL_PACK_REF beside the
            # ranges (libc's note, or its SHA-256 when note-less).
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID) == ranges_emitted
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 1

            # Repeat sighting: same user_file_id, same header/payload --
            # simulates the kernel emitting USER_FILE for this file a
            # second time to the same subscriber.
            lib.elog_user_symbols_observe(b"symbols", ctypes.byref(hdr),
                ctypes.byref(payload), ctypes.sizeof(payload), emit_cb, None)

            files_replayed = lib.elog_user_symbols_files_replayed()
            ranges_replayed = lib.elog_user_symbols_ranges_replayed()
            assert files_replayed == 1, (
                f"expected the repeat USER_FILE sighting to be replayed "
                f"from cache exactly once; got {files_replayed}")
            assert ranges_replayed == ranges_emitted, (
                f"replay emitted {ranges_replayed} ranges but the first "
                f"sighting cached {ranges_emitted} -- some ranges were "
                f"dropped on replay instead of being replayed from cache")
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID) == (
                ranges_emitted + ranges_replayed), (
                "emit_fn range count doesn't match parsed + replayed "
                "ranges")
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 1
        finally:
            lib.elog_user_symbols_shutdown()

    def _load_user_symbols_lib(self):
        try:
            lib = ctypes.CDLL("libelog_user_symbols.so.1")
        except OSError as e:
            pytest.skip(f"libelog_user_symbols.so.1 not loadable: {e}")
        lib.elog_user_symbols_init.restype = None
        lib.elog_user_symbols_shutdown.restype = None
        lib.elog_user_symbols_files_parsed.restype = ctypes.c_uint64
        lib.elog_user_symbols_ranges_emitted.restype = ctypes.c_uint64
        lib.elog_user_symbols_files_replayed.restype = ctypes.c_uint64
        lib.elog_user_symbols_ranges_replayed.restype = ctypes.c_uint64
        lib.elog_user_symbols_observe.restype = None
        lib.elog_user_symbols_observe.argtypes = [
            ctypes.c_char_p, ctypes.POINTER(_EventHeader),
            ctypes.c_void_p, ctypes.c_size_t, _EmitFn, ctypes.c_void_p]
        lib.elog_user_symbols_set_ref_mode.restype = None
        lib.elog_user_symbols_set_ref_mode.argtypes = [ctypes.c_bool]
        return lib

    @staticmethod
    def _observe_user_file(lib, pathname, user_file_id, emit_cb):
        hdr = _EventHeader(event_length=0, cpu=0, provider_id=1,
                            RESERVED=0, timestamp=0, session_id=0,
                            event_id=_SYMBOLS_EVENTLOG_USER_FILE_ID,
                            thread_id=0)
        payload = _UserFilePayload(user_file_id=user_file_id,
                                    build_id=b"", pathname=pathname)
        lib.elog_user_symbols_observe(b"symbols", ctypes.byref(hdr),
            ctypes.byref(payload), ctypes.sizeof(payload), emit_cb, None)

    def test_user_symbols_refs_mode_emits_ref_for_noted_file(self):
        """In refs mode a file with a build-id note contributes exactly
        its SYMBOL_PACK_REF per sighting and no USER_SYMBOL_RANGEs."""
        lib = self._load_user_symbols_lib()
        emitted_eids = []
        emit_cb = _EmitFn(lambda hdr_p, payload, size, cookie:
                           emitted_eids.append(hdr_p.contents.event_id))
        lib.elog_user_symbols_init()
        try:
            lib.elog_user_symbols_set_ref_mode(True)
            self._observe_user_file(lib, b"/lib/libc.so.7", 4243, emit_cb)
            assert lib.elog_user_symbols_files_parsed() == 1
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 1
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID) == 0

            self._observe_user_file(lib, b"/lib/libc.so.7", 4243, emit_cb)
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 2
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID) == 0
        finally:
            lib.elog_user_symbols_set_ref_mode(False)
            lib.elog_user_symbols_shutdown()

    def test_user_symbols_refs_mode_inlines_noteless_file(self, tmp_path):
        """In refs mode a file without a build-id note emits no ref --
        a content hash says nothing about whether a pack exists -- and
        keeps the inline symbol walk instead (the SVM-binary case)."""
        # Hide libc's note from read_build_id() by flipping the note's
        # type field; the ELF stays valid, the id is simply gone.
        src = open("/lib/libc.so.7", "rb").read()
        note = (4).to_bytes(4, "little") + (20).to_bytes(4, "little") + \
            (3).to_bytes(4, "little") + b"GNU\0"
        off = src.find(note)
        if off < 0:
            pytest.skip("could not locate libc's build-id note")
        dst = tmp_path / "libc-nonote.so.7"
        dst.write_bytes(src[:off + 8] + b"\x7f\x00\x00\x00" + src[off + 12:])

        lib = self._load_user_symbols_lib()
        emitted_eids = []
        emit_cb = _EmitFn(lambda hdr_p, payload, size, cookie:
                           emitted_eids.append(hdr_p.contents.event_id))
        lib.elog_user_symbols_init()
        try:
            lib.elog_user_symbols_set_ref_mode(True)
            self._observe_user_file(lib, str(dst).encode(), 4244, emit_cb)
            assert lib.elog_user_symbols_files_parsed() == 1
            ranges_emitted = lib.elog_user_symbols_ranges_emitted()
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 0
            assert ranges_emitted > 0, (
                "expected the note-less file to fall back to inline "
                "USER_SYMBOL_RANGEs from .dynsym")

            self._observe_user_file(lib, str(dst).encode(), 4244, emit_cb)
            assert lib.elog_user_symbols_ranges_replayed() == ranges_emitted
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 0
        finally:
            lib.elog_user_symbols_set_ref_mode(False)
            lib.elog_user_symbols_shutdown()

    def test_user_symbols_refs_mode_inlines_go_pclntab(self, tmp_path):
        """Refs mode reads a Go binary's functions from .gopclntab.
        A GNU build-id still emits the pack ref, and the ranges come
        along with it."""
        go_path = tmp_path / "ftl-go"
        noted_path = tmp_path / "ftl-go-noted"
        _write_go_pclntab_elf(go_path, gnu_note=False)
        _write_go_pclntab_elf(noted_path, gnu_note=True)

        lib = self._load_user_symbols_lib()
        emitted_eids = []
        ranges = []

        def on_emit(hdr_p, payload, size, cookie):
            eid = hdr_p.contents.event_id
            emitted_eids.append(eid)
            if eid == _SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID:
                r = ctypes.cast(
                    payload, ctypes.POINTER(_UserSymbolRange)).contents
                ranges.append((r.offset, r.size, bytes(r.name).split(b"\0", 1)[0]))

        emit_cb = _EmitFn(on_emit)
        lib.elog_user_symbols_init()
        try:
            lib.elog_user_symbols_set_ref_mode(True)
            self._observe_user_file(lib, str(go_path).encode(), 4245, emit_cb)
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 0
            assert ranges == [
                (0x1000, 0x20, b"main.main"),
                (0x1020, 0x10, b"main.helper"),
            ]

            self._observe_user_file(lib, str(go_path).encode(), 4245, emit_cb)
            assert lib.elog_user_symbols_ranges_replayed() == 2

            before = len(ranges)
            self._observe_user_file(
                lib, str(noted_path).encode(), 4246, emit_cb)
            assert ranges[before:] == [
                (0x1000, 0x20, b"main.main"),
                (0x1020, 0x10, b"main.helper"),
            ]
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 1

            self._observe_user_file(
                lib, str(noted_path).encode(), 4246, emit_cb)
            assert ranges[before + 2:] == [
                (0x1000, 0x20, b"main.main"),
                (0x1020, 0x10, b"main.helper"),
            ]
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == 2
        finally:
            lib.elog_user_symbols_set_ref_mode(False)
            lib.elog_user_symbols_shutdown()

    def test_user_symbols_refs_mode_skips_cached_non_go_ranges(self):
        """Refs mode replays the pack ref for a non-Go file parsed
        earlier in inline mode, and leaves those cached ranges unsent."""
        lib = self._load_user_symbols_lib()
        emitted_eids = []
        ranges = []

        def on_emit(hdr_p, payload, size, cookie):
            eid = hdr_p.contents.event_id
            emitted_eids.append(eid)
            if eid == _SYMBOLS_EVENTLOG_USER_SYMBOL_RANGE_ID:
                ranges.append(eid)

        emit_cb = _EmitFn(on_emit)
        lib.elog_user_symbols_init()
        try:
            lib.elog_user_symbols_set_ref_mode(False)
            self._observe_user_file(lib, b"/lib/libc.so.7", 4247, emit_cb)
            assert len(ranges) > 0
            cached = len(ranges)
            refs = emitted_eids.count(_SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID)
            lib.elog_user_symbols_set_ref_mode(True)
            self._observe_user_file(lib, b"/lib/libc.so.7", 4247, emit_cb)
            assert len(ranges) == cached
            assert emitted_eids.count(
                _SYMBOLS_EVENTLOG_SYMBOL_PACK_REF_ID) == refs + 1
        finally:
            lib.elog_user_symbols_set_ref_mode(False)
            lib.elog_user_symbols_shutdown()

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(180)
    def test_term_during_gzip_publishes_complete_file(self, tmp_path):
        """SIGTERM while --gzip is compressing a rolled file exits 0.
        The published .elog.gz decodes, its header event_count covers
        every pushed event, and no .tmp.* working file is left behind.
        """
        _require_eventlog_dev()

        out_dir = tmp_path / "gzroll"
        pname = "uprov_gzdrain"
        n_events = 8
        # 32 KiB fits the default 1 MiB user ring with the record header.
        # Incompressible so --gzip=9 has real work; --roll-size 64K forces
        # a new file per event (payload alone is half the cap). Push one
        # event at a time and wait for its roll stem: a burst of KICKs
        # can overrun the subscriber buffer, and drain still advances the
        # producer ring, so those events are gone for good.
        payload = os.urandom(32 * 1024)

        def roll_stems():
            stems = set()
            if not out_dir.exists():
                return stems
            for p in out_dir.iterdir():
                name = p.name
                if name.startswith(".tmp."):
                    name = name[len(".tmp."):]
                if name.startswith("gzdrain-") and name.endswith(".elog.gz"):
                    stems.add(name[:-len(".elog.gz")])
                elif name.startswith("gzdrain-") and name.endswith(".elog"):
                    stems.add(name[:-len(".elog")])
            return stems

        proc = _spawn_elog(
            "-c", pname, "-o", f"dir={out_dir}",
            "--roll-prefix", "gzdrain", "--roll-size", "64K", "--gzip=9")
        time.sleep(2)
        if proc.poll() is not None:
            err = proc.stderr.read().decode()
            raise AssertionError(f"elog exited early: {err}")
        try:
            with _UserRingProvider(pname) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                for i in range(n_events):
                    prov.push([(ts + i, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                                payload)])
                    want = i + 1
                    deadline = time.time() + 15
                    while time.time() < deadline:
                        if len(roll_stems()) >= want:
                            break
                        time.sleep(0.02)
                    else:
                        names = sorted(p.name for p in out_dir.iterdir()) \
                            if out_dir.exists() else []
                        raise AssertionError(
                            f"elog absorbed {len(roll_stems())}/{want} "
                            f"after push {i}; dir={names}")
        finally:
            err = _finish_elog(proc, timeout=90)

        leftovers = sorted(p.name for p in out_dir.iterdir()
                           if p.name.startswith(".tmp."))
        assert leftovers == [], (
            f"gzip working files left behind: {leftovers}; stderr={err}")
        raw_left = sorted(p.name for p in out_dir.glob("gzdrain-*.elog"))
        assert raw_left == [], (
            f"uncompressed capture left behind: {raw_left}")
        gz_files = sorted(out_dir.glob("gzdrain-*.elog.gz"))
        assert gz_files, (
            f"no .elog.gz in {sorted(p.name for p in out_dir.iterdir())}")
        total = 0
        for gz in gz_files:
            decoded = decode_capture(gz)
            assert decoded.strip(), f"{gz.name} decoded empty"
            total += event_count_of_capture(gz)
        assert total >= n_events, (
            f"header event_count sum {total} < {n_events} pushed events")

    @pytest.mark.require_user("root")
    @pytest.mark.require_progs(["elog"])
    @pytest.mark.timeout(60)
    def test_overlapping_rolling_elogs_distinct_files(self, tmp_path):
        """Two rolling elog processes with the same prefix can run at
        once. roll_open() skips a seq whose file is already on disk and
        O_EXCL-retries the temp name, so each process publishes its own
        finalized file and a SIGTERM of both leaves nothing in .tmp.*.
        """
        _require_eventlog_dev()

        out_dir = tmp_path / "ovl"
        pname = "uprov_ovl"
        n_events = 3
        args = ("-c", pname, "-o", f"dir={out_dir}",
                "--roll-prefix", "ovlcap", "--roll-size", "100M")
        procs = [_spawn_elog(*args), _spawn_elog(*args)]
        time.sleep(2)
        for proc in procs:
            if proc.poll() is not None:
                err = proc.stderr.read().decode()
                raise AssertionError(f"elog exited early: {err}")
        try:
            with _UserRingProvider(pname) as prov:
                ts = int(time.clock_gettime(time.CLOCK_UPTIME) * 1_000_000)
                prov.push([(ts + i, 4, 0x1, EVENTLOG_LEVEL_INFO, 0,
                            struct.pack("<I", 1000 + i))
                           for i in range(n_events)])
            deadline = time.time() + 10
            while time.time() < deadline:
                if not out_dir.exists():
                    time.sleep(0.05)
                    continue
                pending = list(out_dir.glob("ovlcap-*.elog"))
                pending += list(out_dir.glob(".tmp.ovlcap-*"))
                if len(pending) >= 2:
                    break
                time.sleep(0.05)
        finally:
            for proc in procs:
                if proc.poll() is None:
                    proc.terminate()
            errors = []
            for proc in procs:
                try:
                    _finish_elog(proc, timeout=30)
                except AssertionError as exc:
                    errors.append(str(exc))
            assert not errors, errors

        leftovers = sorted(p.name for p in out_dir.iterdir()
                           if p.name.startswith(".tmp."))
        assert leftovers == [], f"temp files left behind: {leftovers}"
        files = sorted(out_dir.glob("ovlcap-*.elog"))
        assert len(files) >= 2, (
            f"expected two finalized captures, got "
            f"{sorted(p.name for p in out_dir.iterdir())}")
        assert len({p.name for p in files}) == len(files)
        for path in files:
            decoded = decode_capture(path)
            assert decoded.strip(), f"{path.name} decoded empty"
            assert event_count_of_capture(path) >= n_events, (
                f"{path.name} recorded fewer than {n_events} events")


class _LinkerFilePayload(ctypes.Structure):
    """Mirrors struct symbols_eventlog_linker_file
    (lib/libelog_source_lines/libelog_source_lines.c)."""
    _pack_ = 1
    _fields_ = [
        ("file_id", ctypes.c_uint32),
        ("base", ctypes.c_uint64),
        ("size", ctypes.c_uint64),
        ("flags", ctypes.c_uint32),
        ("build_id", ctypes.c_char * 41),
        ("filename", ctypes.c_char * 64),
        ("pathname", ctypes.c_char * 128),
    ]


class _CpuSampleHead(ctypes.Structure):
    """Mirrors packed CPU_SAMPLE fixed head (13 bytes)."""
    _pack_ = 1
    _fields_ = [
        ("tid", ctypes.c_uint32),
        ("pid", ctypes.c_uint32),
        ("type", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
        ("depth", ctypes.c_uint8),
        ("freq_mhz", ctypes.c_uint16),
    ]


_SYMBOLS_EVENTLOG_LINKER_FILE_ID = 1
_SYMBOLS_EVENTLOG_SOURCE_FILE_ID = 5
_SYMBOLS_EVENTLOG_SOURCE_LINE_ID = 6
_CPU_EVENTLOG_CPU_SAMPLE_ID = 1


def _build_cpu_sample_payload(pid, pcs):
    head = _CpuSampleHead(tid=1, pid=pid, type=0, flags=0,
                          depth=len(pcs), freq_mhz=0)
    return bytes(head) + b"".join(struct.pack("<Q", pc) for pc in pcs)


def _nm_text_symbol(path, name="main"):
    """Return the st_value of `name` from `nm -n path`, or None."""
    try:
        out = subprocess.check_output(
            ["nm", "-n", path], text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return None
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] == name and parts[1] in ("T", "t"):
            try:
                return int(parts[0], 16)
            except ValueError:
                return None
    return None


_BinaryFn = ctypes.CFUNCTYPE(
    None, ctypes.c_uint8, ctypes.c_uint32, ctypes.c_char_p, ctypes.c_bool,
    ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p)


def _text_vaddr(path):
    """First PF_X PT_LOAD vaddr via readelf/elfdump, or None."""
    for cmd in (["readelf", "-l", path], ["elfdump", "-p", path]):
        try:
            out = subprocess.check_output(
                cmd, text=True, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.CalledProcessError):
            continue
        for line in out.splitlines():
            if "LOAD" in line and ("R E" in line or "RX" in line or
                                   "r-x" in line):
                # readelf: "LOAD ... 0x00400000 0x00400000"
                hexes = [tok for tok in line.split()
                         if tok.startswith("0x")]
                if len(hexes) >= 2:
                    try:
                        return int(hexes[1], 16)
                    except ValueError:
                        pass
    return None


def _build_probe(tmp_path):
    """Compile the -g -no-pie probe; return (bin_path, vas, text_vaddr)."""
    src = tmp_path / "sl_probe.c"
    bin_path = tmp_path / "sl_probe"
    src.write_text(
        "static int helper(int x) { return x + 1; }\n"
        "int main(void) { volatile int x = 0; return helper(x); }\n")
    try:
        subprocess.check_call(
            ["cc", "-g", "-O0", "-no-pie", "-o", str(bin_path), str(src)],
            stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as e:
        pytest.skip(f"cc -g -no-pie failed: {e}")
    vas = {}
    for name in ("main", "helper"):
        va = _nm_text_symbol(str(bin_path), name)
        if va is None:
            pytest.skip(f"nm could not find {name} in probe binary")
        vas[name] = va
    text_vaddr = _text_vaddr(str(bin_path))
    if text_vaddr is None:
        text_vaddr = vas["main"] & ~0xFFFF  # rough page-aligned guess
    return bin_path, vas, text_vaddr


def _load_source_lines_lib():
    try:
        lib = ctypes.CDLL("libelog_source_lines.so.1")
    except OSError as e:
        pytest.skip(f"libelog_source_lines.so.1 not loadable: {e}")
    lib.elog_source_lines_init.restype = None
    lib.elog_source_lines_shutdown.restype = None
    lib.elog_source_lines_binaries_opened.restype = ctypes.c_uint64
    lib.elog_source_lines_files_emitted.restype = ctypes.c_uint64
    lib.elog_source_lines_lines_emitted.restype = ctypes.c_uint64
    lib.elog_source_lines_misses.restype = ctypes.c_uint64
    lib.elog_source_lines_misses_no_binary.restype = ctypes.c_uint64
    lib.elog_source_lines_misses_open.restype = ctypes.c_uint64
    lib.elog_source_lines_misses_addr.restype = ctypes.c_uint64
    lib.elog_source_lines_misses_line.restype = ctypes.c_uint64
    lib.elog_source_lines_set_kernel_version.restype = None
    lib.elog_source_lines_set_kernel_version.argtypes = [ctypes.c_char_p]
    lib.elog_source_lines_observe.restype = None
    lib.elog_source_lines_observe.argtypes = [
        ctypes.c_char_p, ctypes.POINTER(_EventHeader),
        ctypes.c_void_p, ctypes.c_size_t]
    lib.elog_source_lines_resolve.restype = None
    lib.elog_source_lines_resolve.argtypes = [_EmitFn, ctypes.c_void_p]
    lib.elog_source_lines_foreach_binary.restype = None
    lib.elog_source_lines_foreach_binary.argtypes = [
        _BinaryFn, ctypes.c_void_p]
    lib.elog_source_lines_binary_debug_path.restype = ctypes.c_char_p
    lib.elog_source_lines_binary_debug_path.argtypes = [
        ctypes.c_char_p]
    lib.elog_source_lines_set_debug_path.restype = None
    lib.elog_source_lines_set_debug_path.argtypes = [ctypes.c_char_p]
    return lib


def _build_split_debug_pair(tmp_path):
    """A full debug twin next to a binary whose .debug_line holds only a
    few rows, mirroring a port stripped to a split .debug file."""
    src = tmp_path / "sl_split.c"
    bin_path = tmp_path / "sl_split"
    full_path = tmp_path / "sl_split.full"
    src.write_text(
        "static int helper(int x) { return x + 1; }\n"
        "int main(void) { volatile int x = 0; return helper(x); }\n")
    try:
        subprocess.check_call(
            ["cc", "-g", "-O0", "-no-pie", "-o", str(full_path), str(src)],
            stderr=subprocess.DEVNULL)
        subprocess.check_call(
            ["cp", str(full_path), str(bin_path)],
            stderr=subprocess.DEVNULL)
        thin = subprocess.run(
            ["objcopy",
             "--remove-section", ".debug_abbrev",
             "--remove-section", ".debug_info",
             str(bin_path)],
            capture_output=True, text=True)
        if thin.returncode != 0:
            pytest.skip("objcopy cannot strip debug sections: "
                        f"{thin.stderr.strip()}")
        # Keep one row of .debug_line so the binary passes the first
        # open but stays under the split-merge threshold.
        dbg_dir = tmp_path / "usr/lib/debug" / bin_path.parent.relative_to(
            bin_path.parent.anchor)
        dbg_dir.mkdir(parents=True)
        subprocess.check_call(
            ["objcopy", "--only-keep-debug", str(full_path),
             str(dbg_dir / f"{bin_path.name}.debug")],
            stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError) as e:
        pytest.skip(f"split-debug probe setup failed: {e}")
    vas = {}
    for name in ("main", "helper"):
        va = _nm_text_symbol(str(bin_path), name)
        if va is None:
            pytest.skip(f"nm could not find {name} in split probe")
        vas[name] = va
    text_vaddr = _text_vaddr(str(bin_path)) or vas["main"]
    debug_root = tmp_path / "usr/lib/debug"
    return bin_path, vas, text_vaddr, debug_root


def _observe_linker_file(lib, file_id, base, size, bin_path, timestamp=0):
    hdr = _EventHeader(
        event_length=0, cpu=0, provider_id=9, RESERVED=0,
        timestamp=timestamp, session_id=0,
        event_id=_SYMBOLS_EVENTLOG_LINKER_FILE_ID, thread_id=0)
    lf = _LinkerFilePayload(
        file_id=file_id, base=base, size=size, flags=0, build_id=b"",
        filename=b"sl_probe", pathname=str(bin_path).encode())
    lib.elog_source_lines_observe(
        b"symbols", ctypes.byref(hdr), ctypes.byref(lf),
        ctypes.sizeof(lf))


def _observe_cpu_sample(lib, pid, pcs, timestamp=0):
    hdr = _EventHeader(
        event_length=0, cpu=0, provider_id=7, RESERVED=0,
        timestamp=timestamp, session_id=0,
        event_id=_CPU_EVENTLOG_CPU_SAMPLE_ID, thread_id=0)
    sample = _build_cpu_sample_payload(pid, pcs)
    buf = (ctypes.c_char * len(sample)).from_buffer_copy(sample)
    lib.elog_source_lines_observe(
        b"cpu", ctypes.byref(hdr), buf, len(sample))


def _resolve(lib, emit_cb):
    """Run the deferred DWARF resolution pass (elog calls this after the
    capture loop)."""
    lib.elog_source_lines_resolve(emit_cb, None)


def _skip_if_no_dwarf(lib):
    if lib.elog_source_lines_lines_emitted() == 0:
        pytest.skip(
            "DWARF lookup missed (probe binary has no usable .debug_line; "
            f"misses={lib.elog_source_lines_misses()})")


class TestElogSourceLines:
    """ctypes unit tests for libelog_source_lines (no /dev/eventlog)."""

    @pytest.mark.timeout(30)
    def test_source_lines_resolve_and_dedup(self, tmp_path):
        """Feed LINKER_FILE + CPU_SAMPLE through libelog_source_lines,
        run the deferred resolve, and check one SOURCE_LINE is emitted
        for the sampled PC (and that a repeat sample is deduped).
        """
        lib = _load_source_lines_lib()
        bin_path, vas, text_vaddr = _build_probe(tmp_path)

        # Treat the probe as a "kernel" linker file whose runtime base
        # equals the ELF text vaddr so file_offset = pc - base maps
        # straight back to the DWARF address.
        emitted = []

        def _on_emit(hdr_p, payload, size, cookie):
            hdr = hdr_p.contents
            emitted.append((hdr.event_id, hdr.provider_id, hdr.timestamp,
                            int(size), ctypes.string_at(payload, size)))

        emit_cb = _EmitFn(_on_emit)

        lib.elog_source_lines_init()
        try:
            _observe_linker_file(lib, 3, text_vaddr, 0x1000000,
                                 bin_path, timestamp=100)
            _observe_cpu_sample(lib, 0, [vas["main"]],
                                timestamp=250)
            # Nothing is emitted during capture; resolution is deferred.
            assert lib.elog_source_lines_lines_emitted() == 0
            assert not any(e[0] == _SYMBOLS_EVENTLOG_SOURCE_LINE_ID
                           for e in emitted)
            _resolve(lib, emit_cb)
            _skip_if_no_dwarf(lib)

            lines = lib.elog_source_lines_lines_emitted()
            assert lib.elog_source_lines_files_emitted() >= 1, (
                "expected at least one SOURCE_FILE")
            assert any(e[0] == _SYMBOLS_EVENTLOG_SOURCE_FILE_ID
                       for e in emitted)
            assert any(e[0] == _SYMBOLS_EVENTLOG_SOURCE_LINE_ID
                       for e in emitted)
            assert all(e[1] == 9 for e in emitted
                       if e[0] in (_SYMBOLS_EVENTLOG_SOURCE_FILE_ID,
                                   _SYMBOLS_EVENTLOG_SOURCE_LINE_ID))
            assert all(e[2] == 250 for e in emitted
                       if e[0] in (_SYMBOLS_EVENTLOG_SOURCE_FILE_ID,
                                   _SYMBOLS_EVENTLOG_SOURCE_LINE_ID)), (
                "SOURCE_* must use the max observed event timestamp")

            before = len(emitted)
            _observe_cpu_sample(lib, 0, [vas["main"]])
            assert lib.elog_source_lines_lines_emitted() == lines, (
                "repeat PC must be deduped")
            assert len(emitted) == before, (
                "deduped sample must not re-emit SOURCE_LINE")
            # A second resolve() is a no-op.
            _resolve(lib, emit_cb)
            assert len(emitted) == before
        finally:
            lib.elog_source_lines_shutdown()

    @pytest.mark.timeout(30)
    def test_source_lines_walks_full_stack(self, tmp_path):
        """Every frame in a sample is resolved, not just the leaf; an
        out-of-range PC counts as a no-binary miss at resolve time.
        """
        lib = _load_source_lines_lib()
        bin_path, vas, text_vaddr = _build_probe(tmp_path)

        emitted = []

        def _on_emit(hdr_p, payload, size, cookie):
            emitted.append((hdr_p.contents.event_id,
                            ctypes.string_at(payload, size)))

        emit_cb = _EmitFn(_on_emit)

        lib.elog_source_lines_init()
        try:
            _observe_linker_file(lib, 3, text_vaddr, 0x1000000,
                                 bin_path)
            _observe_cpu_sample(lib, 0,
                                [vas["helper"], vas["main"]])
            _observe_cpu_sample(lib, 0, [0xDEADBEEF0000])
            assert lib.elog_source_lines_misses_no_binary() == 0, (
                "no-binary misses are counted at resolve, not observe")
            _resolve(lib, emit_cb)
            _skip_if_no_dwarf(lib)
            assert lib.elog_source_lines_lines_emitted() >= 2, (
                "both stack frames should resolve")
            assert lib.elog_source_lines_misses_no_binary() == 1

            before = len(emitted)
            _observe_cpu_sample(lib, 0,
                                [vas["helper"], vas["main"]])
            _resolve(lib, emit_cb)
            assert len(emitted) == before, "repeat stack must dedup"

            binaries = []
            lib.elog_source_lines_foreach_binary(
                _BinaryFn(lambda *a: binaries.append(a)), None)
            probe = [b for b in binaries
                     if b[2] == str(bin_path).encode()]
            assert probe and probe[0][4] >= 2, (
                "foreach must report the probe's emitted lines")
        finally:
            lib.elog_source_lines_shutdown()

    @pytest.mark.timeout(30)
    def test_source_lines_sample_before_linker_file(self, tmp_path):
        """A CPU_SAMPLE seen before its LINKER_FILE still resolves once
        every mapping event has been observed.
        """
        lib = _load_source_lines_lib()
        bin_path, vas, text_vaddr = _build_probe(tmp_path)

        emitted = []

        def _on_emit(hdr_p, payload, size, cookie):
            emitted.append(hdr_p.contents.event_id)

        emit_cb = _EmitFn(_on_emit)

        lib.elog_source_lines_init()
        try:
            _observe_cpu_sample(lib, 0, [vas["main"]])
            assert lib.elog_source_lines_lines_emitted() == 0
            _observe_linker_file(lib, 3, text_vaddr, 0x1000000,
                                 bin_path)
            _resolve(lib, emit_cb)
            _skip_if_no_dwarf(lib)
            assert lib.elog_source_lines_lines_emitted() >= 1, (
                "PC recorded before LINKER_FILE must resolve")
            assert lib.elog_source_lines_misses_no_binary() == 0
            assert _SYMBOLS_EVENTLOG_SOURCE_LINE_ID in emitted
        finally:
            lib.elog_source_lines_shutdown()

    @pytest.mark.timeout(30)
    def test_source_lines_merges_split_debug_file(self, tmp_path):
        """A binary whose own .debug_line is thin still resolves a PC in a
        function only the split /usr/lib/debug twin names. The index is
        merged across both files, and both frames keep the DWARF path that
        knows them.
        """
        lib = _load_source_lines_lib()
        bin_path, vas, text_vaddr, debug_root = _build_split_debug_pair(
            tmp_path)

        emitted = []

        def _on_emit(hdr_p, payload, size, cookie):
            emitted.append(hdr_p.contents.event_id)

        emit_cb = _EmitFn(_on_emit)

        lib.elog_source_lines_init()
        try:
            lib.elog_source_lines_set_debug_path(str(debug_root).encode())
            _observe_linker_file(lib, 3, text_vaddr, 0x1000000,
                                 bin_path)
            _observe_cpu_sample(lib, 0, [vas["helper"], vas["main"]])
            _resolve(lib, emit_cb)
            lines = lib.elog_source_lines_lines_emitted()
            assert lines >= 2, (
                "expected rows from the split debug twin, got "
                f"{lines} (misses={lib.elog_source_lines_misses()})")
            debug_path = lib.elog_source_lines_binary_debug_path(
                str(bin_path).encode())
            assert debug_path is not None
            debug_path = debug_path.decode()
            assert debug_path.endswith(".debug"), (
                f"split twin not used; debug file was {debug_path!r}")
            assert debug_path.startswith(str(tmp_path)), (
                "expected the twin under this test's debug tree, got "
                f"{debug_path!r}")
        finally:
            lib.elog_source_lines_shutdown()

    @pytest.mark.timeout(30)
    def test_source_lines_commit_id_from_kernel_version(self, tmp_path):
        """kern.version stamps kernel SOURCE_FILE rows with the firmware
        commit. A plain version leaves commit_id empty. -dirty is the
        same commit with a dirty tree; the hash is still recorded.
        """
        lib = _load_source_lines_lib()
        bin_path, vas, text_vaddr = _build_probe(tmp_path)

        emitted = []

        def _on_emit(hdr_p, payload, size, cookie):
            emitted.append((hdr_p.contents.event_id,
                            ctypes.string_at(payload, size)))

        emit_cb = _EmitFn(_on_emit)

        for version, want in (
            (b"FreeBSD 16.0-CURRENT pull/5915-n8635-a36b8d97a3a7 RED1",
             b"a36b8d97a3a7"),
            (b"FreeBSD 16.0-CURRENT #0 n8622-d9885eb13475-dirty: Wed",
             b"d9885eb13475"),
            (b"FreeBSD 16.0-CURRENT", b""),
        ):
            lib.elog_source_lines_init()
            try:
                lib.elog_source_lines_set_kernel_version(version)
                emitted.clear()
                _observe_linker_file(lib, 3, text_vaddr,
                                     0x1000000, bin_path)
                _observe_cpu_sample(lib, 0, [vas["main"]])
                _resolve(lib, emit_cb)
                _skip_if_no_dwarf(lib)
                sf = [p for eid, p in emitted
                      if eid == _SYMBOLS_EVENTLOG_SOURCE_FILE_ID]
                assert sf, "expected a SOURCE_FILE"
                # packed: id u32, kind u8, binary_id u32, commit_id[41]
                commit = sf[0][9:50].split(b"\0")[0]
                assert commit == want, (
                    f"version {version!r}: commit_id {commit!r}")
            finally:
                lib.elog_source_lines_shutdown()
