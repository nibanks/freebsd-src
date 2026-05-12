#
# Copyright (c) 2026 Netflix, Inc.
#
# SPDX-License-Identifier: BSD-2-Clause
#

"""ATF tests for the elog(1) userspace utility.

Smoke tests for the elog binary CLI surface. These catch packaging
regressions (missing binary, broken option parser, broken capture-file
reader) without requiring /dev/eventlog or any provider to be present.

End-to-end coverage of the device interface and individual providers
lives with the providers themselves; the framework's own kernel-side
tests are in kern_eventlog_test.py.
"""

import subprocess
from pathlib import Path

import pytest
from atf_python.utils import BaseTest

ELOG = "/usr/bin/elog"


class TestElogCli(BaseTest):
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
