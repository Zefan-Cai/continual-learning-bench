from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


SOURCE_PATH = (
    Path(__file__).resolve().parents[1] / "cohort_closed_loop_private_access_probe.c"
)


def _source() -> str:
    return SOURCE_PATH.read_text(encoding="ascii")


def _function(source: str, name: str) -> str:
    start = source.index(name)
    next_function = re.search(
        r"\n(?:static\s+)?(?:int|void|bool|size_t)\s+\w+\(", source[start + 1 :]
    )
    if next_function is None:
        return source[start:]
    return source[start : start + 1 + next_function.start()]


def test_unavailable_root_broker_is_a_hard_operation_gate() -> None:
    source = _source()
    assert "#define ROOT_CAPABILITY_BROKER_PROVIDER_AVAILABLE 0" in source
    claim = _function(source, "static void claim_root_capability_or_die")
    assert 'die("root capability broker claim protocol is not implemented")' in claim

    main = source[source.index("int main(int argc") :]
    ordered = (
        "verify_pre_transition();",
        "ROOT_CAPABILITY_BROKER_PROVIDER_AVAILABLE != 1",
        "claim_root_capability_or_die(&options);",
        "open_private_root_anchor(&options);",
        "transition_credentials(&options);",
        "perform_operation(&options, private_root_fd, &outcome);",
    )
    positions = tuple(main.index(value) for value in ordered)
    assert positions == tuple(sorted(positions))


def test_broker_contract_binds_unforgeable_full_request_and_sequence() -> None:
    source = _source()
    for option in (
        "--expected-private-root-device",
        "--expected-private-root-inode",
        "--request-capability-path",
        "--request-capability-sha256",
        "--expected-capability-root-device",
        "--expected-capability-root-inode",
        "--request-capability-epoch",
        "--request-capability-ordinal",
        "--request-capability-nonce",
        "--request-expiry-boottime-seconds",
        "--attester-parent-pid",
        "--attester-parent-start-ticks",
    ):
        assert option in source
    for contract_fragment in (
        '"/run/cohort-closed-loop-private-probe-capabilities"',
        '"/epochs/%" PRIu64 "/next/%" PRIu64 "-%s.request"',
        "root:root 0700",
        "root:root 0400",
        "nlink=1",
        "payload size/SHA-256",
        "attester parent PID/start ticks",
        "renameat2(RENAME_NOREPLACE)",
        "Ordinal 1 is the",
        "only genesis",
        "immediately prior",
        "UID 41001 controls argv",
    ):
        assert contract_fragment in source
    assert "options->request_epoch == 0U" in source
    assert "options->request_ordinal == 0U" in source
    assert "valid_lower_sha256(options->request_nonce)" in source
    assert "validate_capability_path(options);" in source


def test_all_private_operations_are_descriptor_anchored_after_drop() -> None:
    source = _source()
    operation = _function(source, "static void perform_operation")
    assert "open(options->path" not in operation
    assert "unlink(options->path" not in operation
    assert "lstat(options->path" not in operation
    assert "anchored_open(root_fd, options->relative_path" in operation
    assert "unlinkat(root_fd, options->relative_path" in operation
    assert "fstatat(root_fd, options->relative_path" in operation
    assert operation.count("verify_private_root_anchor(options, root_fd);") == 2

    anchored = _function(source, "static int anchored_open")
    for flag in (
        "RESOLVE_BENEATH",
        "RESOLVE_NO_SYMLINKS",
        "RESOLVE_NO_MAGICLINKS",
        "RESOLVE_NO_XDEV",
    ):
        assert flag in anchored
    root_open = _function(source, "static int open_private_root_anchor")
    assert "O_PATH | O_DIRECTORY | O_CLOEXEC" in root_open
    assert "RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS" in root_open
    assert "expected_private_root_device" in source
    assert "expected_private_root_inode" in source


def test_unexpected_create_cleanup_is_anchored_and_fail_closed() -> None:
    source = _source()
    operation = _function(source, "static void perform_operation")
    assert 'die("unexpected-success create cleanup unlink failed")' in operation
    assert 'die("unexpected-success create cleanup verification failed")' in operation
    cleanup = operation.index("unexpected-success create cleanup unlink failed")
    assert operation.rfind("unlinkat(root_fd, options->relative_path", 0, cleanup) >= 0
    assert "AT_SYMLINK_NOFOLLOW" in operation[cleanup:]


def test_receipt_binds_root_identity_and_relative_target() -> None:
    source = _source()
    receipt = _function(source, "static void emit_receipt")
    for key in (
        "private_context_root_device",
        "private_context_root_inode",
        "private_context_root_path",
        "relative_path",
    ):
        assert f'\\"{key}\\"' in receipt
    assert 'printf(",\\"schema_version\\":2")' in receipt


@pytest.mark.skipif(sys.platform != "linux", reason="Linux-only setuid/openat2 source")
def test_linux_source_compiles_with_strict_warnings(tmp_path: Path) -> None:
    compiler = shutil.which("cc")
    if compiler is None:
        pytest.skip("no C compiler")
    subprocess.run(
        [
            compiler,
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-Wformat=2",
            "-Wshadow",
            str(SOURCE_PATH),
            "-o",
            str(tmp_path / "private-access-probe"),
        ],
        check=True,
        capture_output=True,
        text=True,
    )
