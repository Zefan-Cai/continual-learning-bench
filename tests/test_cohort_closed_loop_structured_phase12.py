from __future__ import annotations

import hashlib
import importlib.util
import inspect
import json
import os
import errno
import fcntl
import stat
import sys
from contextlib import contextmanager
from dataclasses import replace
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Any, Callable

import pytest

import cohort_closed_loop_structured_deployment_snapshot as snapshot
import cohort_closed_loop_structured_protocol_plan as protocol_plan
import cohort_closed_loop_structured_trigger_bridge as bridge


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reseal(
    payload: dict[str, Any], self_key: str, unsigned_keys: frozenset[str]
) -> bytes:
    payload[self_key] = _sha(_canonical({key: payload[key] for key in unsigned_keys}))
    return _canonical(payload)


def _strict_fixture_module() -> ModuleType:
    name = "_phase12_strict_trigger_fixture"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = Path(__file__).with_name(
        "test_cohort_closed_loop_structured_trigger_receipt_revalidator.py"
    )
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise AssertionError("cannot load strict trigger fixture module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _strict_receipt_and_inputs() -> tuple[bytes, dict[str, bytes]]:
    raw, inputs = _strict_fixture_module()._receipt_and_inputs()  # type: ignore[attr-defined]
    assert set(inputs) == set(bridge.STRICT_RAW_EVIDENCE_EDGE_NAMES)
    assert all(type(value) is bytes for value in inputs.values())
    return raw, inputs


class _FakeSnapshotFilesystem:
    ROOT_DEVICE = os.makedev(0, 1)
    CHECKOUT_DEVICE = os.makedev(7, 1)
    ASSET_DEVICE = os.makedev(8, 1)

    def __init__(self, *, source_commit: str, attempt_id: str) -> None:
        self.source_commit = source_commit
        self.attempt_id = attempt_id
        self.checkout = PurePosixPath(snapshot.CHECKOUT_BASE, source_commit, attempt_id)
        self.data: dict[str, bytes] = {}
        self.metadata: dict[str, snapshot.FileMetadata] = {}
        self.directories: dict[str, tuple[str, ...]] = {}
        self.committed: dict[str, bytes] = {}
        self.status_raw = b""
        self.submodule_raw = b""
        self.git_index_override: bytes | None = None
        self.rev_parse_calls = 0
        self.before_terminal_git_pass: Callable[[], None] | None = None
        self.mountinfo_raw = (
            b"10 1 0:1 / / ro - rootfs rootfs ro\n"
            b"11 10 7:1 / /mnt/localssd ro - ext4 /dev/localssd ro\n"
            b"12 10 8:1 / /asset-bundle ro - ext4 /dev/assets ro\n"
        )
        self.boot_id_value = "11111111-2222-4333-8444-555555555555"
        self.process_identity_value = snapshot.ProcessIdentity(4242, 987654)
        self.mount_namespace_value = snapshot.MountNamespaceIdentity(
            device=os.makedev(0, 4), inode=7777, link_target="mnt:[7777]"
        )
        self.second_mount_namespace_value: snapshot.MountNamespaceIdentity | None = None
        self.mount_namespace_calls = 0
        self.clock_tick = 0
        self._inode = 100
        self._add_directory(PurePosixPath("/"), device=self.ROOT_DEVICE)
        self._add_directory(PurePosixPath("/mnt"), device=self.ROOT_DEVICE)
        self._add_directory(PurePosixPath("/mnt/localssd"), device=self.CHECKOUT_DEVICE)
        self._add_directory(
            PurePosixPath(snapshot.CHECKOUT_BASE), device=self.CHECKOUT_DEVICE
        )
        self._add_directory(self.checkout.parent, device=self.CHECKOUT_DEVICE)
        self._add_directory(self.checkout, device=self.CHECKOUT_DEVICE)
        self._add_directory(self.checkout / "sources", device=self.CHECKOUT_DEVICE)

        for role in snapshot.SOURCE_ROLE_IDS:
            path = self.checkout / "sources" / f"{role}.py"
            raw = f"# committed source role: {role}\n".encode("ascii")
            self._add_file(path, raw, device=self.CHECKOUT_DEVICE)
            self.committed[path.relative_to(self.checkout).as_posix()] = raw

        repo = Path(__file__).resolve().parent.parent
        controls = {
            "COHORT_CLOSED_LOOP_STRUCTURED_EXECUTION_CONTRACT_V1.md": (
                repo / "COHORT_CLOSED_LOOP_STRUCTURED_EXECUTION_CONTRACT_V1.md"
            ).read_bytes(),
            "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md": (
                repo / "COHORT_CLOSED_LOOP_STRUCTURED_STATE_PREREG_V1.md"
            ).read_bytes(),
        }
        for relative, raw in controls.items():
            path = self.checkout / relative
            self._add_file(path, raw, device=self.CHECKOUT_DEVICE)
            self.committed[relative] = raw

        self.asset_roots: dict[str, PurePosixPath] = {}
        self._add_directory(PurePosixPath("/asset-bundle"), device=self.ASSET_DEVICE)
        for role in snapshot.ASSET_ROLE_IDS:
            root = PurePosixPath("/asset-bundle", role)
            path = root / "payload.bin"
            self._add_directory(root, device=self.ASSET_DEVICE)
            self._add_file(
                path,
                f"materialized asset bytes: {role}\n".encode("ascii"),
                device=self.ASSET_DEVICE,
            )
            self.directories[str(root)] = ("payload.bin",)
            self.asset_roots[role] = root

        self.lease_descriptor = 77
        initial_lease_metadata = snapshot.FileMetadata(
            device=os.makedev(9, 1),
            inode=909,
            mode=stat.S_IFREG | snapshot.LEASE_FILE_MODE,
            owner_uid=snapshot.CAPTURE_SERVICE_UID,
            owner_gid=snapshot.CAPTURE_SERVICE_GID,
            size_bytes=0,
            mtime_ns=100,
        )
        self.lease_raw = snapshot._build_lease_receipt_bytes(  # noqa: SLF001
            source_commit=source_commit,
            attempt_id=attempt_id,
            lease_path=str(
                PurePosixPath(
                    snapshot.DURABLE_BASE,
                    source_commit,
                    "attempts",
                    attempt_id,
                    snapshot.LEASE_RELATIVE_PATH,
                )
            ),
            boot_id=self.boot_id_value,
            process_identity=self.process_identity_value,
            mount_namespace=self.mount_namespace_value,
            lease_metadata=initial_lease_metadata,
            created_at_utc="2026-07-14T12:00:00.000000Z",
        )
        self.lease_metadata_value = replace(
            initial_lease_metadata, size_bytes=len(self.lease_raw)
        )

    def _next_inode(self) -> int:
        self._inode += 1
        return self._inode

    def _add_directory(self, path: PurePosixPath, *, device: int) -> None:
        self.metadata[str(path)] = snapshot.FileMetadata(
            device=device,
            inode=self._next_inode(),
            mode=stat.S_IFDIR | snapshot.DEPLOYMENT_DIRECTORY_MODE,
            owner_uid=41002,
            owner_gid=41002,
            size_bytes=0,
            mtime_ns=100,
        )
        self.directories.setdefault(str(path), ())

    def _add_file(self, path: PurePosixPath, raw: bytes, *, device: int) -> None:
        self.data[str(path)] = raw
        self.metadata[str(path)] = snapshot.FileMetadata(
            device=device,
            inode=self._next_inode(),
            mode=stat.S_IFREG | 0o440,
            owner_uid=41002,
            owner_gid=41002,
            size_bytes=len(raw),
            mtime_ns=100,
        )

    def git(self, root: PurePosixPath, arguments: tuple[str, ...]) -> bytes:
        assert root == self.checkout
        if arguments == ("rev-parse", "--verify", "HEAD"):
            self.rev_parse_calls += 1
            if self.rev_parse_calls == 2 and self.before_terminal_git_pass is not None:
                self.before_terminal_git_pass()
            return (self.source_commit + "\n").encode("ascii")
        if arguments == (
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
        ):
            return self.status_raw
        if arguments == ("submodule", "status", "--recursive"):
            return self.submodule_raw
        if arguments == ("ls-files", "--stage", "-z"):
            if self.git_index_override is not None:
                return self.git_index_override
            return b"".join(
                b"100644 "
                + hashlib.sha1(raw).hexdigest().encode("ascii")
                + b" 0\t"
                + relative.encode("utf-8")
                + b"\x00"
                for relative, raw in sorted(self.committed.items())
            )
        if arguments[:3] == ("ls-files", "--error-unmatch", "--"):
            relative = arguments[3]
            if relative not in self.committed:
                raise snapshot.DeploymentSnapshotError("not tracked")
            return (relative + "\n").encode("utf-8")
        if arguments[:2] == ("cat-file", "blob"):
            prefix = "HEAD:"
            assert arguments[2].startswith(prefix)
            return self.committed[arguments[2][len(prefix) :]]
        raise AssertionError(f"unexpected git command: {arguments!r}")

    def lstat(self, path: PurePosixPath) -> snapshot.FileMetadata:
        try:
            return self.metadata[str(path)]
        except KeyError as exc:
            raise snapshot.DeploymentSnapshotError(f"missing path: {path}") from exc

    def read_bytes(self, path: PurePosixPath) -> bytes:
        return self.data[str(path)]

    def listdir(self, path: PurePosixPath) -> tuple[str, ...]:
        return self.directories[str(path)]

    def mountinfo(self) -> bytes:
        return self.mountinfo_raw

    def boot_id(self) -> str:
        return self.boot_id_value

    def process_identity(self) -> snapshot.ProcessIdentity:
        return self.process_identity_value

    def mount_namespace(self) -> snapshot.MountNamespaceIdentity:
        self.mount_namespace_calls += 1
        if (
            self.mount_namespace_calls == 2
            and self.second_mount_namespace_value is not None
        ):
            return self.second_mount_namespace_value
        return self.mount_namespace_value

    def clock_utc(self) -> str:
        self.clock_tick += 1
        return f"2026-07-14T12:00:{self.clock_tick:02d}.000000Z"

    def lease_metadata(self, descriptor: int) -> snapshot.FileMetadata:
        assert descriptor == self.lease_descriptor
        return self.lease_metadata_value

    def lease_bytes(self, descriptor: int) -> bytes:
        assert descriptor == self.lease_descriptor
        return self.lease_raw

    def runtime(self) -> snapshot.DeploymentSnapshotRuntime:
        return snapshot.DeploymentSnapshotRuntime(
            git=self.git,
            lstat=self.lstat,
            read_bytes=self.read_bytes,
            listdir=self.listdir,
            mountinfo=self.mountinfo,
            boot_id=self.boot_id,
            process_identity=self.process_identity,
            mount_namespace=self.mount_namespace,
            clock_utc=self.clock_utc,
            lease_metadata=self.lease_metadata,
            lease_bytes=self.lease_bytes,
        )

    def source_paths(self) -> dict[str, str]:
        return {
            role: str(self.checkout / "sources" / f"{role}.py")
            for role in snapshot.SOURCE_ROLE_IDS
        }

    def capture_kwargs(self) -> dict[str, Any]:
        return {
            "source_commit": self.source_commit,
            "attempt_id": self.attempt_id,
            "checkout_root": str(self.checkout),
            "source_paths_by_role": self.source_paths(),
            "asset_roots_by_role": {
                role: str(root) for role, root in self.asset_roots.items()
            },
            "lease_descriptor": self.lease_descriptor,
            "lease_receipt_bytes": self.lease_raw,
            "runtime": self.runtime(),
        }


def _capture_fixture(
    *, source_commit: str = "b" * 40
) -> tuple[
    _FakeSnapshotFilesystem,
    snapshot.DeploymentSnapshotArtifacts,
]:
    filesystem = _FakeSnapshotFilesystem(
        source_commit=source_commit, attempt_id="attempt-001"
    )
    artifacts = snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
        **filesystem.capture_kwargs()
    )
    return filesystem, artifacts


def _snapshot_validation_kwargs(
    artifacts: snapshot.DeploymentSnapshotArtifacts,
) -> dict[str, Any]:
    return {
        "source_inventory_bytes": artifacts.source_inventory_bytes,
        "asset_inventory_bytes_by_role": dict(artifacts.asset_inventory_bytes),
        "source_file_bytes_by_role": dict(artifacts.source_file_bytes),
        "asset_file_bytes_by_role": {
            role: dict(files) for role, files in artifacts.asset_file_bytes
        },
        "execution_contract_bytes": artifacts.execution_contract_bytes,
        "structured_preregistration_bytes": (
            artifacts.structured_preregistration_bytes
        ),
        "git_index_bytes": artifacts.git_index_bytes,
        "lease_receipt_bytes": artifacts.lease_receipt_bytes,
        "observation_bytes": artifacts.observation_bytes,
    }


def test_bridge_revalidates_every_independent_raw_edge_without_authority() -> None:
    receipt, inputs = _strict_receipt_and_inputs()

    result = bridge.revalidate_and_bind_trigger_a_receipt(receipt, **inputs)
    validated = bridge.validate_structured_trigger_bridge_bytes(
        result.bridge_receipt_bytes,
        trigger_receipt_bytes=receipt,
        **inputs,
    )

    assert result == validated
    assert result.raw_evidence_edge_count == len(bridge.STRICT_RAW_EVIDENCE_EDGE_NAMES)
    assert result.raw_evidence_edge_count == 21
    assert result.tooling_source_commit == "b" * 40
    assert result.model_calls_authorized is False
    assert result.operational_authorization is False
    payload = json.loads(result.bridge_receipt_bytes)
    assert payload["strict_revalidation"]["tooling_source_commit"] == "b" * 40
    assert payload["strict_raw_evidence_edge_count"] == 21
    assert [
        row["binding_id"] for row in payload["strict_raw_evidence_bindings"]
    ] == list(bridge.STRICT_RAW_EVIDENCE_EDGE_NAMES)
    assert result.bridge_receipt_bytes == _canonical(payload)
    assert "cohort_closed_loop_structured_trigger_receipt" not in (
        value.__name__
        for value in bridge.__dict__.values()
        if isinstance(value, ModuleType)
    )


def test_bridge_rejects_raw_edge_substitution_and_forged_bridge() -> None:
    receipt, inputs = _strict_receipt_and_inputs()
    result = bridge.revalidate_and_bind_trigger_a_receipt(receipt, **inputs)
    substituted = dict(inputs)
    substituted["causal_original_decision_bytes"] += b"\n"
    with pytest.raises(bridge.StructuredTriggerBridgeError):
        bridge.validate_structured_trigger_bridge_bytes(
            result.bridge_receipt_bytes,
            trigger_receipt_bytes=receipt,
            **substituted,
        )

    forged = json.loads(result.bridge_receipt_bytes)
    forged["model_calls_authorized"] = True
    unsigned = {
        key: value for key, value in forged.items() if key != "bridge_receipt_sha256"
    }
    forged["bridge_receipt_sha256"] = _sha(_canonical(unsigned))
    with pytest.raises(
        bridge.StructuredTriggerBridgeError, match="strict reconstruction"
    ):
        bridge.validate_structured_trigger_bridge_bytes(
            _canonical(forged), trigger_receipt_bytes=receipt, **inputs
        )


def test_impure_snapshot_and_pure_validator_bind_complete_raw_bytes() -> None:
    _, artifacts = _capture_fixture()

    validation = snapshot.validate_deployment_snapshot_bytes(
        artifacts.deployment_snapshot_bytes,
        **_snapshot_validation_kwargs(artifacts),
    )

    assert validation.source_commit == "b" * 40
    assert validation.attempt_id == "attempt-001"
    assert validation.checkout_root.endswith("/" + validation.attempt_id)
    assert len(validation.source_bindings) == len(snapshot.SOURCE_ROLE_IDS)
    assert len(validation.asset_inventory_bindings) == len(snapshot.ASSET_ROLE_IDS)
    assert validation.normalized_observations_equal is True
    assert validation.read_only_mounts_verified is True
    assert validation.fresh_consumer_revalidation_required is True
    assert validation.dgp_generation_authorized is False
    assert validation.model_calls_authorized is False
    assert validation.operational_authorization is False
    observations = [json.loads(raw) for raw in artifacts.observation_bytes]
    assert observations[0]["state"] == observations[1]["state"]
    assert observations[0]["state_sha256"] == observations[1]["state_sha256"]
    assert observations[0]["ordinal"] == 1
    assert observations[1]["ordinal"] == 2
    assert observations[0]["observed_at_utc"] != observations[1]["observed_at_utc"]
    payload = json.loads(artifacts.deployment_snapshot_bytes)
    assert payload["normalized_observations_equal"] is True
    assert payload["fresh_consumer_revalidation_available"] is False
    for raw in (
        artifacts.deployment_snapshot_bytes,
        artifacts.source_inventory_bytes,
        *(value for _, value in artifacts.asset_inventory_bytes),
    ):
        raw.decode("ascii")
        assert raw == _canonical(json.loads(raw))


def test_snapshot_rejects_dirty_submodule_alias_symlink_cross_device_and_lfs() -> None:
    filesystem = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    kwargs = filesystem.capture_kwargs()

    filesystem.status_raw = b"?? untracked\x00"
    with pytest.raises(
        snapshot.DeploymentSnapshotError, match="dirty or has untracked"
    ):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.status_raw = b""

    filesystem.submodule_raw = b"-deadbeef vendor/submodule\n"
    with pytest.raises(snapshot.DeploymentSnapshotError, match="submodules"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.submodule_raw = b""

    filesystem.git_index_override = b"160000 " + b"d" * 40 + b" 0\tvendor/submodule\x00"
    with pytest.raises(snapshot.DeploymentSnapshotError, match="submodule gitlink"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.git_index_override = None

    missing_sources = filesystem.source_paths()
    del missing_sources[snapshot.SOURCE_ROLE_IDS[0]]
    with pytest.raises(snapshot.DeploymentSnapshotError, match="role set differs"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **{**kwargs, "source_paths_by_role": missing_sources}
        )

    aliased = filesystem.source_paths()
    aliased[snapshot.SOURCE_ROLE_IDS[1]] = aliased[snapshot.SOURCE_ROLE_IDS[0]]
    with pytest.raises(snapshot.DeploymentSnapshotError, match="share a path"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **{**kwargs, "source_paths_by_role": aliased}
        )

    first_source = snapshot.SOURCE_ROLE_IDS[0]
    source_path = PurePosixPath(filesystem.source_paths()[first_source])
    source_regular = filesystem.metadata[str(source_path)]
    filesystem.metadata[str(source_path)] = replace(
        source_regular, mode=stat.S_IFLNK | 0o777
    )
    with pytest.raises(snapshot.DeploymentSnapshotError, match="non-symlink regular"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.metadata[str(source_path)] = source_regular

    first_asset = snapshot.ASSET_ROLE_IDS[0]
    asset_path = filesystem.asset_roots[first_asset] / "payload.bin"
    regular = filesystem.metadata[str(asset_path)]
    asset_bundle = filesystem.metadata["/asset-bundle"]
    filesystem.metadata["/asset-bundle"] = replace(
        asset_bundle, mode=stat.S_IFLNK | 0o777
    )
    with pytest.raises(snapshot.DeploymentSnapshotError, match="ancestor"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.metadata["/asset-bundle"] = asset_bundle

    filesystem.metadata[str(asset_path)] = replace(regular, mode=stat.S_IFLNK | 0o777)
    with pytest.raises(snapshot.DeploymentSnapshotError, match="symlink"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.metadata[str(asset_path)] = replace(regular, device=99)
    with pytest.raises(snapshot.DeploymentSnapshotError, match="crosses a device"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001
    filesystem.metadata[str(asset_path)] = regular

    lfs = b"version https://git-lfs.github.com/spec/v1\noid sha256:" + b"0" * 64
    filesystem.data[str(asset_path)] = lfs
    filesystem.metadata[str(asset_path)] = replace(regular, size_bytes=len(lfs))
    with pytest.raises(snapshot.DeploymentSnapshotError, match="Git LFS pointer"):
        snapshot._capture_deployment_snapshot_core(**kwargs)  # noqa: SLF001


def test_default_fd_anchored_capture_rejects_symlink_descent(tmp_path: Path) -> None:
    root = tmp_path / "anchored"
    real = root / "real"
    real.mkdir(parents=True)
    (real / "payload.bin").write_bytes(b"payload")
    (root / "alias").symlink_to(real, target_is_directory=True)

    captured = snapshot._capture_root(  # noqa: SLF001
        snapshot.DeploymentSnapshotRuntime(),
        PurePosixPath(str(root)),
        ("real/payload.bin",),
    )
    assert captured.files[0].raw == b"payload"
    with pytest.raises(snapshot.DeploymentSnapshotError, match="anchored"):
        snapshot._capture_root(  # noqa: SLF001
            snapshot.DeploymentSnapshotRuntime(),
            PurePosixPath(str(root)),
            ("alias/payload.bin",),
        )


def test_snapshot_terminal_pass_rejects_source_and_asset_inode_drift() -> None:
    source_filesystem = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    source_role = snapshot.SOURCE_ROLE_IDS[0]
    source_path = PurePosixPath(source_filesystem.source_paths()[source_role])

    def drift_source() -> None:
        raw = source_filesystem.data[str(source_path)] + b"# terminal drift\n"
        source_filesystem.data[str(source_path)] = raw
        source_filesystem.metadata[str(source_path)] = replace(
            source_filesystem.metadata[str(source_path)],
            size_bytes=len(raw),
            mtime_ns=101,
        )

    source_filesystem.before_terminal_git_pass = drift_source
    with pytest.raises(
        snapshot.DeploymentSnapshotError, match="source/control.*drifted"
    ):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **source_filesystem.capture_kwargs()
        )

    asset_filesystem = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    asset_role = snapshot.ASSET_ROLE_IDS[0]
    asset_path = asset_filesystem.asset_roots[asset_role] / "payload.bin"

    def drift_asset_inode() -> None:
        asset_filesystem.metadata[str(asset_path)] = replace(
            asset_filesystem.metadata[str(asset_path)], inode=99_999
        )

    asset_filesystem.before_terminal_git_pass = drift_asset_inode
    with pytest.raises(
        snapshot.DeploymentSnapshotError, match=f"asset {asset_role}.*drifted"
    ):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **asset_filesystem.capture_kwargs()
        )


def test_snapshot_rejects_stacked_longest_mount_and_wrong_mount_device() -> None:
    stacked = _FakeSnapshotFilesystem(source_commit="b" * 40, attempt_id="attempt-001")
    stacked.mountinfo_raw += (
        b"13 10 7:1 / /mnt/localssd ro - ext4 /dev/stacked-localssd ro\n"
    )
    with pytest.raises(snapshot.DeploymentSnapshotError, match="non-unique longest"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **stacked.capture_kwargs()
        )

    wrong_device = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    wrong_device.mountinfo_raw = wrong_device.mountinfo_raw.replace(b"7:1", b"9:1")
    with pytest.raises(snapshot.DeploymentSnapshotError, match="major:minor"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **wrong_device.capture_kwargs()
        )


def test_snapshot_terminal_pass_rejects_git_index_drift() -> None:
    filesystem = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )

    def drift_index() -> None:
        filesystem.git_index_override = b"".join(
            b"100644 "
            + hashlib.sha1(raw).hexdigest().encode("ascii")
            + b" 0\t"
            + relative.encode("utf-8")
            + b"\x00"
            for relative, raw in sorted(filesystem.committed.items())
        ) + (b"100644 " + b"d" * 40 + b" 0\tterminal-extra.txt\x00")

    filesystem.before_terminal_git_pass = drift_index
    with pytest.raises(snapshot.DeploymentSnapshotError, match="Git state drifted"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **filesystem.capture_kwargs()
        )


def test_snapshot_rejects_writable_mount_owner_mode_and_mount_namespace_drift() -> None:
    writable = _FakeSnapshotFilesystem(source_commit="b" * 40, attempt_id="attempt-001")
    writable.mountinfo_raw = writable.mountinfo_raw.replace(
        b"/mnt/localssd ro", b"/mnt/localssd rw"
    ).replace(b"/dev/localssd ro", b"/dev/localssd rw")
    with pytest.raises(snapshot.DeploymentSnapshotError, match="not read-only"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **writable.capture_kwargs()
        )

    wrong_mode = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    wrong_mode.metadata[str(wrong_mode.checkout)] = replace(
        wrong_mode.metadata[str(wrong_mode.checkout)], mode=stat.S_IFDIR | 0o750
    )
    with pytest.raises(snapshot.DeploymentSnapshotError, match="owner or mode"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **wrong_mode.capture_kwargs()
        )

    wrong_owner = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    source_path = PurePosixPath(wrong_owner.source_paths()[snapshot.SOURCE_ROLE_IDS[0]])
    wrong_owner.metadata[str(source_path)] = replace(
        wrong_owner.metadata[str(source_path)], owner_uid=41_999
    )
    with pytest.raises(snapshot.DeploymentSnapshotError, match="owner or mode"):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **wrong_owner.capture_kwargs()
        )

    namespace_drift = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    )
    namespace_drift.second_mount_namespace_value = snapshot.MountNamespaceIdentity(
        device=os.makedev(0, 4), inode=8888, link_target="mnt:[8888]"
    )
    with pytest.raises(
        snapshot.DeploymentSnapshotError, match="normalized deployment observations"
    ):
        snapshot._capture_deployment_snapshot_core(  # noqa: SLF001
            **namespace_drift.capture_kwargs()
        )


def test_pure_snapshot_rejects_missing_or_substituted_raw_inventory_edges() -> None:
    _, artifacts = _capture_fixture()
    kwargs = _snapshot_validation_kwargs(artifacts)
    sources = dict(kwargs["source_file_bytes_by_role"])
    sources["dgp_generator"] += b"substitution"
    with pytest.raises(snapshot.DeploymentSnapshotError, match="content join"):
        snapshot.validate_deployment_snapshot_bytes(
            artifacts.deployment_snapshot_bytes,
            **{**kwargs, "source_file_bytes_by_role": sources},
        )

    assets = {
        role: dict(files) for role, files in kwargs["asset_file_bytes_by_role"].items()
    }
    del assets[snapshot.ASSET_ROLE_IDS[0]]["payload.bin"]
    with pytest.raises(snapshot.DeploymentSnapshotError, match="raw file is missing"):
        snapshot.validate_deployment_snapshot_bytes(
            artifacts.deployment_snapshot_bytes,
            **{**kwargs, "asset_file_bytes_by_role": assets},
        )


@pytest.mark.parametrize("observation_index", (0, 1))
def test_pure_snapshot_rejects_each_forged_observation_state_and_raw_lease_join(
    observation_index: int,
) -> None:
    _, artifacts = _capture_fixture()
    kwargs = _snapshot_validation_kwargs(artifacts)

    forged_observation = json.loads(artifacts.observation_bytes[observation_index])
    forged_observation["state"]["mount_namespace"]["inode"] += 1
    forged_observation["state_sha256"] = _sha(_canonical(forged_observation["state"]))
    forged_observation_raw = _reseal(
        forged_observation,
        "observation_sha256",
        snapshot._OBSERVATION_UNSIGNED_KEYS,  # noqa: SLF001
    )
    forged_snapshot = json.loads(artifacts.deployment_snapshot_bytes)
    forged_snapshot["deployment_observations"][observation_index]["sha256"] = _sha(
        forged_observation_raw
    )
    forged_snapshot["deployment_observations"][observation_index]["size_bytes"] = len(
        forged_observation_raw
    )
    forged_snapshot["deployment_observations"][observation_index]["state_sha256"] = (
        forged_observation["state_sha256"]
    )
    forged_snapshot_raw = _reseal(
        forged_snapshot,
        "deployment_snapshot_sha256",
        snapshot._SNAPSHOT_UNSIGNED_KEYS,  # noqa: SLF001
    )
    with pytest.raises(
        snapshot.DeploymentSnapshotError, match="normalized deployment observations"
    ):
        snapshot.validate_deployment_snapshot_bytes(
            forged_snapshot_raw,
            **{
                **kwargs,
                "observation_bytes": tuple(
                    forged_observation_raw if index == observation_index else raw
                    for index, raw in enumerate(artifacts.observation_bytes)
                ),
            },
        )

    substituted_lease = artifacts.lease_receipt_bytes + b"\n"
    with pytest.raises(snapshot.DeploymentSnapshotError):
        snapshot.validate_deployment_snapshot_bytes(
            artifacts.deployment_snapshot_bytes,
            **{**kwargs, "lease_receipt_bytes": substituted_lease},
        )


def test_production_entrypoint_has_no_injection_and_private_helper_rejects_prod() -> (
    None
):
    signature = inspect.signature(
        snapshot.capture_and_publish_production_deployment_snapshot
    )
    assert "runtime" not in signature.parameters
    assert "publisher" not in signature.parameters
    assert "lease_context" not in signature.parameters

    with pytest.raises(snapshot.DeploymentSnapshotError, match="rejects production"):
        snapshot._capture_and_publish_deployment_snapshot_for_test(  # noqa: SLF001
            checkout_root=(f"{snapshot.CHECKOUT_BASE}/{'b' * 40}/attempt-001"),
            durable_root="/nonproduction/durable",
            lease_context=lambda: None,
            capture=lambda _descriptor, _raw: _capture_fixture()[1],
            publisher=lambda **_kwargs: object(),
        )


def test_private_capture_holds_lease_across_all_atomic_publications() -> None:
    _, artifacts = _capture_fixture()
    held = False
    calls: list[str] = []

    @contextmanager
    def lease_context() -> Any:
        nonlocal held
        held = True
        try:
            yield 77, artifacts.lease_receipt_bytes
        finally:
            held = False

    def capture(descriptor: int, raw: bytes) -> snapshot.DeploymentSnapshotArtifacts:
        assert held is True
        assert descriptor == 77
        assert raw == artifacts.lease_receipt_bytes
        calls.append("capture")
        return artifacts

    def publisher(*, root: Path, relative_path: str, payload: bytes) -> Any:
        assert held is True
        assert root == Path("/nonproduction/durable")
        assert payload
        calls.append(relative_path)
        return object()

    result = snapshot._capture_and_publish_deployment_snapshot_for_test(  # noqa: SLF001
        checkout_root="/nonproduction/checkout",
        durable_root="/nonproduction/durable",
        lease_context=lease_context,
        capture=capture,
        publisher=publisher,
    )
    assert held is False
    assert len(result.published_artifacts) == 3
    assert calls == [
        "capture",
        *snapshot.OBSERVATION_RELATIVE_PATHS,
        snapshot.SNAPSHOT_RELATIVE_PATH,
    ]

    def failing_publisher(*, root: Path, relative_path: str, payload: bytes) -> Any:
        assert held is True
        assert root == Path("/nonproduction/durable-2")
        assert payload
        if relative_path == snapshot.SNAPSHOT_RELATIVE_PATH:
            raise RuntimeError("injected publication failure")
        return object()

    with pytest.raises(RuntimeError, match="publication failure"):
        snapshot._capture_and_publish_deployment_snapshot_for_test(  # noqa: SLF001
            checkout_root="/nonproduction/checkout-2",
            durable_root="/nonproduction/durable-2",
            lease_context=lease_context,
            capture=capture,
            publisher=failing_publisher,
        )
    assert held is False


def test_production_entrypoint_uses_exclusive_lease_and_holds_lock_through_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_commit = "b" * 40
    attempt_id = "attempt-001"
    checkout_base = "/mnt/localssd/phase12-production-wrapper-test"
    durable_base = tmp_path / "durable-base"
    monkeypatch.setattr(snapshot, "CHECKOUT_BASE", checkout_base)
    monkeypatch.setattr(snapshot, "DURABLE_BASE", str(durable_base))
    monkeypatch.setattr(snapshot, "CAPTURE_SERVICE_UID", os.geteuid())
    monkeypatch.setattr(snapshot, "CAPTURE_SERVICE_GID", os.getegid())

    filesystem = _FakeSnapshotFilesystem(
        source_commit=source_commit, attempt_id=attempt_id
    )
    runtime = replace(
        filesystem.runtime(),
        lease_metadata=snapshot._default_lease_metadata,  # noqa: SLF001
        lease_bytes=snapshot._default_lease_bytes,  # noqa: SLF001
    )
    monkeypatch.setattr(snapshot, "DeploymentSnapshotRuntime", lambda: runtime)

    durable_root = durable_base / source_commit / "attempts" / attempt_id
    control_root = durable_root / "control"
    control_root.mkdir(parents=True)
    durable_root.chmod(snapshot.CAPTURE_ROOT_MODE)
    control_root.chmod(snapshot.CAPTURE_CONTROL_MODE)
    lease_path = durable_root / snapshot.LEASE_RELATIVE_PATH

    original_os_open = os.open
    original_flock = fcntl.flock
    original_capture = snapshot._capture_deployment_snapshot_core  # noqa: SLF001
    original_lease_assertion = snapshot._assert_exclusive_lease_held  # noqa: SLF001
    lease_open_flags: list[int] = []
    flock_operations: list[int] = []
    lease_assertion_calls: list[int] = []
    events: list[str] = []

    def open_spy(
        path: str | bytes | int,
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        if (
            path == PurePosixPath(snapshot.LEASE_RELATIVE_PATH).name
            and flags & os.O_CREAT
        ):
            lease_open_flags.append(flags)
        if dir_fd is None:
            return original_os_open(path, flags, mode)
        return original_os_open(path, flags, mode, dir_fd=dir_fd)

    def flock_spy(descriptor: int, operation: int) -> None:
        flock_operations.append(operation)
        original_flock(descriptor, operation)

    def assert_lease_is_locked() -> None:
        probe = original_os_open(lease_path, os.O_RDONLY)
        try:
            try:
                original_flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as exc:
                assert exc.errno in {errno.EACCES, errno.EAGAIN}
            else:
                original_flock(probe, fcntl.LOCK_UN)
                raise AssertionError("production lease was not held exclusively")
        finally:
            os.close(probe)

    def capture_spy(**kwargs: Any) -> snapshot.DeploymentSnapshotArtifacts:
        assert_lease_is_locked()
        events.append("capture")
        return original_capture(**kwargs)

    def lease_assertion_spy(descriptor: int, **kwargs: Any) -> None:
        lease_assertion_calls.append(descriptor)
        original_lease_assertion(descriptor, **kwargs)

    def publisher_spy(*, root: Path, relative_path: str, payload: bytes) -> object:
        assert root == durable_root
        assert payload
        assert_lease_is_locked()
        events.append(relative_path)
        return object()

    monkeypatch.setattr(snapshot.os, "open", open_spy)
    monkeypatch.setattr(snapshot.fcntl, "flock", flock_spy)
    monkeypatch.setattr(snapshot, "_capture_deployment_snapshot_core", capture_spy)
    monkeypatch.setattr(snapshot, "_assert_exclusive_lease_held", lease_assertion_spy)
    monkeypatch.setattr(
        snapshot.atomic_publish, "publish_readonly_no_overwrite", publisher_spy
    )

    result = snapshot.capture_and_publish_production_deployment_snapshot(
        source_commit=source_commit,
        attempt_id=attempt_id,
        checkout_root=str(filesystem.checkout),
        durable_root=str(durable_root),
        source_paths_by_role=filesystem.source_paths(),
        asset_roots_by_role={
            role: str(root) for role, root in filesystem.asset_roots.items()
        },
    )

    assert len(result.published_artifacts) == 3
    assert events == [
        "capture",
        *snapshot.OBSERVATION_RELATIVE_PATHS,
        snapshot.SNAPSHOT_RELATIVE_PATH,
    ]
    assert len(lease_open_flags) == 1
    assert lease_open_flags[0] & os.O_CREAT
    assert lease_open_flags[0] & os.O_EXCL
    assert lease_open_flags[0] & os.O_NOFOLLOW
    assert fcntl.LOCK_EX | fcntl.LOCK_NB in flock_operations
    assert len(lease_assertion_calls) == 10
    assert len(set(lease_assertion_calls)) == 1

    probe = original_os_open(lease_path, os.O_RDONLY)
    try:
        original_flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        original_flock(probe, fcntl.LOCK_UN)
    finally:
        os.close(probe)


@pytest.mark.parametrize(
    "failure_kind", ("unlock", "close", "identity-swap", "contender-steal")
)
def test_production_entrypoint_rejects_lost_or_replaced_lease_before_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_kind: str,
) -> None:
    source_commit = "b" * 40
    attempt_id = "attempt-001"
    checkout_base = f"/mnt/localssd/phase12-lease-{failure_kind}"
    durable_base = tmp_path / failure_kind
    monkeypatch.setattr(snapshot, "CHECKOUT_BASE", checkout_base)
    monkeypatch.setattr(snapshot, "DURABLE_BASE", str(durable_base))
    monkeypatch.setattr(snapshot, "CAPTURE_SERVICE_UID", os.geteuid())
    monkeypatch.setattr(snapshot, "CAPTURE_SERVICE_GID", os.getegid())

    filesystem = _FakeSnapshotFilesystem(
        source_commit=source_commit, attempt_id=attempt_id
    )
    lease_read_calls = 0
    contender_descriptor = -1
    replacement_path = tmp_path / f"replacement-{failure_kind}.bin"
    replacement_path.write_bytes(b"replacement lease descriptor")
    replacement_path.chmod(snapshot.LEASE_FILE_MODE)

    def disrupted_lease_bytes(descriptor: int) -> bytes:
        nonlocal contender_descriptor, lease_read_calls
        lease_read_calls += 1
        raw = snapshot._default_lease_bytes(descriptor)  # noqa: SLF001
        if lease_read_calls != 1:
            return raw
        if failure_kind == "unlock":
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        elif failure_kind == "close":
            os.close(descriptor)
        elif failure_kind == "identity-swap":
            replacement_descriptor = os.open(replacement_path, os.O_RDONLY)
            try:
                os.dup2(replacement_descriptor, descriptor)
            finally:
                os.close(replacement_descriptor)
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            contender_descriptor = os.open(
                durable_root / snapshot.LEASE_RELATIVE_PATH,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
            )
            fcntl.flock(
                contender_descriptor,
                fcntl.LOCK_EX | fcntl.LOCK_NB,
            )
        return raw

    runtime = replace(
        filesystem.runtime(),
        lease_metadata=snapshot._default_lease_metadata,  # noqa: SLF001
        lease_bytes=disrupted_lease_bytes,
    )
    monkeypatch.setattr(snapshot, "DeploymentSnapshotRuntime", lambda: runtime)
    published: list[str] = []

    def publisher_spy(*, root: Path, relative_path: str, payload: bytes) -> object:
        assert root
        assert payload
        published.append(relative_path)
        return object()

    monkeypatch.setattr(
        snapshot.atomic_publish, "publish_readonly_no_overwrite", publisher_spy
    )
    durable_root = durable_base / source_commit / "attempts" / attempt_id
    control_root = durable_root / "control"
    control_root.mkdir(parents=True)
    durable_root.chmod(snapshot.CAPTURE_ROOT_MODE)
    control_root.chmod(snapshot.CAPTURE_CONTROL_MODE)

    try:
        with pytest.raises(
            snapshot.DeploymentSnapshotError,
            match="(?:lease (?:descriptor|is no longer held|original descriptor)|held "
            "lease identity)",
        ):
            snapshot.capture_and_publish_production_deployment_snapshot(
                source_commit=source_commit,
                attempt_id=attempt_id,
                checkout_root=str(filesystem.checkout),
                durable_root=str(durable_root),
                source_paths_by_role=filesystem.source_paths(),
                asset_roots_by_role={
                    role: str(root) for role, root in filesystem.asset_roots.items()
                },
            )
    finally:
        if contender_descriptor >= 0:
            fcntl.flock(contender_descriptor, fcntl.LOCK_UN)
            os.close(contender_descriptor)

    assert published == []
    assert (durable_root / snapshot.LEASE_RELATIVE_PATH).exists()


def test_production_lease_is_non_reusable_and_lock_failure_poison_stays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(snapshot, "CAPTURE_SERVICE_UID", os.geteuid())
    monkeypatch.setattr(snapshot, "CAPTURE_SERVICE_GID", os.getegid())
    runtime = _FakeSnapshotFilesystem(
        source_commit="b" * 40, attempt_id="attempt-001"
    ).runtime()
    durable = tmp_path / "durable"
    control = durable / "control"
    control.mkdir(parents=True)
    durable.chmod(snapshot.CAPTURE_ROOT_MODE)
    control.chmod(snapshot.CAPTURE_CONTROL_MODE)

    with snapshot._production_capture_lease(  # noqa: SLF001
        durable_root=PurePosixPath(str(durable)),
        source_commit="b" * 40,
        attempt_id="attempt-001",
        runtime=runtime,
    ) as (descriptor, raw):
        assert descriptor >= 0
        assert raw
    lease_path = control / PurePosixPath(snapshot.LEASE_RELATIVE_PATH).name
    assert lease_path.exists()
    with pytest.raises(snapshot.DeploymentSnapshotError, match="already exists"):
        with snapshot._production_capture_lease(  # noqa: SLF001
            durable_root=PurePosixPath(str(durable)),
            source_commit="b" * 40,
            attempt_id="attempt-001",
            runtime=runtime,
        ):
            raise AssertionError("stale lease was reused")

    poisoned = tmp_path / "poisoned"
    poisoned_control = poisoned / "control"
    poisoned_control.mkdir(parents=True)
    poisoned.chmod(snapshot.CAPTURE_ROOT_MODE)
    poisoned_control.chmod(snapshot.CAPTURE_CONTROL_MODE)

    def fail_lock(_descriptor: int, _operation: int) -> None:
        raise BlockingIOError("busy")

    monkeypatch.setattr(snapshot.fcntl, "flock", fail_lock)
    with pytest.raises(snapshot.DeploymentSnapshotError, match="locked exclusively"):
        with snapshot._production_capture_lease(  # noqa: SLF001
            durable_root=PurePosixPath(str(poisoned)),
            source_commit="b" * 40,
            attempt_id="attempt-001",
            runtime=runtime,
        ):
            raise AssertionError("lock failure yielded")
    assert (
        poisoned_control / PurePosixPath(snapshot.LEASE_RELATIVE_PATH).name
    ).exists()


def test_protocol_plan_reconstructs_full_closure_and_stays_unauthorized() -> None:
    receipt, evidence = _strict_receipt_and_inputs()
    trigger = bridge.revalidate_and_bind_trigger_a_receipt(receipt, **evidence)
    _, artifacts = _capture_fixture()
    snapshot_kwargs = _snapshot_validation_kwargs(artifacts)
    kwargs = {
        "strict_trigger_bridge_bytes": trigger.bridge_receipt_bytes,
        "strict_trigger_receipt_bytes": receipt,
        "strict_trigger_evidence_bytes": evidence,
        "deployment_snapshot_bytes": artifacts.deployment_snapshot_bytes,
        **snapshot_kwargs,
    }

    raw = protocol_plan.seal_structured_protocol_plan_bytes(**kwargs)
    validation = protocol_plan.validate_structured_protocol_plan_bytes(raw, **kwargs)

    assert validation.attempt_id == "attempt-001"
    assert validation.source_commit == trigger.tooling_source_commit == "b" * 40
    assert validation.durable_root.endswith("/attempts/attempt-001")
    assert validation.dgp_generation_authorized is False
    assert validation.model_calls_authorized is False
    assert validation.scorer_calls_authorized is False
    assert validation.operational_authorization is False
    payload = json.loads(raw)
    assert payload["dgp_binding"]["future_dgp_claim_adapter_required"] is True
    assert payload["dgp_binding"]["dgp_generation_authorized"] is False
    assert (
        payload["dgp_binding"][
            "deployment_snapshot_fresh_consumer_revalidation_required"
        ]
        is True
    )
    assert (
        payload["dgp_binding"][
            "deployment_snapshot_fresh_consumer_revalidation_available"
        ]
        is False
    )
    assert payload["raw_input_closure_sha256"] == _sha(
        _canonical(
            {
                key: payload[key]
                for key in (
                    "strict_trigger_bridge",
                    "strict_trigger_receipt",
                    "strict_trigger_raw_evidence",
                    "deployment_snapshot",
                    "deployment_capture_lease",
                    "deployment_observations",
                    "git_index",
                    "source_inventory",
                    "source_files",
                    "asset_inventories",
                    "asset_files",
                    "execution_contract",
                    "structured_preregistration",
                )
            }
        )
    )


def test_protocol_plan_rejects_source_contract_and_embedded_authority_substitution() -> (
    None
):
    receipt, evidence = _strict_receipt_and_inputs()
    trigger = bridge.revalidate_and_bind_trigger_a_receipt(receipt, **evidence)
    _, artifacts = _capture_fixture()
    kwargs = {
        "strict_trigger_bridge_bytes": trigger.bridge_receipt_bytes,
        "strict_trigger_receipt_bytes": receipt,
        "strict_trigger_evidence_bytes": evidence,
        "deployment_snapshot_bytes": artifacts.deployment_snapshot_bytes,
        **_snapshot_validation_kwargs(artifacts),
    }
    raw = protocol_plan.seal_structured_protocol_plan_bytes(**kwargs)

    sources = dict(kwargs["source_file_bytes_by_role"])
    sources["dgp_generator"] += b"forged"
    with pytest.raises(protocol_plan.StructuredProtocolPlanError):
        protocol_plan.validate_structured_protocol_plan_bytes(
            raw, **{**kwargs, "source_file_bytes_by_role": sources}
        )

    with pytest.raises(protocol_plan.StructuredProtocolPlanError):
        protocol_plan.seal_structured_protocol_plan_bytes(
            **{**kwargs, "execution_contract_bytes": b"forged contract"}
        )

    substituted_observations = (
        kwargs["observation_bytes"][0],
        kwargs["observation_bytes"][1] + b"\n",
    )
    with pytest.raises(protocol_plan.StructuredProtocolPlanError):
        protocol_plan.validate_structured_protocol_plan_bytes(
            raw, **{**kwargs, "observation_bytes": substituted_observations}
        )

    forged = json.loads(raw)
    forged["model_calls_authorized"] = True
    unsigned = {
        key: value
        for key, value in forged.items()
        if key != "protocol_plan_seal_sha256"
    }
    forged["protocol_plan_seal_sha256"] = _sha(_canonical(unsigned))
    with pytest.raises(
        protocol_plan.StructuredProtocolPlanError,
        match="complete raw-byte reconstruction",
    ):
        protocol_plan.validate_structured_protocol_plan_bytes(
            _canonical(forged), **kwargs
        )


def test_protocol_plan_rejects_trigger_tooling_snapshot_commit_mismatch() -> None:
    receipt, evidence = _strict_receipt_and_inputs()
    trigger = bridge.revalidate_and_bind_trigger_a_receipt(receipt, **evidence)
    _, artifacts = _capture_fixture(source_commit="c" * 40)
    kwargs = {
        "strict_trigger_bridge_bytes": trigger.bridge_receipt_bytes,
        "strict_trigger_receipt_bytes": receipt,
        "strict_trigger_evidence_bytes": evidence,
        "deployment_snapshot_bytes": artifacts.deployment_snapshot_bytes,
        **_snapshot_validation_kwargs(artifacts),
    }

    with pytest.raises(
        protocol_plan.StructuredProtocolPlanError,
        match="tooling/deployment source commit join",
    ):
        protocol_plan.seal_structured_protocol_plan_bytes(**kwargs)
