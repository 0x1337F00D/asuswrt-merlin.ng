#!/usr/bin/env python3
"""Host-side, fail-closed one-shot firmware trials for the GT-AX11000.

The default CLI mode only verifies the local artifact and prints a plan.  An
actual trial needs three independent opt-ins: ``--execute``, the exact risk
acknowledgement, and a new evidence directory.  There is deliberately no
firmware promotion operation in this module. A persistent setter is reserved
solely for restoring the recorded baseline after a failed pre-boot gate.
"""

from __future__ import annotations

import argparse
import dataclasses
import enum
import hashlib
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path
from typing import Protocol, Sequence


RISK_ACKNOWLEDGEMENT = "GT-AX11000-ONE-SHOT-TRIAL"
MINIMUM_FIRMWARE_SIZE = 16 * 1024 * 1024
REMOTE_IMAGE_PREFIX = "/tmp/codex-trial-"
SAFE_REMOTE_PATH = re.compile(r"^/tmp/codex-trial-[0-9a-f]{16}\.w$")
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]+$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")


class TrialFailure(RuntimeError):
    """A sanitized failure suitable for the evidence log."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class Phase(enum.Enum):
    NEW = "new"
    ARTIFACT_VERIFIED = "artifact_verified"
    BASELINE_VERIFIED = "baseline_verified"
    TRANSFERRED = "transferred"
    REMOTE_HASH_VERIFIED = "remote_hash_verified"
    FIRMWARE_CHECKED = "firmware_checked"
    IMAGE_WRITTEN = "image_written"
    ONE_SHOT_ARMED = "one_shot_armed"
    CANDIDATE_BOOTED = "candidate_booted"
    HEALTH_PASSED = "health_passed"
    EVIDENCE_COLLECTED = "evidence_collected"
    ROLLBACK_REQUESTED = "rollback_requested"
    ROLLBACK_VERIFIED = "rollback_verified"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str = ""
    stderr: str = ""


@dataclasses.dataclass(frozen=True)
class BootState:
    partition: str
    image_state: str


@dataclasses.dataclass(frozen=True)
class FirmwareVersion:
    firmver: str
    buildno: str
    extendno: str


@dataclasses.dataclass(frozen=True)
class TrialConfig:
    image: Path
    expected_sha256: str
    expected_baseline_partition: str
    expected_baseline_version: FirmwareVersion
    expected_candidate_version: FirmwareVersion
    evidence_dir: Path
    expected_model: str = "GT-AX11000"
    command_timeout: float = 30.0
    transfer_timeout: float = 300.0
    reboot_timeout: float = 240.0
    write_timeout: float = 600.0


class RemoteTransport(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None = None,
        timeout: float,
    ) -> CommandResult: ...

    def put_file(self, local: Path, remote: str, *, timeout: float) -> None: ...

    def reboot_and_wait(self, *, timeout: float) -> None: ...


class LiveProbe(Protocol):
    def run(
        self,
        transport: RemoteTransport,
        *,
        candidate_partition: str,
        fallback_state: str,
        version: FirmwareVersion,
        timeout: float,
    ) -> dict[str, str]: ...


class EvidenceStore:
    """Append-only, sanitized evidence with atomic terminal state updates."""

    def __init__(self, path: Path):
        self.path = path
        self.events_path = path / "events.jsonl"
        self.state_path = path / "state.json"

    def create(self) -> None:
        if self.path.exists():
            raise TrialFailure("EVIDENCE_DIRECTORY_EXISTS")
        self.path.mkdir(mode=0o700, parents=True)
        os.chmod(self.path, 0o700)

    def event(self, phase: Phase, **details: str | int | bool) -> None:
        record = {
            "phase": phase.value,
            "monotonic_ns": time.monotonic_ns(),
            "details": details,
        }
        with self.events_path.open("a", encoding="utf-8") as stream:
            os.chmod(self.events_path, 0o600)
            stream.write(json.dumps(record, sort_keys=True) + "\n")
            stream.flush()
            os.fsync(stream.fileno())

    def terminal(self, phase: Phase, code: str) -> None:
        temporary = self.path / ".state.json.tmp"
        payload = {"phase": phase.value, "code": code}
        with temporary.open("w", encoding="utf-8") as stream:
            os.chmod(temporary, 0o600)
            json.dump(payload, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.state_path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def verify_artifact(path: Path, expected_sha256: str) -> tuple[str, int]:
    normalized = expected_sha256.lower()
    if not SHA256.fullmatch(normalized):
        raise TrialFailure("EXPECTED_SHA256_INVALID")
    if path.is_symlink() or not path.is_file():
        raise TrialFailure("FIRMWARE_NOT_REGULAR_FILE")
    if path.suffix != ".w":
        raise TrialFailure("FIRMWARE_EXTENSION_INVALID")
    size = path.stat().st_size
    if size < MINIMUM_FIRMWARE_SIZE:
        raise TrialFailure("FIRMWARE_TOO_SMALL")
    actual = sha256_file(path)
    if actual != normalized:
        raise TrialFailure("LOCAL_SHA256_MISMATCH")
    return actual, size


def parse_bootstate(output: str) -> BootState:
    partitions = re.findall(r"^\s*Booted Partition:\s*(First|Second)\s*$", output, re.M)
    states = re.findall(r"^\s*Boot image state:\s*(BOOT_[A-Z0-9_]+)\s*$", output, re.M)
    if len(partitions) != 1 or len(states) != 1:
        raise TrialFailure("BOOTSTATE_OUTPUT_INVALID")
    return BootState(partitions[0], states[0])


def other_partition(partition: str) -> str:
    if partition == "First":
        return "Second"
    if partition == "Second":
        return "First"
    raise TrialFailure("PARTITION_INVALID")


def persistent_state(partition: str) -> str:
    if partition not in ("First", "Second"):
        raise TrialFailure("PARTITION_INVALID")
    return f"BOOT_SET_PART{1 if partition == 'First' else 2}_IMAGE"


def one_shot_state(partition: str) -> str:
    if partition not in ("First", "Second"):
        raise TrialFailure("PARTITION_INVALID")
    return f"BOOT_SET_PART{1 if partition == 'First' else 2}_IMAGE_ONCE"


def parse_single_value(result: CommandResult, code: str) -> str:
    if result.returncode != 0:
        raise TrialFailure(code)
    value = result.stdout.strip()
    if not value or "\n" in value or "\r" in value:
        raise TrialFailure(code)
    return value


def parse_openssl_sha256(result: CommandResult) -> str:
    if result.returncode != 0:
        raise TrialFailure("REMOTE_SHA256_READ_FAILED")
    match = re.fullmatch(
        r"[A-Za-z0-9-]+\([^\r\n]+\)= ([0-9a-fA-F]{64})\s*",
        result.stdout,
    )
    if match is None:
        raise TrialFailure("REMOTE_SHA256_OUTPUT_INVALID")
    return match.group(1).lower()


class TrialController:
    """Strict one-shot state machine.  It has no promotion operation."""

    def __init__(
        self,
        config: TrialConfig,
        transport: RemoteTransport,
        probe: LiveProbe,
        evidence: EvidenceStore | None = None,
    ):
        self.config = config
        self.transport = transport
        self.probe = probe
        self.evidence = evidence or EvidenceStore(config.evidence_dir)
        self.phase = Phase.NEW
        self._baseline: BootState | None = None
        self._candidate: str | None = None
        self._remote_image: str | None = None
        self._candidate_boot_attempted = False
        self._candidate_reached = False
        self._fallback_verified = False
        self._rollback_verified = False
        self._write_invoked = False

    def _advance(self, phase: Phase, **details: str | int | bool) -> None:
        self.phase = phase
        self.evidence.event(phase, **details)

    def _run(self, argv: Sequence[str], timeout: float | None = None) -> CommandResult:
        return self.transport.run(
            tuple(argv), timeout=timeout or self.config.command_timeout
        )

    def _bootstate(self) -> BootState:
        result = self._run(("/bin/bcm_bootstate",))
        if result.returncode != 0:
            raise TrialFailure("BOOTSTATE_READ_FAILED")
        return parse_bootstate(result.stdout)

    def _version(self) -> FirmwareVersion:
        values = []
        for key in ("firmver", "buildno", "extendno"):
            result = self._run(("/bin/nvram", "get", key))
            values.append(parse_single_value(result, f"NVRAM_{key.upper()}_READ_FAILED"))
        return FirmwareVersion(*values)

    def _model(self) -> str:
        return parse_single_value(
            self._run(("/bin/nvram", "get", "productid")),
            "NVRAM_PRODUCTID_READ_FAILED",
        )

    def _require_no_commit_marker(self) -> None:
        result = self._run(
            (
                "/bin/busybox", "test", "!", "-e",
                "/data/commit_image_after_reboot",
            )
        )
        if result.returncode != 0:
            raise TrialFailure("COMMIT_MARKER_PRESENT")

    @staticmethod
    def _require_version(actual: FirmwareVersion, expected: FirmwareVersion, code: str) -> None:
        if actual != expected:
            raise TrialFailure(code)

    def run(self) -> None:
        self.evidence.create()
        try:
            digest, size = verify_artifact(
                self.config.image, self.config.expected_sha256
            )
            self._advance(Phase.ARTIFACT_VERIFIED, sha256=digest, size=size)

            baseline = self._bootstate()
            if baseline.partition != self.config.expected_baseline_partition:
                raise TrialFailure("BASELINE_PARTITION_MISMATCH")
            if baseline.image_state != persistent_state(baseline.partition):
                raise TrialFailure("BASELINE_BOOT_STATE_UNSAFE")
            if self._model() != self.config.expected_model:
                raise TrialFailure("ROUTER_MODEL_MISMATCH")
            self._require_version(
                self._version(), self.config.expected_baseline_version,
                "BASELINE_VERSION_MISMATCH"
            )
            self._baseline = baseline
            self._candidate = other_partition(baseline.partition)
            self._require_no_commit_marker()
            self._advance(
                Phase.BASELINE_VERIFIED,
                partition=baseline.partition,
                state=baseline.image_state,
            )

            remote = f"{REMOTE_IMAGE_PREFIX}{digest[:16]}.w"
            if not SAFE_REMOTE_PATH.fullmatch(remote):
                raise TrialFailure("REMOTE_PATH_INVALID")
            self._remote_image = remote
            # Recheck immediately before and after the transfer so a build
            # process cannot replace the path between the first gate and scp.
            verify_artifact(self.config.image, digest)
            self.transport.put_file(
                self.config.image, remote, timeout=self.config.transfer_timeout
            )
            verify_artifact(self.config.image, digest)
            self._advance(Phase.TRANSFERRED, remote=remote)

            remote_hash = parse_openssl_sha256(
                self._run(("/usr/sbin/openssl", "dgst", "-sha256", remote))
            )
            if remote_hash != digest:
                raise TrialFailure("REMOTE_SHA256_MISMATCH")
            self._advance(Phase.REMOTE_HASH_VERIFIED, sha256=remote_hash)

            check = self._run(("/sbin/firmware_check", remote), self.config.write_timeout)
            if check.returncode != 0:
                raise TrialFailure("FIRMWARE_CHECK_COMMAND_FAILED")
            firmware_check = parse_single_value(
                self._run(("/bin/nvram", "get", "firmware_check")),
                "FIRMWARE_CHECK_RESULT_MISSING",
            )
            if firmware_check != "1":
                raise TrialFailure("FIRMWARE_CHECK_REJECTED")
            self._advance(Phase.FIRMWARE_CHECKED)

            self._write_invoked = True
            write = self._run(("/sbin/hnd-write", remote), self.config.write_timeout)
            # This platform's successful bca_sys_upgrade path returns 99.  Do
            # not broaden this without a separately tested board profile.
            if write.returncode != 99:
                raise TrialFailure("IMAGE_WRITE_STATUS_INVALID")
            hndwr = parse_single_value(
                self._run(("/bin/nvram", "get", "hndwr")),
                "IMAGE_WRITE_NVRAM_MISSING",
            )
            if hndwr != "99":
                raise TrialFailure("IMAGE_WRITE_NVRAM_INVALID")
            written = self._bootstate()
            if written.partition != baseline.partition:
                raise TrialFailure("ACTIVE_PARTITION_CHANGED_DURING_WRITE")
            if written.image_state != persistent_state(self._candidate):
                raise TrialFailure("INACTIVE_PARTITION_NOT_SELECTED")
            self._require_no_commit_marker()
            self._advance(Phase.IMAGE_WRITTEN, candidate=self._candidate)

            arm = one_shot_state(self._candidate)
            armed_result = self._run(("/bin/bcm_bootstate", arm))
            if armed_result.returncode != 0:
                raise TrialFailure("ONE_SHOT_ARM_FAILED")
            armed = self._bootstate()
            if armed.partition != baseline.partition or armed.image_state != arm:
                raise TrialFailure("ONE_SHOT_ARM_NOT_CONFIRMED")
            self._advance(Phase.ONE_SHOT_ARMED, state=arm)

            self._candidate_boot_attempted = True
            self.transport.reboot_and_wait(timeout=self.config.reboot_timeout)
            candidate_boot = self._bootstate()
            expected_fallback = persistent_state(baseline.partition)
            if candidate_boot.partition != self._candidate:
                raise TrialFailure("CANDIDATE_PARTITION_MISMATCH")
            self._candidate_reached = True
            if candidate_boot.image_state != expected_fallback:
                raise TrialFailure("FALLBACK_STATE_NOT_CONSUMED")
            self._fallback_verified = True
            self._advance(
                Phase.CANDIDATE_BOOTED,
                partition=self._candidate,
                fallback_state=expected_fallback,
            )
            if self._model() != self.config.expected_model:
                raise TrialFailure("CANDIDATE_MODEL_MISMATCH")
            self._require_version(
                self._version(), self.config.expected_candidate_version,
                "CANDIDATE_VERSION_MISMATCH",
            )
            probe_evidence = self.probe.run(
                self.transport,
                candidate_partition=self._candidate,
                fallback_state=expected_fallback,
                version=self.config.expected_candidate_version,
                timeout=self.config.command_timeout,
            )
            self._advance(Phase.HEALTH_PASSED)
            self._advance(Phase.EVIDENCE_COLLECTED, **probe_evidence)

            pre_rollback = self._bootstate()
            if (
                pre_rollback.partition != self._candidate
                or pre_rollback.image_state != expected_fallback
            ):
                raise TrialFailure("PRE_ROLLBACK_STATE_DRIFT")
            self._require_no_commit_marker()
            self._advance(Phase.ROLLBACK_REQUESTED)
            self.transport.reboot_and_wait(timeout=self.config.reboot_timeout)
            rollback = self._bootstate()
            if rollback.partition != baseline.partition:
                raise TrialFailure("ROLLBACK_PARTITION_MISMATCH")
            if rollback.image_state != baseline.image_state:
                raise TrialFailure("ROLLBACK_BOOT_STATE_MISMATCH")
            if self._model() != self.config.expected_model:
                raise TrialFailure("ROLLBACK_MODEL_MISMATCH")
            self._require_version(
                self._version(), self.config.expected_baseline_version,
                "ROLLBACK_VERSION_MISMATCH",
            )
            self._rollback_verified = True
            self._advance(Phase.ROLLBACK_VERIFIED, partition=rollback.partition)
            self._advance(Phase.COMPLETE)
            self.evidence.terminal(Phase.COMPLETE, "PASS")
        except BaseException as failure:
            recovery = self._recover_after_failure()
            self.phase = Phase.FAILED
            failure_code = (
                failure.code if isinstance(failure, TrialFailure) else "INTERNAL_ERROR"
            )
            try:
                self.evidence.event(
                    Phase.FAILED, code=failure_code, recovery=recovery
                )
                self.evidence.terminal(Phase.FAILED, failure_code)
            except OSError:
                # Recovery has already run. Evidence failure must not mask the
                # original gate failure or trigger unsafe follow-up actions.
                pass
            if isinstance(failure, TrialFailure):
                raise
            raise TrialFailure("INTERNAL_ERROR") from failure

    def _recover_after_failure(self) -> str:
        """Restore only the recorded baseline; never select/promote a candidate."""
        if self._baseline is None:
            return "NOT_NEEDED"
        try:
            # Once the candidate was positively identified and reachable, an
            # explicit reboot consumes the already verified fallback state.
            if self._candidate_reached and not self._rollback_verified:
                current = self._bootstate()
                baseline_state = persistent_state(self._baseline.partition)
                if (
                    current.partition == self._candidate
                    and current.image_state != baseline_state
                ):
                    restored = self._run(("/bin/bcm_bootstate", baseline_state))
                    if restored.returncode != 0:
                        return "BASELINE_RESTORE_COMMAND_FAILED"
                    current = self._bootstate()
                    if (
                        current.partition != self._candidate
                        or current.image_state != baseline_state
                    ):
                        return "BASELINE_RESTORE_NOT_CONFIRMED"
                if current.partition == self._candidate:
                    try:
                        self.evidence.event(
                            Phase.ROLLBACK_REQUESTED,
                            reason="candidate_gate_failure",
                        )
                    except BaseException:
                        pass
                    self.transport.reboot_and_wait(timeout=self.config.reboot_timeout)
                    rollback = self._bootstate()
                elif current.partition == self._baseline.partition:
                    rollback = current
                else:
                    return "RECOVERY_PARTITION_INVALID"
                if rollback != self._baseline:
                    return "ROLLBACK_STATE_MISMATCH"
                if self._model() != self.config.expected_model:
                    return "ROLLBACK_MODEL_MISMATCH"
                self._require_version(
                    self._version(), self.config.expected_baseline_version,
                    "ROLLBACK_VERSION_MISMATCH",
                )
                self._rollback_verified = True
                try:
                    self.evidence.event(
                        Phase.ROLLBACK_VERIFIED,
                        partition=rollback.partition,
                        recovery=True,
                    )
                except BaseException:
                    pass
                return "ROLLBACK_VERIFIED"

            # Before the candidate is positively identified, any exception
            # after hnd-write (including during one-shot arming/reboot) must
            # inspect the live state. If the baseline is still running, remove
            # any candidate/one-shot selection. If the candidate is already
            # reachable, select only the baseline and reboot back to it.
            if self._write_invoked and not self._candidate_reached:
                baseline_state = persistent_state(self._baseline.partition)
                current = self._bootstate()
                if current.partition not in (
                    self._baseline.partition,
                    self._candidate,
                ):
                    return "RECOVERY_PARTITION_INVALID"
                if current.image_state != baseline_state:
                    restored = self._run(("/bin/bcm_bootstate", baseline_state))
                    if restored.returncode != 0:
                        return "BASELINE_RESTORE_COMMAND_FAILED"
                    current = self._bootstate()
                    if current.image_state != baseline_state:
                        return "BASELINE_RESTORE_NOT_CONFIRMED"
                if current.partition == self._candidate:
                    self.transport.reboot_and_wait(timeout=self.config.reboot_timeout)
                    current = self._bootstate()
                    if current != self._baseline:
                        return "ROLLBACK_STATE_MISMATCH"
                    if self._model() != self.config.expected_model:
                        return "ROLLBACK_MODEL_MISMATCH"
                    self._require_version(
                        self._version(),
                        self.config.expected_baseline_version,
                        "ROLLBACK_VERSION_MISMATCH",
                    )
                    return "ROLLBACK_VERIFIED"
                if current != self._baseline:
                    return "BASELINE_RESTORE_NOT_CONFIRMED"
                return "BASELINE_SELECTION_RESTORED"
        except BaseException as recovery_failure:
            if isinstance(recovery_failure, TrialFailure):
                return recovery_failure.code
            return "RECOVERY_INTERNAL_ERROR"
        return "UNAVAILABLE_OR_NOT_NEEDED"


class ScriptedLiveProbe:
    """Runs the existing bounded router and read-only infosvr gates."""

    def __init__(self, router_health: Path, infosvr_live: Path, router_host: str):
        self.router_health = router_health
        self.infosvr_live = infosvr_live
        self.router_host = router_host

    def run(
        self,
        transport: RemoteTransport,
        *,
        candidate_partition: str,
        fallback_state: str,
        version: FirmwareVersion,
        timeout: float,
    ) -> dict[str, str]:
        health_script = self.router_health.read_bytes()
        health = transport.run(
            (
                "/bin/sh", "-s", "--", candidate_partition, fallback_state,
                version.firmver, version.buildno, version.extendno,
            ),
            stdin=health_script,
            timeout=max(timeout, 90.0),
        )
        if health.returncode != 0 or "RESULT=PASS" not in health.stdout.splitlines():
            raise TrialFailure("ROUTER_HEALTH_FAILED")
        try:
            infosvr = subprocess.run(
                (sys.executable, str(self.infosvr_live), self.router_host),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=max(timeout, 20.0),
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise TrialFailure("INFOSVR_TIMEOUT") from error
        if infosvr.returncode != 0 or "RESULT=PASS" not in infosvr.stdout.splitlines():
            raise TrialFailure("INFOSVR_FAILED")
        return {"router_health": "PASS", "infosvr": "PASS"}


class OpenSSHTransport:
    """OpenSSH adapter using the user's existing agent/config, never passwords."""

    def __init__(self, host: str, user: str, port: int = 22):
        validate_host(host)
        if not SAFE_ID.fullmatch(user):
            raise TrialFailure("SSH_USER_INVALID")
        if not 1 <= port <= 65535:
            raise TrialFailure("SSH_PORT_INVALID")
        self.host = host
        self.user = user
        self.port = port
        self.target = f"{user}@{host}"

    def _ssh_prefix(self, connect_timeout: int = 10) -> tuple[str, ...]:
        return (
            "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
            "-o", f"ConnectTimeout={connect_timeout}", "-p", str(self.port),
            "--", self.target,
        )

    def run(
        self,
        argv: Sequence[str],
        *,
        stdin: bytes | None = None,
        timeout: float,
    ) -> CommandResult:
        if not argv or any("\x00" in item or "\n" in item for item in argv):
            raise TrialFailure("REMOTE_ARGUMENT_INVALID")
        remote_command = shlex.join(tuple(argv))
        try:
            completed = subprocess.run(
                self._ssh_prefix() + (remote_command,),
                input=stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise TrialFailure("REMOTE_COMMAND_TIMEOUT") from error
        return CommandResult(
            completed.returncode,
            completed.stdout.decode("utf-8", "replace"),
            completed.stderr.decode("utf-8", "replace"),
        )

    def put_file(self, local: Path, remote: str, *, timeout: float) -> None:
        if not SAFE_REMOTE_PATH.fullmatch(remote):
            raise TrialFailure("REMOTE_PATH_INVALID")
        command = (
            "scp", "-q", "-o", "BatchMode=yes", "-o",
            "StrictHostKeyChecking=yes", "-P", str(self.port), "--",
            str(local), f"{self.target}:{remote}",
        )
        try:
            completed = subprocess.run(
                command, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as error:
            raise TrialFailure("TRANSFER_TIMEOUT") from error
        if completed.returncode != 0:
            raise TrialFailure("TRANSFER_FAILED")

    def _ready(self) -> bool:
        try:
            return self.run(("/bin/true",), timeout=5.0).returncode == 0
        except TrialFailure:
            return False

    def reboot_and_wait(self, *, timeout: float) -> None:
        if not self._ready():
            raise TrialFailure("ROUTER_NOT_READY_BEFORE_REBOOT")
        # A disconnect (255) after a verified session is expected here.
        try:
            reboot = self.run(("/sbin/reboot",), timeout=10.0)
            if reboot.returncode not in (0, 255):
                raise TrialFailure("REBOOT_REQUEST_FAILED")
        except TrialFailure as failure:
            # Some SSH daemons do not close their side before the client-side
            # command timeout. The mandatory down-then-up observation below
            # still proves whether the preflight-authenticated request worked.
            if failure.code != "REMOTE_COMMAND_TIMEOUT":
                raise
        deadline = time.monotonic() + timeout
        observed_down = False
        while time.monotonic() < deadline:
            ready = self._ready()
            observed_down = observed_down or not ready
            if observed_down and ready:
                return
            time.sleep(2.0)
        raise TrialFailure("REBOOT_TIMEOUT")


def validate_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        raise TrialFailure("SSH_HOST_NOT_IPV4") from None
    if address.version != 4:
        raise TrialFailure("SSH_HOST_NOT_IPV4")
    return value


def version_arg(value: str) -> FirmwareVersion:
    fields = value.split("/")
    if len(fields) != 3 or any(not SAFE_ID.fullmatch(field) for field in fields):
        raise argparse.ArgumentTypeError("version must be firmver/buildno/extendno")
    return FirmwareVersion(*fields)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True, type=Path)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--baseline-partition", choices=("First", "Second"), required=True)
    parser.add_argument("--baseline-version", type=version_arg, required=True)
    parser.add_argument("--candidate-version", type=version_arg, required=True)
    parser.add_argument("--host", default="192.168.0.1")
    parser.add_argument("--user", default="admin")
    parser.add_argument("--port", type=int, default=22)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--acknowledge-risk")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        digest, size = verify_artifact(args.image, args.expected_sha256)
        plan = {
            "mode": "execute" if args.execute else "dry-run",
            "image_sha256": digest,
            "image_size": size,
            "baseline_partition": args.baseline_partition,
            "candidate_partition": other_partition(args.baseline_partition),
            "promotion_supported": False,
        }
        if not args.execute:
            print(json.dumps(plan, sort_keys=True))
            return 0
        if args.acknowledge_risk != RISK_ACKNOWLEDGEMENT:
            raise TrialFailure("RISK_ACKNOWLEDGEMENT_REQUIRED")
        if args.evidence_dir is None:
            raise TrialFailure("EVIDENCE_DIRECTORY_REQUIRED")
        root = Path(__file__).resolve().parents[1]
        config = TrialConfig(
            image=args.image,
            expected_sha256=digest,
            expected_baseline_partition=args.baseline_partition,
            expected_baseline_version=args.baseline_version,
            expected_candidate_version=args.candidate_version,
            evidence_dir=args.evidence_dir,
        )
        transport = OpenSSHTransport(args.host, args.user, args.port)
        probe = ScriptedLiveProbe(
            root / "tests/router-health.sh",
            root / "tests/infosvr-live.py",
            validate_host(args.host),
        )
        TrialController(config, transport, probe).run()
        print(json.dumps({**plan, "result": "PASS"}, sort_keys=True))
        return 0
    except TrialFailure as failure:
        print(f"RESULT=FAIL\nFAILED_CHECK={failure.code}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
