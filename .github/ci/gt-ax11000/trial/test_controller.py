#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from controller import (
    BootState,
    CommandResult,
    EvidenceStore,
    FirmwareVersion,
    MINIMUM_FIRMWARE_SIZE,
    Phase,
    TrialConfig,
    TrialController,
    TrialFailure,
    parse_bootstate,
    parse_openssl_sha256,
    persistent_state,
    validate_host,
    verify_artifact,
)


BASELINE = FirmwareVersion("3.0.0.4", "388.11", "0")
CANDIDATE = FirmwareVersion("3.0.0.6", "102.8", "2")


def boot_output(partition: str, state: str) -> str:
    return f"Boot image state: {state}\nBooted Partition: {partition}\n"


class FakeTransport:
    def __init__(self, *, initial_partition: str = "First"):
        self.partition = initial_partition
        self.state = persistent_state(initial_partition)
        self.version = BASELINE
        self.commands: list[tuple[str, ...]] = []
        self.puts: list[tuple[Path, str]] = []
        self.reboots = 0
        self.remote_hash = ""
        self.firmware_check = "1"
        self.hndwr = "99"
        self.write_status = 99
        self.reboot_failure: TrialFailure | None = None
        self.candidate_partition_override: str | None = None
        self.candidate_state_override: str | None = None
        self.model = "GT-AX11000"
        self.commit_marker_present = False

    def run(self, argv, *, stdin=None, timeout):
        del timeout
        command = tuple(argv)
        self.commands.append(command)
        if command == ("/bin/bcm_bootstate",):
            return CommandResult(0, boot_output(self.partition, self.state))
        if command[:2] == ("/bin/nvram", "get"):
            key = command[2]
            values = {
                "firmver": self.version.firmver,
                "buildno": self.version.buildno,
                "extendno": self.version.extendno,
                "firmware_check": self.firmware_check,
                "hndwr": self.hndwr,
                "productid": self.model,
            }
            return CommandResult(0, values[key] + "\n")
        if command == (
            "/bin/busybox", "test", "!", "-e",
            "/data/commit_image_after_reboot",
        ):
            return CommandResult(1 if self.commit_marker_present else 0)
        if command[0:3] == ("/usr/sbin/openssl", "dgst", "-sha256"):
            return CommandResult(0, f"SHA2-256({command[3]})= {self.remote_hash}\n")
        if command[0] == "/sbin/firmware_check":
            return CommandResult(0)
        if command[0] == "/sbin/hnd-write":
            candidate = "Second" if self.partition == "First" else "First"
            self.state = persistent_state(candidate)
            return CommandResult(self.write_status)
        if command[0] == "/bin/bcm_bootstate" and len(command) == 2:
            if command[1] not in (
                "BOOT_SET_PART1_IMAGE", "BOOT_SET_PART2_IMAGE",
                "BOOT_SET_PART1_IMAGE_ONCE", "BOOT_SET_PART2_IMAGE_ONCE",
            ):
                return CommandResult(2)
            self.state = command[1]
            return CommandResult(0)
        if command[0:3] == ("/bin/sh", "-s", "--"):
            return CommandResult(0, "RESULT=PASS\n")
        return CommandResult(127)

    def put_file(self, local, remote, *, timeout):
        del timeout
        self.puts.append((local, remote))
        self.remote_hash = hashlib.sha256(local.read_bytes()).hexdigest()

    def reboot_and_wait(self, *, timeout):
        del timeout
        self.reboots += 1
        if self.reboot_failure is not None:
            raise self.reboot_failure
        if self.reboots == 1:
            target = "Second" if self.partition == "First" else "First"
            self.partition = self.candidate_partition_override or target
            self.state = self.candidate_state_override or persistent_state(
                "First" if target == "Second" else "Second"
            )
            self.version = CANDIDATE
        else:
            self.partition = "First"
            self.state = persistent_state("First")
            self.version = BASELINE


class FakeProbe:
    def __init__(self, failure: TrialFailure | None = None):
        self.failure = failure
        self.calls = 0

    def run(self, transport, **kwargs):
        del transport, kwargs
        self.calls += 1
        if self.failure:
            raise self.failure
        return {"router_health": "PASS", "infosvr": "PASS"}


class FailingEvidence(EvidenceStore):
    def __init__(self, path: Path, phase: Phase, failure: BaseException):
        super().__init__(path)
        self.failure_phase = phase
        self.failure = failure
        self.failed = False

    def event(self, phase, **details):
        if phase is self.failure_phase and not self.failed:
            self.failed = True
            raise self.failure
        super().event(phase, **details)


class TrialTestCase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.image = self.root / "candidate.w"
        self.image.write_bytes(b"F" * MINIMUM_FIRMWARE_SIZE)
        self.digest = hashlib.sha256(self.image.read_bytes()).hexdigest()

    def tearDown(self):
        self.temp.cleanup()

    def config(self, **changes):
        values = dict(
            image=self.image,
            expected_sha256=self.digest,
            expected_baseline_partition="First",
            expected_baseline_version=BASELINE,
            expected_candidate_version=CANDIDATE,
            evidence_dir=self.root / "evidence",
        )
        values.update(changes)
        return TrialConfig(**values)

    def run_failure(self, controller, code):
        with self.assertRaisesRegex(TrialFailure, f"^{code}$"):
            controller.run()
        state = json.loads(controller.evidence.state_path.read_text())
        self.assertEqual(state, {"code": code, "phase": "failed"})

    def test_complete_ordered_trial_and_rollback(self):
        transport = FakeTransport()
        probe = FakeProbe()
        controller = TrialController(self.config(), transport, probe)
        controller.run()
        self.assertEqual(controller.phase, Phase.COMPLETE)
        self.assertEqual(transport.reboots, 2)
        self.assertEqual(probe.calls, 1)
        phases = [
            json.loads(line)["phase"]
            for line in controller.evidence.events_path.read_text().splitlines()
        ]
        self.assertEqual(
            phases,
            [
                "artifact_verified", "baseline_verified", "transferred",
                "remote_hash_verified", "firmware_checked", "image_written",
                "one_shot_armed", "candidate_booted", "health_passed",
                "evidence_collected", "rollback_requested",
                "rollback_verified", "complete",
            ],
        )
        rendered = [" ".join(command) for command in transport.commands]
        for command in rendered:
            self.assertNotIn("promotion", command.lower())
            self.assertNotIn("nvram commit", command.lower())
            self.assertNotIn("touch /data/commit_image_after_reboot", command.lower())
            if "bcm_bootstate BOOT_SET_PART" in command:
                self.assertTrue(command.endswith("_ONCE"))

    def test_wrong_local_hash_never_contacts_router(self):
        transport = FakeTransport()
        config = self.config(expected_sha256="0" * 64)
        controller = TrialController(config, transport, FakeProbe())
        self.run_failure(controller, "LOCAL_SHA256_MISMATCH")
        self.assertEqual(transport.commands, [])
        self.assertEqual(transport.puts, [])

    def test_wrong_remote_hash_stops_before_firmware_check(self):
        transport = FakeTransport()
        original_put = transport.put_file

        def corrupt_put(local, remote, *, timeout):
            original_put(local, remote, timeout=timeout)
            transport.remote_hash = "0" * 64

        transport.put_file = corrupt_put
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "REMOTE_SHA256_MISMATCH")
        self.assertFalse(any(command[0] == "/sbin/firmware_check" for command in transport.commands))

    def test_local_image_replacement_during_transfer_stops_before_check(self):
        transport = FakeTransport()
        original_put = transport.put_file

        def replace_after_put(local, remote, *, timeout):
            original_put(local, remote, timeout=timeout)
            local.write_bytes(b"X" * MINIMUM_FIRMWARE_SIZE)

        transport.put_file = replace_after_put
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "LOCAL_SHA256_MISMATCH")
        self.assertFalse(any(command[0] == "/sbin/firmware_check" for command in transport.commands))

    def test_unsafe_baseline_state_stops_before_transfer(self):
        transport = FakeTransport()
        transport.state = "BOOT_SET_PART2_IMAGE_ONCE"
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "BASELINE_BOOT_STATE_UNSAFE")
        self.assertEqual(transport.puts, [])

    def test_wrong_router_model_stops_before_transfer(self):
        transport = FakeTransport()
        transport.model = "RT-OTHER"
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "ROUTER_MODEL_MISMATCH")
        self.assertEqual(transport.puts, [])

    def test_existing_commit_marker_stops_before_transfer(self):
        transport = FakeTransport()
        transport.commit_marker_present = True
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "COMMIT_MARKER_PRESENT")
        self.assertEqual(transport.puts, [])

    def test_write_must_select_inactive_partition(self):
        transport = FakeTransport()
        original_run = transport.run

        def stale_state(argv, *, stdin=None, timeout):
            result = original_run(argv, stdin=stdin, timeout=timeout)
            if tuple(argv)[0] == "/sbin/hnd-write":
                transport.state = persistent_state("First")
            return result

        transport.run = stale_state
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "INACTIVE_PARTITION_NOT_SELECTED")
        self.assertFalse(any("_ONCE" in item for cmd in transport.commands for item in cmd))
        self.assertEqual(transport.state, persistent_state("First"))

    def test_wrong_candidate_partition_is_detected(self):
        transport = FakeTransport()
        transport.candidate_partition_override = "First"
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "CANDIDATE_PARTITION_MISMATCH")
        self.assertEqual(transport.reboots, 1)

    def test_wrong_consumed_fallback_is_restored_then_rebooted(self):
        transport = FakeTransport()
        transport.candidate_state_override = persistent_state("Second")
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "FALLBACK_STATE_NOT_CONSUMED")
        self.assertEqual(transport.reboots, 2)
        self.assertEqual(transport.partition, "First")
        self.assertIn(
            ("/bin/bcm_bootstate", "BOOT_SET_PART1_IMAGE"),
            transport.commands,
        )

    def test_reboot_timeout_is_terminal_and_never_promotes(self):
        transport = FakeTransport()
        transport.reboot_failure = TrialFailure("REBOOT_TIMEOUT")
        controller = TrialController(self.config(), transport, FakeProbe())
        self.run_failure(controller, "REBOOT_TIMEOUT")
        rendered = "\n".join(" ".join(command) for command in transport.commands)
        self.assertNotIn("nvram commit", rendered.lower())
        self.assertNotIn("touch /data/commit_image_after_reboot", rendered.lower())
        self.assertNotRegex(rendered, r"bcm_bootstate BOOT_SET_PART[12]_IMAGE$")

    def test_health_failure_does_not_report_complete(self):
        transport = FakeTransport()
        controller = TrialController(
            self.config(), transport, FakeProbe(TrialFailure("ROUTER_HEALTH_FAILED"))
        )
        self.run_failure(controller, "ROUTER_HEALTH_FAILED")
        self.assertEqual(transport.reboots, 2)
        self.assertEqual(transport.partition, "First")
        events = [json.loads(line) for line in controller.evidence.events_path.read_text().splitlines()]
        self.assertTrue(any(event["phase"] == "rollback_verified" for event in events))

    def test_unexpected_exception_after_write_restores_baseline_selection(self):
        for phase, failure in [
            (Phase.IMAGE_WRITTEN, OSError("evidence full")),
            (Phase.ONE_SHOT_ARMED, KeyboardInterrupt()),
        ]:
            with self.subTest(phase=phase):
                evidence_path = self.root / f"evidence-{phase.value}"
                transport = FakeTransport()
                evidence = FailingEvidence(evidence_path, phase, failure)
                controller = TrialController(
                    self.config(evidence_dir=evidence_path),
                    transport,
                    FakeProbe(),
                    evidence,
                )
                with self.assertRaisesRegex(TrialFailure, "^INTERNAL_ERROR$"):
                    controller.run()
                self.assertEqual(transport.partition, "First")
                self.assertEqual(transport.state, persistent_state("First"))
                self.assertEqual(transport.reboots, 0)

    def test_evidence_failure_before_rollback_cannot_block_rollback(self):
        evidence_path = self.root / "evidence-rollback-requested"
        transport = FakeTransport()
        evidence = FailingEvidence(
            evidence_path,
            Phase.ROLLBACK_REQUESTED,
            OSError("evidence full"),
        )
        controller = TrialController(
            self.config(evidence_dir=evidence_path),
            transport,
            FakeProbe(),
            evidence,
        )
        with self.assertRaisesRegex(TrialFailure, "^INTERNAL_ERROR$"):
            controller.run()
        self.assertEqual(transport.reboots, 2)
        self.assertEqual(transport.partition, "First")
        self.assertEqual(transport.state, persistent_state("First"))

    def test_existing_evidence_directory_refuses_run(self):
        evidence = self.root / "evidence"
        evidence.mkdir()
        transport = FakeTransport()
        with self.assertRaisesRegex(TrialFailure, "EVIDENCE_DIRECTORY_EXISTS"):
            TrialController(self.config(), transport, FakeProbe()).run()
        self.assertEqual(transport.commands, [])


class ParserTests(unittest.TestCase):
    def test_parse_bootstate_requires_unique_fields(self):
        self.assertEqual(
            parse_bootstate(boot_output("First", "BOOT_SET_PART1_IMAGE")),
            BootState("First", "BOOT_SET_PART1_IMAGE"),
        )
        with self.assertRaisesRegex(TrialFailure, "BOOTSTATE_OUTPUT_INVALID"):
            parse_bootstate("Booted Partition: First\n")

    def test_symlink_artifact_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "real.w"
            image.write_bytes(b"F" * MINIMUM_FIRMWARE_SIZE)
            link = root / "candidate.w"
            link.symlink_to(image)
            digest = hashlib.sha256(image.read_bytes()).hexdigest()
            with self.assertRaisesRegex(TrialFailure, "FIRMWARE_NOT_REGULAR_FILE"):
                verify_artifact(link, digest)

    def test_remote_openssl_digest_is_strict(self):
        digest = "a" * 64
        self.assertEqual(
            parse_openssl_sha256(
                CommandResult(0, f"SHA2-256(/tmp/candidate.w)= {digest}\n")
            ),
            digest,
        )
        with self.assertRaisesRegex(TrialFailure, "REMOTE_SHA256_OUTPUT_INVALID"):
            parse_openssl_sha256(CommandResult(0, f"noise\n{digest}\n"))

    def test_router_endpoint_must_be_ipv4(self):
        self.assertEqual(validate_host("192.168.0.1"), "192.168.0.1")
        for invalid in ("router.local", "::1", "-oProxyCommand=bad"):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(TrialFailure, "SSH_HOST_NOT_IPV4"):
                    validate_host(invalid)


class GuardSourceTests(unittest.TestCase):
    def test_persistent_guard_has_fixed_safe_slot_roles(self):
        source = Path(__file__).with_name("router-persistent-guard.sh").read_text()
        self.assertIn("CANDIDATE_STATE=BOOT_SET_PART1_IMAGE", source)
        self.assertIn("FALLBACK_STATE=BOOT_SET_PART2_IMAGE", source)
        self.assertNotIn("set_boot_roles", source)

    def test_health_gates_reject_kernel_fatal_signal_wording(self):
        trial_root = Path(__file__).parent
        guard = (trial_root / "router-persistent-guard.sh").read_text()
        health = (trial_root.parent / "tests" / "router-health.sh").read_text()
        for source in (guard, health):
            self.assertIn("potentially unexpected fatal signal", source)
            self.assertIn("fatal signal [0-9]+", source)

    def test_persistent_guard_supports_fail_safe_promotion_hold(self):
        source = Path(__file__).with_name("router-persistent-guard.sh").read_text()
        self.assertIn('PROMOTION_HOLD_FILE="$TRIAL_DIR/hold-promotion"', source)
        self.assertIn('[ -e "$PROMOTION_HOLD_FILE" ] && is_candidate_identity', source)
        hold_block = source.split('if [ -e "$PROMOTION_HOLD_FILE" ]', 1)[1]
        hold_block = hold_block.split("if healthy", 1)[0]
        self.assertIn('/bin/bcm_bootstate "$FALLBACK_STATE"', hold_block)
        self.assertNotIn('"$CANDIDATE_STATE"', hold_block)

    def test_persistent_guard_health_check_is_read_only(self):
        source = Path(__file__).with_name("router-persistent-guard.sh").read_text()
        check_block = source.split("\tcheck)", 1)[1].split("\t\t;;", 1)[0]
        self.assertIn("if healthy", check_block)
        self.assertNotIn("bcm_bootstate", check_block)
        self.assertNotIn("set_state", check_block)


if __name__ == "__main__":
    unittest.main()
