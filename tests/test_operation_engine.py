import unittest
import threading

from operation_engine import (
    DependencyCycleError,
    DuplicateOperationError,
    FileState,
    FileStateError,
    FileStateManager,
    InvalidOperationTransition,
    Operation,
    OperationBlocked,
    OperationCancelled,
    OperationManager,
    OperationSnapshot,
    OperationState,
    StaleFileState,
    StaleSimulationPlan,
    advise_settings,
)


class TestOperationEngine(unittest.TestCase):
    def test_operation_progress_and_completion(self):
        manager = OperationManager()
        operation = manager.create("Encrypt", current_item="movie.mp4", total_items=2, total_bytes=200)
        operation.start()
        first = operation.update(bytes_processed=100, total_bytes=200)
        self.assertEqual(first.percent, 50)
        operation.update(current_item="image.png", completed_items=1, bytes_processed=150)
        completed = operation.complete()
        self.assertEqual(completed.state, OperationState.COMPLETED)
        self.assertIsNotNone(completed.completed_at)
        self.assertEqual(completed.percent, 75)

    def test_cancel_is_cooperative_and_acknowledged_at_checkpoint(self):
        operation = OperationManager().create("Archive")
        operation.start()
        operation.request_cancel()
        with self.assertRaises(OperationCancelled):
            operation.checkpoint()
        canceled = operation.canceled()
        self.assertEqual(canceled.state, OperationState.CANCELED)
        self.assertTrue(canceled.cancellation_acknowledged)

    def test_queued_cancel_is_terminal_without_starting(self):
        operation = OperationManager().create("Queued")
        canceled = operation.request_cancel()
        self.assertEqual(canceled.state, OperationState.CANCELED)
        self.assertTrue(canceled.cancellation_acknowledged)
        with self.assertRaises(InvalidOperationTransition):
            operation.start()

    def test_invalid_transitions_and_progress_regressions_are_rejected(self):
        operation = OperationManager().create("Invalid")
        with self.assertRaises(InvalidOperationTransition):
            operation.complete()
        operation.start()
        operation.update(bytes_processed=10, total_bytes=20)
        with self.assertRaises(ValueError):
            operation.update(bytes_processed=9)
        operation.fail("disk error", recovery_state="journal_pending")
        with self.assertRaises(InvalidOperationTransition):
            operation.complete()

    def test_recovery_transitions_are_explicit(self):
        operation = OperationManager().create("Recoverable", resumable=True)
        operation.start()
        operation.fail("interrupted", recovery_state="journal_pending")
        operation.recovering()
        result = operation.complete()
        self.assertTrue(result.resumable)
        self.assertEqual(result.state, OperationState.COMPLETED)

    def test_observers_receive_snapshots_and_can_unsubscribe(self):
        manager = OperationManager()
        seen: list[OperationSnapshot] = []
        unsubscribe = manager.subscribe(seen.append)
        operation = manager.create("Observed")
        operation.start()
        unsubscribe()
        operation.complete()
        self.assertEqual([item.state for item in seen],
                         [OperationState.QUEUED, OperationState.RUNNING])

    def test_observer_failures_are_diagnosable_without_breaking_operations(self):
        manager = OperationManager()
        def fail_observer(snapshot: OperationSnapshot) -> None:
            raise RuntimeError(snapshot.state.value)

        manager.subscribe(fail_observer)
        operation = manager.create("Observed")
        operation.start()
        self.assertEqual(manager.observer_errors, ("RuntimeError", "RuntimeError"))
        self.assertEqual(operation.snapshot.state, OperationState.RUNNING)

    def test_operation_manager_is_thread_safe_and_history_is_bounded(self):
        manager = OperationManager(history_limit=2)
        first = manager.create("one")
        second = manager.create("two")
        third = manager.create("three")
        first.start(); first.complete()
        second.start(); second.complete()
        third.start(); third.complete()
        self.assertEqual([item.name for item in manager.snapshots()], ["three", "two"])
        with self.assertRaises(KeyError):
            manager.get(first.operation_id)

    def test_cancel_request_does_not_allow_progress_to_move_backwards(self):
        operation = OperationManager().create("Progress")
        operation.start()
        operation.update(total_items=3, completed_items=1)
        operation.request_cancel()
        with self.assertRaises(ValueError):
            operation.update(completed_items=0)

    def test_dependency_waits_then_becomes_startable_after_predecessor_completes(self):
        manager = OperationManager()
        encrypt = manager.create("Encrypt")
        decrypt = manager.create("Decrypt", depends_on=(encrypt,))

        with self.assertRaises(OperationBlocked):
            decrypt.start()
        self.assertEqual(decrypt.snapshot.state, OperationState.WAITING)
        self.assertEqual(decrypt.snapshot.waiting_reason, "Waiting for Encrypt to complete.")
        self.assertEqual(
            tuple(item.operation_id for item in manager.ready_operations()),
            (encrypt.operation_id,),
        )

        encrypt.start()
        encrypt.complete()
        self.assertEqual(decrypt.snapshot.state, OperationState.QUEUED)
        self.assertIsNone(decrypt.snapshot.waiting_reason)
        self.assertEqual(
            tuple(item.operation_id for item in manager.ready_operations()),
            (decrypt.operation_id,),
        )
        decrypt.start()
        self.assertEqual(decrypt.snapshot.state, OperationState.RUNNING)

    def test_direct_running_transition_uses_dependency_gates(self):
        manager = OperationManager()
        predecessor = manager.create("Prepare")
        dependent = manager.create("Use prepared data", depends_on=(predecessor,))
        with self.assertRaises(OperationBlocked):
            manager.transition(dependent.operation_id, OperationState.RUNNING)
        self.assertEqual(dependent.snapshot.state, OperationState.WAITING)

    def test_waiting_operation_dispatches_when_dependencies_complete(self):
        manager = OperationManager()
        predecessor = manager.create("Prepare")
        dependent = manager.create("Continue", depends_on=(predecessor,))
        ready_states: list[OperationState] = []
        dependent.on_ready(lambda: ready_states.append(dependent.start().state))

        with self.assertRaises(OperationBlocked):
            dependent.start()
        predecessor.start()
        predecessor.complete()

        self.assertEqual(ready_states, [OperationState.RUNNING])
        self.assertEqual(dependent.snapshot.state, OperationState.RUNNING)

    def test_failed_and_cancelled_dependencies_stop_waiting_dependents(self):
        manager = OperationManager()
        failed = manager.create("Failing operation")
        dependent = manager.create("Dependent", depends_on=(failed,))
        with self.assertRaises(OperationBlocked):
            dependent.start()
        failed.start()
        failed.fail("verification failed")
        self.assertEqual(dependent.snapshot.state, OperationState.FAILED)
        self.assertIn("Failing operation failed", dependent.snapshot.error or "")

        canceled = manager.create("Canceled operation")
        canceled_dependent = manager.create("Canceled dependent", depends_on=(canceled,))
        with self.assertRaises(OperationBlocked):
            canceled_dependent.start()
        canceled.request_cancel()
        self.assertEqual(canceled_dependent.snapshot.state, OperationState.CANCELED)

    def test_dependency_cycles_are_rejected(self):
        manager = OperationManager()
        first = manager.create("First")
        second = manager.create("Second", depends_on=(first,))
        with self.assertRaises(DependencyCycleError):
            manager.add_dependency(first.operation_id, second)
        with self.assertRaises(DependencyCycleError):
            manager.add_dependency(first.operation_id, first)

    def test_resource_conflicts_wait_and_resume_without_blocking_independent_work(self):
        manager = OperationManager()
        owner = manager.create("Rename", resource_keys=("item:abc",))
        conflicting = manager.create("Delete", resource_keys=("ITEM:ABC",))
        independent = manager.create("Encrypt", resource_keys=("item:def",))

        owner.start()
        with self.assertRaises(OperationBlocked):
            conflicting.start()
        self.assertEqual(conflicting.snapshot.state, OperationState.WAITING)
        self.assertIn("Rename", conflicting.snapshot.waiting_reason or "")
        independent.start()
        self.assertEqual(independent.snapshot.state, OperationState.RUNNING)

        owner.complete()
        self.assertEqual(conflicting.snapshot.state, OperationState.QUEUED)
        conflicting.start()
        self.assertEqual(conflicting.snapshot.state, OperationState.RUNNING)

    def test_resource_reservations_release_on_failure_and_cancellation(self):
        manager = OperationManager()
        failed_owner = manager.create("Failure", resource_keys=("vault:item",))
        waiting = manager.create("Waiting", resource_keys=("vault:item",))
        failed_owner.start()
        with self.assertRaises(OperationBlocked):
            waiting.start()
        failed_owner.fail("operation failed")
        self.assertEqual(waiting.snapshot.state, OperationState.QUEUED)
        waiting.start()
        waiting.request_cancel()
        waiting.canceled()
        retry = manager.create("Retry", resource_keys=("vault:item",))
        retry.start()
        self.assertEqual(retry.snapshot.state, OperationState.RUNNING)

    def test_identical_active_fingerprints_are_rejected_but_changed_or_completed_requests_are_allowed(self):
        manager = OperationManager()
        original = manager.create("Delete", fingerprint_inputs={"item_id": "abc", "version": 3})
        with self.assertRaises(DuplicateOperationError):
            manager.create("Delete", fingerprint_inputs={"version": 3, "item_id": "abc"})
        changed = manager.create("Delete", fingerprint_inputs={"item_id": "abc", "version": 4})
        self.assertNotEqual(original.snapshot.fingerprint, changed.snapshot.fingerprint)
        original.start()
        original.complete()
        repeated = manager.create("Delete", fingerprint_inputs={"item_id": "abc", "version": 3})
        self.assertEqual(repeated.snapshot.state, OperationState.QUEUED)

    def test_fingerprints_do_not_accept_sensitive_fields_or_store_input_values(self):
        manager = OperationManager()
        with self.assertRaises(ValueError):
            manager.create("Unlock", fingerprint_inputs={"password": "do-not-store"})
        operation = manager.create("Rename", fingerprint_inputs={"item_id": "private-name.pdf"})
        self.assertNotIn("private-name.pdf", operation.snapshot.fingerprint or "")
        self.assertFalse(hasattr(operation.snapshot, "fingerprint_inputs"))

    def test_operations_with_no_shared_resources_can_run_concurrently(self):
        manager = OperationManager()
        first = manager.create("First", resource_keys=("item:a",))
        second = manager.create("Second", resource_keys=("item:b",))
        first.start()
        second.start()
        self.assertEqual(first.snapshot.state, OperationState.RUNNING)
        self.assertEqual(second.snapshot.state, OperationState.RUNNING)

    def test_competing_resource_claims_are_atomic_across_threads(self):
        manager = OperationManager()
        operations = (
            manager.create("First", resource_keys=("shared-item",)),
            manager.create("Second", resource_keys=("shared-item",)),
        )
        barrier = threading.Barrier(3)

        def start_when_released(operation: Operation) -> None:
            barrier.wait()
            try:
                operation.start()
            except OperationBlocked:
                pass

        threads = [threading.Thread(target=start_when_released, args=(operation,)) for operation in operations]
        for thread in threads:
            thread.start()
        barrier.wait()
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())

        states = [operation.snapshot.state for operation in operations]
        self.assertEqual(states.count(OperationState.RUNNING), 1)
        self.assertEqual(states.count(OperationState.WAITING), 1)

    def test_file_state_transitions_require_verified_stages_and_owner(self):
        operations = OperationManager()
        states = FileStateManager(operations)
        item = "private-vault-id"
        initial = states.register(item)
        operation = operations.create("Seal", resource_keys=(f"file:{item}",))
        operation.start()
        processing = states.transition(
            item, FileState.PROCESSING, expected_revision=initial.revision,
            operation_id=operation.operation_id)
        with self.assertRaises(FileStateError):
            states.transition(
                item, FileState.AVAILABLE, expected_revision=processing.revision,
                operation_id=operation.operation_id)
        pending = states.transition(
            item, FileState.PENDING_VERIFICATION, expected_revision=processing.revision,
            operation_id=operation.operation_id)
        available = states.transition(
            item, FileState.AVAILABLE, expected_revision=pending.revision,
            operation_id=operation.operation_id, verified=True)
        self.assertEqual(available.state, FileState.AVAILABLE)
        self.assertNotIn(item, repr(available))

    def test_file_state_rejects_stale_ui_revision_and_invalid_transitions(self):
        operations = OperationManager()
        states = FileStateManager(operations)
        initial = states.register("item")
        locked = states.transition(
            "item", FileState.LOCKED, expected_revision=initial.revision)
        with self.assertRaises(StaleFileState):
            states.require_available("item", initial.revision)
        with self.assertRaises(FileStateError):
            states.transition(
                "item", FileState.PROCESSING, expected_revision=locked.revision)
        unlocked = states.transition(
            "item", FileState.AVAILABLE, expected_revision=locked.revision, verified=True)
        states.require_available("item", unlocked.revision)

    def test_file_state_recovery_requires_running_recovery_operation_and_verification(self):
        operations = OperationManager()
        states = FileStateManager(operations)
        item = "interrupted-item"
        registered = states.register(item)
        interrupted = operations.create("Seal")
        interrupted.start()
        processing = states.transition(
            item, FileState.PROCESSING, expected_revision=registered.revision,
            operation_id=interrupted.operation_id)
        recovery_required = states.transition(
            item, FileState.RECOVERY_REQUIRED, expected_revision=processing.revision,
            operation_id=interrupted.operation_id)
        interrupted.fail("interrupted")

        recovery = operations.create("Recover")
        recovery.start()
        with self.assertRaises(FileStateError):
            states.transition(
                item, FileState.PROCESSING, expected_revision=recovery_required.revision,
                operation_id=recovery.operation_id)
        recovering = states.transition(
            item, FileState.PROCESSING, expected_revision=recovery_required.revision,
            operation_id=recovery.operation_id, recovery=True)
        pending = states.transition(
            item, FileState.PENDING_VERIFICATION, expected_revision=recovering.revision,
            operation_id=recovery.operation_id)
        restored = states.transition(
            item, FileState.AVAILABLE, expected_revision=pending.revision,
            operation_id=recovery.operation_id, recovery=True, verified=True)
        self.assertEqual(restored.state, FileState.AVAILABLE)

    def test_file_state_revision_claim_is_atomic_across_threads(self):
        operations = OperationManager()
        states = FileStateManager(operations)
        initial = states.register("shared")
        contenders = [operations.create(f"Claim {index}") for index in range(8)]
        for operation in contenders:
            operation.start()
        barrier = threading.Barrier(len(contenders))
        successful: list[str] = []
        failures: list[Exception] = []

        def claim(operation: Operation) -> None:
            barrier.wait()
            try:
                states.transition(
                    "shared", FileState.PROCESSING, expected_revision=initial.revision,
                    operation_id=operation.operation_id)
                successful.append(operation.operation_id)
            except Exception as exc:
                failures.append(exc)

        threads = [threading.Thread(target=claim, args=(operation,)) for operation in contenders]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(len(successful), 1)
        self.assertEqual(len(failures), len(contenders) - 1)
        self.assertTrue(all(isinstance(error, StaleFileState) for error in failures))

    def test_simulation_reuses_dependency_and_resource_gates_without_mutation(self):
        manager = OperationManager()
        owner = manager.create("Busy", resource_keys=("file:private",))
        owner.start()
        before = (manager.snapshots(), manager.reports)
        plan = manager.simulate(
            "seal_file",
            affected_items=("private-name",),
            resource_keys=("file:private",),
            expected_changes=("sealed_object",),
            verification_requirements=("authenticated_readback",),
            recovery_implications=("retain_journal",),
        )
        self.assertFalse(plan.valid)
        self.assertEqual(plan.conflicts, ("resource_in_use",))
        self.assertTrue(plan.predicted_only)
        self.assertNotIn("private-name", repr(plan))
        self.assertEqual((manager.snapshots(), manager.reports), before)

    def test_simulation_handles_destructive_invalid_and_recovery_sensitive_requests(self):
        manager = OperationManager()
        destructive = manager.simulate(
            "burn_items", affected_items=("item-1",), destructive=True,
            verification_requirements=("absence_check",),
            recovery_implications=("recovery_may_be_impossible",))
        self.assertTrue(destructive.valid)
        self.assertTrue(destructive.destructive)
        self.assertIn("recovery_may_be_impossible", destructive.recovery_implications)
        with self.assertRaises(ValueError):
            manager.simulate("seal /private/file")

    def test_simulation_rejects_a_changed_file_revision(self):
        manager = OperationManager()
        planned = manager.simulate(
            "view_file", affected_items=("item",), resource_keys=("file:item",),
            state_revisions={"item": 4})
        current = manager.simulate(
            "view_file", affected_items=("item",), resource_keys=("file:item",),
            state_revisions={"item": 5})
        with self.assertRaises(StaleSimulationPlan):
            manager.require_current_simulation(planned, current)
        manager.require_current_simulation(
            planned,
            manager.simulate(
                "view_file", affected_items=("item",), resource_keys=("file:item",),
                state_revisions={"item": 4}),
        )

    def test_required_terminal_report_records_missing_worker_result(self):
        manager = OperationManager()
        operation = manager.create("Required report", require_report=True)
        operation.start()
        operation.fail("worker_terminated")
        report = manager.report_for(operation.operation_id)
        self.assertIsNotNone(report)
        assert report is not None
        self.assertEqual(report.status, OperationState.FAILED.value)
        self.assertTrue(report.reporting_incomplete)
        self.assertTrue(report.manual_review_required)
        self.assertEqual(report.failure_codes, ("result_report_missing",))

    def test_settings_advisor_explains_dependencies_and_preserves_security_conflicts(self):
        advice = advise_settings({"ghost": True, "vmode": "file", "log": True})
        self.assertFalse(advice.valid)
        self.assertEqual(dict(advice.required_changes), {"log": False, "vmode": "mem"})
        self.assertTrue(all(issue.security_sensitive for issue in advice.issues))
        self.assertTrue(advise_settings(
            {"ghost": True, "vmode": "mem", "log": False}).valid)
        self.assertFalse(advise_settings({"ghost": "yes"}).valid)

    def test_operation_result_report_is_sanitized_and_bounded(self):
        manager = OperationManager(history_limit=2)
        operation = manager.create("Completed")
        operation.start()
        operation.complete()
        report = manager.record_result(
            operation.operation_id, "seal_file",
            affected_items=("private-name",), succeeded_items=("private-name",),
            verified_items=("private-name",), committed_items=("private-name",))
        self.assertEqual(report.status, "completed")
        self.assertEqual(report.succeeded_count, 1)
        self.assertNotIn("private-name", repr(report))
        with self.assertRaises(ValueError):
            manager.record_result(
                operation.operation_id, "seal_file", affected_items=("one",),
                failed_items=("other",))

    def test_operation_reports_cover_empty_partial_cancel_and_recovery_outcomes(self):
        manager = OperationManager()
        cases = (
            ("empty", (), (), (), (), (), False, False),
            ("partial", ("a", "b"), ("a",), ("b",), (), (), False, False),
            ("cancelled", ("a", "b"), ("a",), (), ("b",), (), False, False),
            ("recovery", ("a",), (), ("a",), (), ("a",), True, True),
        )
        for name, affected, succeeded, failed, cancelled, recovery, expect_recovery, expect_review in cases:
            with self.subTest(name=name):
                operation = manager.create(name)
                operation.start()
                if name == "cancelled":
                    operation.request_cancel()
                    operation.canceled()
                else:
                    operation.fail("operation did not complete")
                report = manager.record_result(
                    operation.operation_id, "test_operation",
                    affected_items=affected, succeeded_items=succeeded,
                    failed_items=failed, cancelled_items=cancelled,
                    verified_items=succeeded, committed_items=succeeded,
                    recovery_items=recovery,
                    manual_review_items=recovery)
                self.assertEqual(report.recovery_required, expect_recovery)
                self.assertEqual(report.manual_review_required, expect_review)
                self.assertEqual(report.affected_count, len(affected))
                self.assertEqual(report.failed_count, len(failed))
                self.assertEqual(report.cancelled_count, len(cancelled))
                self.assertEqual(report.verified_count, len(succeeded))
                if name == "cancelled":
                    self.assertEqual(report.status, OperationState.CANCELED.value)
        empty_report = manager.reports[-1]
        self.assertEqual(empty_report.affected_count, 0)

    def test_operation_reports_are_safe_under_concurrent_updates(self):
        manager = OperationManager(history_limit=16)
        operations = [manager.create(f"Concurrent {index}") for index in range(8)]
        for operation in operations:
            operation.start()
            operation.complete()
        barrier = threading.Barrier(len(operations))
        errors: list[Exception] = []

        def record(operation: Operation, index: int) -> None:
            barrier.wait()
            try:
                operation.report_result(
                    "concurrent_test", affected_items=(f"item-{index}",),
                    succeeded_items=(f"item-{index}",), verified_items=(f"item-{index}",))
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=record, args=(operation, index))
            for index, operation in enumerate(operations)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=2)
            self.assertFalse(thread.is_alive())
        self.assertEqual(errors, [])
        self.assertEqual(len(manager.reports), len(operations))


if __name__ == "__main__":
    unittest.main()
