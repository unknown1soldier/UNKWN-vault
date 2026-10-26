"""UI-independent lifecycle and progress tracking for long-running operations."""

from __future__ import annotations

from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, replace
from enum import Enum
import hashlib
import json
import re
import threading
import time
import unicodedata
import uuid
from typing import Callable, Literal, cast


class OperationState(str, Enum):
    QUEUED = "queued"
    WAITING = "waiting"
    RUNNING = "running"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELING = "canceling"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELED = "canceled"
    RECOVERING = "recovering"
    RECOVERY_FAILED = "recovery_failed"


TERMINAL_STATES = {
    OperationState.COMPLETED,
    OperationState.FAILED,
    OperationState.CANCELED,
    OperationState.RECOVERY_FAILED,
}

_TRANSITIONS: dict[OperationState, set[OperationState]] = {
    OperationState.QUEUED: {
        OperationState.WAITING,
        OperationState.RUNNING,
        OperationState.CANCEL_REQUESTED,
        OperationState.CANCELED,
        OperationState.FAILED,
    },
    OperationState.WAITING: {
        OperationState.QUEUED,
        OperationState.RUNNING,
        OperationState.CANCEL_REQUESTED,
        OperationState.CANCELED,
        OperationState.FAILED,
    },
    OperationState.RUNNING: {
        OperationState.CANCEL_REQUESTED,
        OperationState.COMPLETED,
        OperationState.FAILED,
        OperationState.RECOVERING,
    },
    OperationState.CANCEL_REQUESTED: {
        OperationState.CANCELING,
        OperationState.COMPLETED,
        OperationState.FAILED,
        OperationState.RECOVERY_FAILED,
    },
    OperationState.CANCELING: {
        OperationState.CANCELED,
        OperationState.FAILED,
        OperationState.RECOVERING,
    },
    OperationState.RECOVERING: {
        OperationState.COMPLETED,
        OperationState.FAILED,
        OperationState.RECOVERY_FAILED,
    },
    OperationState.FAILED: {OperationState.RECOVERING},
    OperationState.RECOVERY_FAILED: {OperationState.RECOVERING},
    OperationState.COMPLETED: set(),
    OperationState.CANCELED: set(),
}


class InvalidOperationTransition(ValueError):
    """Raised when an operation attempts an unsupported lifecycle transition."""


class OperationBlocked(InvalidOperationTransition):
    """Raised when dependencies or resource conflicts prevent an operation from starting."""


class DependencyCycleError(ValueError):
    """Raised when an operation dependency would create a cycle."""


class DuplicateOperationError(ValueError):
    """Raised when an identical operation request is already active."""


class OperationCancelled(Exception):
    """Cooperative cancellation acknowledged at a safe operation checkpoint."""


class FileState(str, Enum):
    AVAILABLE = "available"
    PROCESSING = "processing"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"
    RECOVERY_REQUIRED = "recovery_required"
    UNAVAILABLE = "unavailable"


class FileStateError(ValueError):
    """Raised when an item action conflicts with its authoritative lifecycle state."""


class StaleFileState(FileStateError):
    """Raised when an action was prepared against an obsolete item revision."""


class StaleSimulationPlan(ValueError):
    """Raised when a no-write plan no longer describes the current operation state."""


@dataclass(frozen=True)
class FileStateSnapshot:
    item_token: str
    state: FileState
    revision: int
    operation_token: str | None


@dataclass(frozen=True)
class SimulationPlan:
    simulation_id: str
    requested: str
    valid: bool
    destructive: bool
    affected_count: int
    affected_tokens: tuple[str, ...]
    conflicts: tuple[str, ...]
    required_resources: tuple[str, ...]
    expected_changes: tuple[str, ...]
    verification_requirements: tuple[str, ...]
    recovery_implications: tuple[str, ...]
    context_token: str
    predicted_only: Literal[True] = True


@dataclass(frozen=True)
class SettingsDependencyIssue:
    setting: str
    required_changes: tuple[tuple[str, object], ...]
    message: str
    security_sensitive: bool


@dataclass(frozen=True)
class SettingsAdvice:
    valid: bool
    issues: tuple[SettingsDependencyIssue, ...]

    @property
    def required_changes(self) -> tuple[tuple[str, object], ...]:
        changes: dict[str, object] = {}
        for issue in self.issues:
            changes.update(issue.required_changes)
        return tuple(sorted(changes.items()))


@dataclass(frozen=True)
class OperationResultReport:
    operation_id: str
    requested: str
    status: str
    affected_count: int
    succeeded_count: int
    failed_count: int
    cancelled_count: int
    skipped_count: int
    verified_count: int
    committed_count: int
    recovery_required: bool
    manual_review_required: bool
    recovered_count: int
    reporting_incomplete: bool
    affected_tokens: tuple[str, ...]
    succeeded_tokens: tuple[str, ...]
    failed_tokens: tuple[str, ...]
    cancelled_tokens: tuple[str, ...]
    skipped_tokens: tuple[str, ...]
    verified_tokens: tuple[str, ...]
    committed_tokens: tuple[str, ...]
    recovery_tokens: tuple[str, ...]
    recovered_tokens: tuple[str, ...]
    manual_review_tokens: tuple[str, ...]
    failure_codes: tuple[str, ...]


@dataclass(frozen=True)
class OperationSnapshot:
    operation_id: str
    name: str
    state: OperationState
    current_item: str | None
    completed_items: int
    total_items: int | None
    bytes_processed: int
    total_bytes: int | None
    started_at: float | None
    completed_at: float | None
    error: str | None
    recovery_state: str | None
    resumable: bool
    cancellation_acknowledged: bool
    dependencies: tuple[str, ...] = ()
    resource_keys: tuple[str, ...] = ()
    fingerprint: str | None = None
    waiting_reason: str | None = None

    @property
    def elapsed_seconds(self) -> float:
        end = self.completed_at if self.completed_at is not None else time.monotonic()
        return max(0.0, end - self.started_at) if self.started_at is not None else 0.0

    @property
    def percent(self) -> int | None:
        if self.total_bytes and self.total_bytes > 0:
            return min(100, int(self.bytes_processed * 100 / self.total_bytes))
        if self.total_items and self.total_items > 0:
            return min(100, int(self.completed_items * 100 / self.total_items))
        return None

    @property
    def estimated_remaining_seconds(self) -> float | None:
        total = self.total_bytes
        current = self.bytes_processed
        if not total or total <= 0 or current <= 0 or current >= total or self.started_at is None:
            return None
        elapsed = self.elapsed_seconds
        if elapsed <= 0:
            return None
        return max(0.0, elapsed * (total - current) / current)


class Operation:
    def __init__(self, manager: "OperationManager", operation_id: str) -> None:
        self._manager = manager
        self.operation_id = operation_id

    @property
    def snapshot(self) -> OperationSnapshot:
        return self._manager.get(self.operation_id)

    def belongs_to(self, manager: "OperationManager") -> bool:
        return self._manager is manager

    def on_ready(self, callback: Callable[[], None]) -> Callable[[], None]:
        """Register a one-shot callback to dispatch this operation when its gates clear."""
        return self._manager.on_ready(self.operation_id, callback)

    @property
    def cancel_event(self) -> threading.Event:
        return self._manager.cancel_event(self.operation_id)

    def start(self) -> OperationSnapshot:
        snapshot = self._manager.start(self.operation_id)
        if snapshot.state != OperationState.RUNNING:
            raise OperationBlocked(snapshot.waiting_reason or "The operation is not ready to start.")
        return snapshot

    def update(
        self,
        *,
        current_item: str | None = None,
        completed_items: int | None = None,
        total_items: int | None = None,
        bytes_processed: int | None = None,
        total_bytes: int | None = None,
        recovery_state: str | None = None,
    ) -> OperationSnapshot:
        return self._manager.update(
            self.operation_id,
            current_item=current_item,
            completed_items=completed_items,
            total_items=total_items,
            bytes_processed=bytes_processed,
            total_bytes=total_bytes,
            recovery_state=recovery_state,
        )

    def request_cancel(self) -> OperationSnapshot:
        return self._manager.request_cancel(self.operation_id)

    def checkpoint(self) -> None:
        if self.cancel_event.is_set():
            state = self.snapshot.state
            if state == OperationState.CANCEL_REQUESTED:
                self._manager.transition(self.operation_id, OperationState.CANCELING)
            raise OperationCancelled("Cancellation acknowledged at a safe checkpoint.")

    def complete(self) -> OperationSnapshot:
        return self._manager.transition(self.operation_id, OperationState.COMPLETED)

    def fail(self, error: str, recovery_state: str | None = None) -> OperationSnapshot:
        self.update(recovery_state=recovery_state)
        self._manager.set_error(self.operation_id, error)
        return self._manager.transition(self.operation_id, OperationState.FAILED)

    def canceled(self) -> OperationSnapshot:
        state = self.snapshot.state
        if state == OperationState.CANCEL_REQUESTED:
            self._manager.transition(self.operation_id, OperationState.CANCELING)
        snapshot = self._manager.transition(self.operation_id, OperationState.CANCELED)
        self._manager.mark_cancellation_acknowledged(self.operation_id)
        return snapshot

    def recovering(self, detail: str | None = None) -> OperationSnapshot:
        self._manager.transition(self.operation_id, OperationState.RECOVERING)
        return self.update(recovery_state=detail or "recovering")

    def recovery_failed(self, error: str) -> OperationSnapshot:
        self._manager.set_error(self.operation_id, error)
        self.update(recovery_state="recovery_failed")
        return self._manager.transition(self.operation_id, OperationState.RECOVERY_FAILED)

    def report_result(
        self,
        requested: str,
        *,
        affected_items: Iterable[str] = (),
        succeeded_items: Iterable[str] = (),
        failed_items: Iterable[str] = (),
        cancelled_items: Iterable[str] = (),
        skipped_items: Iterable[str] = (),
        verified_items: Iterable[str] = (),
        committed_items: Iterable[str] = (),
        recovery_items: Iterable[str] = (),
        manual_review_items: Iterable[str] = (),
        recovered_items: Iterable[str] = (),
        failure_codes: Iterable[object] = (),
    ) -> OperationResultReport:
        """Publish a sanitized, bounded summary for this operation."""
        return self._manager.record_result(
            self.operation_id, requested,
            affected_items=affected_items,
            succeeded_items=succeeded_items,
            failed_items=failed_items,
            cancelled_items=cancelled_items,
            skipped_items=skipped_items,
            verified_items=verified_items,
            committed_items=committed_items,
            recovery_items=recovery_items,
            manual_review_items=manual_review_items,
            recovered_items=recovered_items,
            failure_codes=failure_codes,
        )


class OperationManager:
    """Thread-safe in-memory operation state with bounded history and observers."""

    def __init__(self, history_limit: int = 100) -> None:
        if type(history_limit) is not int or history_limit < 1:
            raise ValueError("Operation history limit must be a positive integer.")
        self._lock = threading.RLock()
        self._snapshots: dict[str, OperationSnapshot] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._history: deque[str] = deque()
        self._resource_owners: dict[str, str] = {}
        self._ready_callbacks: dict[str, list[Callable[[], None]]] = {}
        self._observers: set[Callable[[OperationSnapshot], None]] = set()
        self._observer_errors: deque[str] = deque(maxlen=16)
        self._history_limit = history_limit
        self._reports: dict[str, OperationResultReport] = {}
        self._required_reports: set[str] = set()

    @property
    def reports(self) -> tuple[OperationResultReport, ...]:
        with self._lock:
            return tuple(self._reports[key] for key in reversed(self._history)
                         if key in self._reports)

    def report_for(self, operation_id: str) -> OperationResultReport | None:
        with self._lock:
            return self._reports.get(operation_id)

    def _store_report_locked(self, report: OperationResultReport) -> None:
        self._reports[report.operation_id] = report
        while len(self._reports) > self._history_limit:
            oldest = next(iter(self._reports))
            self._reports.pop(oldest)

    def _ensure_terminal_report_locked(self, snapshot: OperationSnapshot) -> None:
        if (snapshot.operation_id not in self._required_reports
                or snapshot.operation_id in self._reports):
            return
        self._store_report_locked(OperationResultReport(
            operation_id=snapshot.operation_id,
            requested="unreported_operation",
            status=snapshot.state.value,
            affected_count=0,
            succeeded_count=0,
            failed_count=0,
            cancelled_count=0,
            skipped_count=0,
            verified_count=0,
            committed_count=0,
            recovery_required=snapshot.recovery_state is not None,
            manual_review_required=True,
            recovered_count=0,
            reporting_incomplete=True,
            affected_tokens=(),
            succeeded_tokens=(),
            failed_tokens=(),
            cancelled_tokens=(),
            skipped_tokens=(),
            verified_tokens=(),
            committed_tokens=(),
            recovery_tokens=(),
            recovered_tokens=(),
            manual_review_tokens=(),
            failure_codes=("result_report_missing",),
        ))

    def simulate(
        self,
        requested: str,
        *,
        affected_items: Iterable[str] = (),
        resource_keys: Iterable[object] = (),
        depends_on: Iterable[Operation | str] = (),
        preflight_conflicts: Iterable[str] = (),
        destructive: bool = False,
        expected_changes: Iterable[str] = (),
        verification_requirements: Iterable[str] = (),
        recovery_implications: Iterable[str] = (),
        state_revisions: Mapping[str, int] | None = None,
    ) -> SimulationPlan:
        """Build a no-write prediction using the same dependency/resource gates as start()."""
        _validate_action_identifier(requested, "Simulation request")
        if type(destructive) is not bool:
            raise TypeError("Simulation destructive flag must be boolean.")
        items = _validated_values(affected_items, "affected item identifiers")
        resources = self._normalize_resource_keys(resource_keys)
        dependencies = self._validate_dependencies(depends_on)
        preflight = _validated_descriptions(preflight_conflicts, "preflight conflicts")
        changes = _validated_descriptions(expected_changes, "expected changes")
        verifications = _validated_descriptions(
            verification_requirements, "verification requirements")
        recovery = _validated_descriptions(recovery_implications, "recovery implications")
        revisions: dict[str, int] = {}
        if state_revisions is not None:
            for item_id, revision in state_revisions.items():
                _validate_identifier(item_id)
                if type(revision) is not int or revision < 0:
                    raise ValueError("Simulation state revisions must be non-negative integers.")
                revisions[item_id] = revision
        conflicts: list[str] = list(preflight)
        with self._lock:
            dependency_states: list[tuple[str, str]] = []
            for dependency_id in dependencies:
                dependency = self._require_locked(dependency_id)
                dependency_states.append(
                    (_identifier_token(dependency_id), dependency.state.value))
                if dependency.state != OperationState.COMPLETED:
                    conflicts.append("dependency_not_completed")
            owned_resources = {
                key for key, owner_id in self._resource_owners.items()
                if owner_id in self._snapshots
                and self._snapshots[owner_id].state not in TERMINAL_STATES
            }
            if any(key in owned_resources for key in resources):
                conflicts.append("resource_in_use")
            resource_owners = tuple(
                (key, _identifier_token(self._resource_owners[key])
                 if key in self._resource_owners else "")
                for key in resources
            )
            context_payload: dict[str, object] = {
                "requested": requested,
                "affected": tuple(_identifier_token(value) for value in items),
                "resources": resources,
                "dependencies": tuple(dependency_states),
                "owners": resource_owners,
                "preflight": tuple(dict.fromkeys(preflight)),
                "destructive": destructive,
                "changes": changes,
                "verification": verifications,
                "recovery": recovery,
                "state_revisions": tuple(sorted(
                    (_identifier_token(item_id), revision)
                    for item_id, revision in revisions.items()
                )),
            }
            context_token = hashlib.sha256(json.dumps(
                context_payload, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")).hexdigest()
        return SimulationPlan(
            simulation_id=uuid.uuid4().hex,
            requested=requested,
            valid=not conflicts,
            destructive=destructive,
            affected_count=len(items),
            affected_tokens=tuple(_identifier_token(value) for value in items),
            conflicts=tuple(dict.fromkeys(conflicts)),
            required_resources=tuple(_identifier_token(value) for value in resources),
            expected_changes=changes,
            verification_requirements=verifications,
            recovery_implications=recovery,
            context_token=context_token,
        )

    @staticmethod
    def require_current_simulation(
        planned: SimulationPlan, current: SimulationPlan,
    ) -> None:
        if (not planned.valid or not current.valid
                or replace(current, simulation_id=planned.simulation_id) != planned):
            raise StaleSimulationPlan(
                "Operation state changed after simulation; refresh and simulate again.")

    def record_result(
        self,
        operation_id: str,
        requested: str,
        *,
        affected_items: Iterable[str] = (),
        succeeded_items: Iterable[str] = (),
        failed_items: Iterable[str] = (),
        cancelled_items: Iterable[str] = (),
        skipped_items: Iterable[str] = (),
        verified_items: Iterable[str] = (),
        committed_items: Iterable[str] = (),
        recovery_items: Iterable[str] = (),
        manual_review_items: Iterable[str] = (),
        recovered_items: Iterable[str] = (),
        failure_codes: Iterable[object] = (),
    ) -> OperationResultReport:
        _validate_action_identifier(requested, "Report request")
        groups = [
            _validated_values(values, label)
            for values, label in (
                (affected_items, "affected items"),
                (succeeded_items, "succeeded items"),
                (failed_items, "failed items"),
                (cancelled_items, "cancelled items"),
                (skipped_items, "skipped items"),
                (verified_items, "verified items"),
                (committed_items, "committed items"),
                (recovery_items, "recovery items"),
                (recovered_items, "recovered items"),
                (manual_review_items, "manual-review items"),
            )
        ]
        affected, succeeded, failed, cancelled, skipped, verified, committed, recovery, recovered, review = groups
        affected_set = set(affected)
        if any(not set(group).issubset(affected_set) for group in groups[1:]):
            raise ValueError("Reported item outcomes must refer to affected items.")
        try:
            code_values = tuple(failure_codes)
        except TypeError as exc:
            raise TypeError("Failure codes must be iterable.") from exc
        safe_codes: list[str] = []
        for code in code_values:
            if not isinstance(code, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", code):
                raise ValueError("Failure codes must be non-sensitive identifiers.")
            safe_codes.append(code)
        codes = tuple(dict.fromkeys(safe_codes))
        with self._lock:
            snapshot = self._require_locked(operation_id)
            report = OperationResultReport(
                operation_id=operation_id,
                requested=requested,
                status=snapshot.state.value,
                affected_count=len(affected),
                succeeded_count=len(succeeded),
                failed_count=len(failed),
                cancelled_count=len(cancelled),
                skipped_count=len(skipped),
                verified_count=len(verified),
                committed_count=len(committed),
                recovery_required=bool(recovery),
                manual_review_required=bool(review),
                recovered_count=len(recovered),
                reporting_incomplete=False,
                affected_tokens=tuple(_identifier_token(value) for value in affected),
                succeeded_tokens=tuple(_identifier_token(value) for value in succeeded),
                failed_tokens=tuple(_identifier_token(value) for value in failed),
                cancelled_tokens=tuple(_identifier_token(value) for value in cancelled),
                skipped_tokens=tuple(_identifier_token(value) for value in skipped),
                verified_tokens=tuple(_identifier_token(value) for value in verified),
                committed_tokens=tuple(_identifier_token(value) for value in committed),
                recovery_tokens=tuple(_identifier_token(value) for value in recovery),
                recovered_tokens=tuple(_identifier_token(value) for value in recovered),
                manual_review_tokens=tuple(_identifier_token(value) for value in review),
                failure_codes=codes,
            )
            self._store_report_locked(report)
        return report

    def subscribe(self, observer: Callable[[OperationSnapshot], None]) -> Callable[[], None]:
        if not callable(observer):
            raise TypeError("Operation observer must be callable.")
        with self._lock:
            self._observers.add(observer)

        def unsubscribe() -> None:
            with self._lock:
                self._observers.discard(observer)

        return unsubscribe

    def create(
        self,
        name: object,
        *,
        current_item: str | None = None,
        total_items: int | None = None,
        total_bytes: int | None = None,
        resumable: bool = False,
        require_report: bool = False,
        depends_on: Iterable[Operation | str] = (),
        resource_keys: Iterable[object] = (),
        fingerprint_inputs: Mapping[object, object] | None = None,
    ) -> Operation:
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Operation name must be a non-empty string.")
        for label, value in (("total items", total_items), ("total bytes", total_bytes)):
            if value is not None and (type(value) is not int or value < 0):
                raise ValueError(f"Operation {label} must be a non-negative integer.")
        if type(resumable) is not bool:
            raise TypeError("Operation resumable flag must be boolean.")
        if type(require_report) is not bool:
            raise TypeError("Operation report requirement must be boolean.")
        dependency_ids = self._validate_dependencies(depends_on)
        normalized_resources = self._normalize_resource_keys(resource_keys)
        fingerprint = self._fingerprint(name.strip(), fingerprint_inputs)
        operation_id = uuid.uuid4().hex
        snapshot = OperationSnapshot(
            operation_id=operation_id,
            name=name.strip(),
            state=OperationState.QUEUED,
            current_item=current_item,
            completed_items=0,
            total_items=total_items,
            bytes_processed=0,
            total_bytes=total_bytes,
            started_at=None,
            completed_at=None,
            error=None,
            recovery_state=None,
            resumable=resumable,
            cancellation_acknowledged=False,
            dependencies=dependency_ids,
            resource_keys=normalized_resources,
            fingerprint=fingerprint,
        )
        with self._lock:
            for dependency_id in dependency_ids:
                self._require_locked(dependency_id)
            if fingerprint is not None and any(
                item.fingerprint == fingerprint and item.state not in TERMINAL_STATES
                for item in self._snapshots.values()
            ):
                raise DuplicateOperationError(
                    f"An identical {name.strip()} operation is already active.")
            self._snapshots[operation_id] = snapshot
            self._cancel_events[operation_id] = threading.Event()
            if require_report:
                self._required_reports.add(operation_id)
            self._history.append(operation_id)
            self._trim_history_locked()
        self._notify(snapshot)
        return Operation(self, operation_id)

    def add_dependency(self, operation_id: str, dependency: Operation | str) -> OperationSnapshot:
        dependency_id = self._dependency_id(dependency)
        with self._lock:
            current = self._require_locked(operation_id)
            self._require_locked(dependency_id)
            if current.state not in {OperationState.QUEUED, OperationState.WAITING}:
                raise InvalidOperationTransition("Dependencies cannot change after an operation starts.")
            if dependency_id == operation_id or self._depends_on_locked(dependency_id, operation_id):
                raise DependencyCycleError("The dependency would create an operation cycle.")
            if dependency_id in current.dependencies:
                return current
            snapshot = replace(current, dependencies=current.dependencies + (dependency_id,))
            self._snapshots[operation_id] = snapshot
        self._notify(snapshot)
        return snapshot

    def start(self, operation_id: str) -> OperationSnapshot:
        dependent_updates: list[OperationSnapshot] = []
        with self._lock:
            current = self._require_locked(operation_id)
            if current.state not in {OperationState.QUEUED, OperationState.WAITING}:
                raise InvalidOperationTransition(f"Cannot start operation from {current.state.value}.")
            failed_dependency = self._terminal_dependency_locked(current)
            blocker = self._dependency_blocker_locked(current)
            if blocker is None:
                blocker = self._resource_blocker_locked(current)
            if failed_dependency is not None:
                dependency, state = failed_dependency
                snapshot = replace(
                    current,
                    state=state,
                    error=f"Required operation {dependency.name} {state.value}.",
                    waiting_reason=None,
                    completed_at=time.monotonic(),
                    cancellation_acknowledged=state == OperationState.CANCELED,
                )
                self._snapshots[operation_id] = snapshot
                if state == OperationState.CANCELED:
                    self._cancel_events[operation_id].set()
                self._ready_callbacks.pop(operation_id, None)
                self._ensure_terminal_report_locked(snapshot)
                dependent_updates = self._resolve_dependents_locked(operation_id)
                self._trim_history_locked()
            elif blocker is not None:
                snapshot = replace(current, state=OperationState.WAITING, waiting_reason=blocker)
                self._snapshots[operation_id] = snapshot
            else:
                snapshot = replace(
                    current,
                    state=OperationState.RUNNING,
                    started_at=time.monotonic() if current.started_at is None else current.started_at,
                    waiting_reason=None,
                )
                self._snapshots[operation_id] = snapshot
                for key in snapshot.resource_keys:
                    self._resource_owners[key] = operation_id
        self._notify_many([snapshot, *dependent_updates])
        return snapshot

    def get(self, operation_id: str) -> OperationSnapshot:
        with self._lock:
            try:
                return self._snapshots[operation_id]
            except KeyError as exc:
                raise KeyError("Unknown operation ID.") from exc

    def cancel_event(self, operation_id: str) -> threading.Event:
        with self._lock:
            return self._cancel_events[operation_id]

    def snapshots(self) -> tuple[OperationSnapshot, ...]:
        with self._lock:
            return tuple(self._snapshots[operation_id] for operation_id in reversed(self._history))

    def ready_operations(self) -> tuple[OperationSnapshot, ...]:
        """Return queued operations whose dependencies and resources currently permit a start."""
        with self._lock:
            ready: list[OperationSnapshot] = []
            for operation_id in self._history:
                snapshot = self._snapshots[operation_id]
                if snapshot.state != OperationState.QUEUED:
                    continue
                if (self._terminal_dependency_locked(snapshot) is None
                        and self._dependency_blocker_locked(snapshot) is None
                        and self._resource_blocker_locked(snapshot) is None):
                    ready.append(snapshot)
            return tuple(ready)

    def on_ready(self, operation_id: str, callback: Callable[[], None]) -> Callable[[], None]:
        if not callable(callback):
            raise TypeError("Operation ready callback must be callable.")
        invoke_now = False
        with self._lock:
            snapshot = self._require_locked(operation_id)
            if snapshot.state not in {OperationState.QUEUED, OperationState.WAITING}:
                raise InvalidOperationTransition("Ready callbacks can only be registered for queued operations.")
            if snapshot.state == OperationState.QUEUED and self._is_ready_locked(snapshot):
                invoke_now = True
            else:
                self._ready_callbacks.setdefault(operation_id, []).append(callback)
        if invoke_now:
            self._invoke_ready_callback(callback)

        def unsubscribe() -> None:
            with self._lock:
                callbacks = self._ready_callbacks.get(operation_id)
                if callbacks is not None and callback in callbacks:
                    callbacks.remove(callback)
                    if not callbacks:
                        self._ready_callbacks.pop(operation_id, None)

        return unsubscribe

    @property
    def observer_errors(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._observer_errors)

    def transition(self, operation_id: str, state: object) -> OperationSnapshot:
        if not isinstance(state, OperationState):
            raise TypeError("Operation state must be an OperationState.")
        if state == OperationState.RUNNING:
            snapshot = self.start(operation_id)
            if snapshot.state != OperationState.RUNNING:
                raise OperationBlocked(snapshot.waiting_reason or "The operation is not ready to start.")
            return snapshot
        blocked_reason: str | None = None
        with self._lock:
            current = self._require_locked(operation_id)
            snapshot = current
            if state not in _TRANSITIONS[current.state]:
                raise InvalidOperationTransition(
                    f"Cannot transition operation from {current.state.value} to {state.value}.")
            if state == OperationState.RECOVERING:
                blocked_reason = self._resource_blocker_locked(current)
            now = time.monotonic()
            if blocked_reason is None:
                snapshot = replace(
                    current,
                    state=state,
                    started_at=current.started_at,
                    completed_at=now if state in TERMINAL_STATES else None,
                    waiting_reason=None if state != OperationState.WAITING else current.waiting_reason,
                    cancellation_acknowledged=(
                        True if state == OperationState.CANCELED else current.cancellation_acknowledged
                    ),
                )
                self._snapshots[operation_id] = snapshot
                if state == OperationState.RECOVERING:
                    for key in snapshot.resource_keys:
                        self._resource_owners[key] = operation_id
                if state in TERMINAL_STATES:
                    self._release_resources_locked(operation_id)
                    self._ready_callbacks.pop(operation_id, None)
                    self._ensure_terminal_report_locked(snapshot)
                    dependent_updates = self._resolve_dependents_locked(operation_id)
                    self._trim_history_locked()
                else:
                    dependent_updates = []
            else:
                dependent_updates = []
        if blocked_reason is not None:
            self._notify(snapshot)
            raise OperationBlocked(blocked_reason)
        self._notify_many([snapshot, *dependent_updates])
        return snapshot

    def request_cancel(self, operation_id: str) -> OperationSnapshot:
        with self._lock:
            current = self._require_locked(operation_id)
            if current.state in {OperationState.QUEUED, OperationState.WAITING}:
                self._cancel_events[operation_id].set()
                snapshot = replace(
                    current,
                    state=OperationState.CANCELED,
                    completed_at=time.monotonic(),
                    cancellation_acknowledged=True,
                    waiting_reason=None,
                )
                self._snapshots[operation_id] = snapshot
                self._ready_callbacks.pop(operation_id, None)
                self._ensure_terminal_report_locked(snapshot)
                dependent_updates = self._resolve_dependents_locked(operation_id)
                self._trim_history_locked()
            elif current.state == OperationState.RUNNING:
                self._cancel_events[operation_id].set()
                snapshot = replace(current, state=OperationState.CANCEL_REQUESTED)
                self._snapshots[operation_id] = snapshot
                dependent_updates = []
            else:
                return current
        self._notify_many([snapshot, *dependent_updates])
        return snapshot

    def update(
        self,
        operation_id: str,
        *,
        current_item: str | None = None,
        completed_items: int | None = None,
        total_items: int | None = None,
        bytes_processed: int | None = None,
        total_bytes: int | None = None,
        recovery_state: str | None = None,
    ) -> OperationSnapshot:
        with self._lock:
            current = self._require_locked(operation_id)
            updates = {}
            for key, value in (
                ("completed_items", completed_items),
                ("total_items", total_items),
                ("bytes_processed", bytes_processed),
                ("total_bytes", total_bytes),
            ):
                if value is not None:
                    if type(value) is not int or value < 0:
                        raise ValueError(f"Operation {key.replace('_', ' ')} must be a non-negative integer.")
                    updates[key] = value
            if current_item is not None:
                updates["current_item"] = current_item
            if recovery_state is not None:
                updates["recovery_state"] = recovery_state
            candidate = replace(current, **updates)
            if candidate.total_items is not None and candidate.completed_items > candidate.total_items:
                raise ValueError("Completed item count cannot exceed total items.")
            if candidate.total_bytes is not None and candidate.bytes_processed > candidate.total_bytes:
                raise ValueError("Processed bytes cannot exceed total bytes.")
            if candidate.completed_items < current.completed_items or candidate.bytes_processed < current.bytes_processed:
                raise ValueError("Operation progress cannot move backwards.")
            if current.state in TERMINAL_STATES:
                raise InvalidOperationTransition("A terminal operation cannot be updated.")
            self._snapshots[operation_id] = candidate
        self._notify(candidate)
        return candidate

    def set_error(self, operation_id: str, error: object) -> OperationSnapshot:
        if not isinstance(error, str) or not error.strip():
            raise ValueError("Operation failure detail must be non-empty text.")
        with self._lock:
            current = self._require_locked(operation_id)
            if current.state in TERMINAL_STATES:
                raise InvalidOperationTransition("A terminal operation cannot be changed.")
            snapshot = replace(current, error=error.strip()[:1000])
            self._snapshots[operation_id] = snapshot
        self._notify(snapshot)
        return snapshot

    def mark_cancellation_acknowledged(self, operation_id: str) -> OperationSnapshot:
        with self._lock:
            current = self._require_locked(operation_id)
            if current.state != OperationState.CANCELED:
                raise InvalidOperationTransition("Cancellation can only be acknowledged after cancellation.")
            snapshot = replace(current, cancellation_acknowledged=True)
            self._snapshots[operation_id] = snapshot
        self._notify(snapshot)
        return snapshot

    def _require_locked(self, operation_id: str) -> OperationSnapshot:
        try:
            return self._snapshots[operation_id]
        except KeyError as exc:
            raise KeyError("Unknown operation ID.") from exc

    def _trim_history_locked(self) -> None:
        while len(self._history) > self._history_limit:
            oldest = self._history.popleft()
            snapshot = self._snapshots[oldest]
            referenced = {
                dependency_id
                for item in self._snapshots.values()
                if item.state not in TERMINAL_STATES
                for dependency_id in item.dependencies
            }
            if oldest in referenced:
                self._history.append(oldest)
                if all(item in referenced for item in self._history):
                    break
                continue
            if snapshot.state not in TERMINAL_STATES:
                self._history.append(oldest)
                if all(self._snapshots[item].state not in TERMINAL_STATES for item in self._history):
                    break
                continue
            self._snapshots.pop(oldest, None)
            self._cancel_events.pop(oldest, None)
            self._required_reports.discard(oldest)
            self._reports.pop(oldest, None)

    def _notify(self, snapshot: OperationSnapshot) -> None:
        with self._lock:
            observers = tuple(self._observers)
        for observer in observers:
            try:
                observer(snapshot)
            except Exception as exc:
                with self._lock:
                    self._observer_errors.append(type(exc).__name__)

    def _notify_many(self, snapshots: Iterable[OperationSnapshot]) -> None:
        for snapshot in snapshots:
            self._notify(snapshot)
            if snapshot.state == OperationState.QUEUED:
                self._dispatch_ready_callbacks(snapshot.operation_id)

    def _dispatch_ready_callbacks(self, operation_id: str) -> None:
        with self._lock:
            snapshot = self._snapshots.get(operation_id)
            if snapshot is None or snapshot.state != OperationState.QUEUED or not self._is_ready_locked(snapshot):
                return
            callbacks = self._ready_callbacks.pop(operation_id, [])
        for callback in callbacks:
            self._invoke_ready_callback(callback)

    def _invoke_ready_callback(self, callback: Callable[[], None]) -> None:
        try:
            callback()
        except Exception as exc:
            with self._lock:
                self._observer_errors.append(type(exc).__name__)

    def _is_ready_locked(self, snapshot: OperationSnapshot) -> bool:
        return (
            self._terminal_dependency_locked(snapshot) is None
            and self._dependency_blocker_locked(snapshot) is None
            and self._resource_blocker_locked(snapshot) is None
        )

    def _dependency_id(self, dependency: Operation | str) -> str:
        if isinstance(dependency, Operation):
            if not dependency.belongs_to(self):
                raise ValueError("Operation dependencies must belong to the same manager.")
            return dependency.operation_id
        if not dependency:
            raise ValueError("Operation dependency ID must be a non-empty string.")
        return dependency

    def _validate_dependencies(self, dependencies: Iterable[Operation | str]) -> tuple[str, ...]:
        try:
            values = tuple(self._dependency_id(item) for item in dependencies)
        except TypeError as exc:
            raise TypeError("Operation dependencies must be iterable.") from exc
        if len(set(values)) != len(values):
            raise ValueError("Operation dependencies cannot contain duplicates.")
        with self._lock:
            for dependency_id in values:
                self._require_locked(dependency_id)
        return values

    @staticmethod
    def _normalize_resource_keys(resource_keys: Iterable[object]) -> tuple[str, ...]:
        values = tuple(resource_keys)
        normalized: list[str] = []
        for value in values:
            candidate: object = value
            if not isinstance(candidate, str) or not candidate.strip():
                raise ValueError("Operation resource keys must be non-empty strings.")
            key = unicodedata.normalize("NFKC", candidate).casefold().strip()
            if key not in normalized:
                normalized.append(key)
        return tuple(normalized)

    @staticmethod
    def _fingerprint(name: str, inputs: Mapping[object, object] | None) -> str | None:
        if inputs is None:
            return None
        forbidden = re.compile(
            r"password|passwd|secret|token|credential|recovery|plaintext|private.?key",
            re.IGNORECASE,
        )
        safe_inputs: dict[str, str | int | bool | None] = {}
        for key, value in inputs.items():
            candidate_key: object = key
            if not isinstance(candidate_key, str) or not candidate_key.strip():
                raise ValueError("Fingerprint input names must be non-empty strings.")
            if forbidden.search(candidate_key):
                raise ValueError("Sensitive fields cannot be used as operation fingerprint inputs.")
            if value is None:
                safe_inputs[candidate_key] = None
            elif isinstance(value, str):
                safe_inputs[candidate_key] = value
            elif type(value) is int:
                safe_inputs[candidate_key] = value
            elif type(value) is bool:
                safe_inputs[candidate_key] = value
            else:
                raise TypeError("Fingerprint values must be strings, integers, booleans, or None.")
        payload = json.dumps(
            {"name": name, "inputs": safe_inputs},
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def _depends_on_locked(self, operation_id: str, target_id: str) -> bool:
        pending = [operation_id]
        visited: set[str] = set()
        while pending:
            current_id = pending.pop()
            if current_id == target_id:
                return True
            if current_id in visited:
                continue
            visited.add(current_id)
            snapshot = self._snapshots.get(current_id)
            if snapshot is not None:
                pending.extend(snapshot.dependencies)
        return False

    def _terminal_dependency_locked(
        self,
        snapshot: OperationSnapshot,
    ) -> tuple[OperationSnapshot, OperationState] | None:
        for dependency_id in snapshot.dependencies:
            dependency = self._require_locked(dependency_id)
            if dependency.state in {OperationState.FAILED, OperationState.RECOVERY_FAILED}:
                return dependency, OperationState.FAILED
            if dependency.state == OperationState.CANCELED:
                return dependency, OperationState.CANCELED
        return None

    def _dependency_blocker_locked(self, snapshot: OperationSnapshot) -> str | None:
        for dependency_id in snapshot.dependencies:
            dependency = self._require_locked(dependency_id)
            if dependency.state != OperationState.COMPLETED:
                return f"Waiting for {dependency.name} to complete."
        return None

    def _resource_blocker_locked(self, snapshot: OperationSnapshot) -> str | None:
        for key in snapshot.resource_keys:
            owner_id = self._resource_owners.get(key)
            if owner_id is not None and owner_id != snapshot.operation_id:
                owner = self._snapshots.get(owner_id)
                if owner is not None:
                    return f"Waiting for {owner.name} to release a required resource."
        return None

    def _release_resources_locked(self, operation_id: str) -> None:
        for key, owner_id in tuple(self._resource_owners.items()):
            if owner_id == operation_id:
                del self._resource_owners[key]

    def _resolve_dependents_locked(self, dependency_id: str) -> list[OperationSnapshot]:
        dependency = self._require_locked(dependency_id)
        notifications: list[OperationSnapshot] = []
        candidates = tuple(self._history)
        for current_id in candidates:
            current = self._snapshots.get(current_id)
            if (current is None or dependency_id not in current.dependencies
                    or current.state not in {OperationState.QUEUED, OperationState.WAITING}):
                continue
            if dependency.state in {OperationState.FAILED, OperationState.RECOVERY_FAILED}:
                updated = replace(
                    current,
                    state=OperationState.FAILED,
                    error=f"Required operation {dependency.name} failed.",
                    waiting_reason=None,
                    completed_at=time.monotonic(),
                )
                self._snapshots[current_id] = updated
                self._ready_callbacks.pop(current_id, None)
                notifications.append(updated)
                notifications.extend(self._resolve_dependents_locked(current_id))
                continue
            if dependency.state == OperationState.CANCELED:
                updated = replace(
                    current,
                    state=OperationState.CANCELED,
                    error=f"Required operation {dependency.name} was canceled.",
                    waiting_reason=None,
                    completed_at=time.monotonic(),
                    cancellation_acknowledged=True,
                )
                self._snapshots[current_id] = updated
                self._ready_callbacks.pop(current_id, None)
                self._cancel_events[current_id].set()
                notifications.append(updated)
                notifications.extend(self._resolve_dependents_locked(current_id))
                continue
            blocker = self._terminal_dependency_locked(current)
            if blocker is not None:
                blocked_dependency, terminal_state = blocker
                updated = replace(
                    current,
                    state=terminal_state,
                    error=f"Required operation {blocked_dependency.name} {terminal_state.value}.",
                    waiting_reason=None,
                    completed_at=time.monotonic(),
                    cancellation_acknowledged=terminal_state == OperationState.CANCELED,
                )
                self._snapshots[current_id] = updated
                self._ready_callbacks.pop(current_id, None)
                if terminal_state == OperationState.CANCELED:
                    self._cancel_events[current_id].set()
                notifications.append(updated)
                notifications.extend(self._resolve_dependents_locked(current_id))
                continue
            waiting_reason = self._dependency_blocker_locked(current)
            if waiting_reason is None:
                waiting_reason = self._resource_blocker_locked(current)
            if waiting_reason is None and current.state == OperationState.WAITING:
                updated = replace(current, state=OperationState.QUEUED, waiting_reason=None)
                self._snapshots[current_id] = updated
                notifications.append(updated)
            elif waiting_reason is not None and current.waiting_reason != waiting_reason:
                updated = replace(current, state=OperationState.WAITING, waiting_reason=waiting_reason)
                self._snapshots[current_id] = updated
                notifications.append(updated)

        if dependency.state in TERMINAL_STATES:
            for current_id in candidates:
                current = self._snapshots.get(current_id)
                if current is None or current.state != OperationState.WAITING:
                    continue
                blocker = self._terminal_dependency_locked(current)
                if blocker is not None:
                    continue
                waiting_reason = self._dependency_blocker_locked(current)
                if waiting_reason is None:
                    waiting_reason = self._resource_blocker_locked(current)
                if waiting_reason is None:
                    updated = replace(current, state=OperationState.QUEUED, waiting_reason=None)
                    self._snapshots[current_id] = updated
                    notifications.append(updated)
        return notifications


_FILE_STATE_TRANSITIONS: dict[FileState, set[FileState]] = {
    FileState.AVAILABLE: {
        FileState.PROCESSING, FileState.LOCKED,
    },
    FileState.PROCESSING: {
        FileState.AVAILABLE, FileState.PENDING_VERIFICATION, FileState.RECOVERY_REQUIRED,
    },
    FileState.PENDING_VERIFICATION: {
        FileState.AVAILABLE, FileState.UNAVAILABLE, FileState.RECOVERY_REQUIRED,
    },
    FileState.LOCKED: {FileState.AVAILABLE},
    FileState.RECOVERY_REQUIRED: {FileState.PROCESSING},
    FileState.UNAVAILABLE: {FileState.AVAILABLE},
}


class FileStateManager:
    """Authoritative, revisioned state for individual vault objects."""

    def __init__(self, operations: OperationManager) -> None:
        self._operations = operations
        self._lock = threading.RLock()
        self._states: dict[str, tuple[FileState, int, str | None]] = {}

    def register(self, item_id: str, state: object = FileState.AVAILABLE) -> FileStateSnapshot:
        _validate_identifier(item_id)
        if not isinstance(state, FileState):
            raise TypeError("File state must be a FileState value.")
        if state in {FileState.PROCESSING, FileState.PENDING_VERIFICATION}:
            raise FileStateError("An active file state requires an owning operation.")
        with self._lock:
            current = self._states.get(item_id)
            if current is None:
                self._states[item_id] = (state, 0, None)
                current = self._states[item_id]
            return self._snapshot(item_id, current)

    def snapshot(self, item_id: str) -> FileStateSnapshot:
        _validate_identifier(item_id)
        with self._lock:
            try:
                current = self._states[item_id]
            except KeyError as exc:
                raise FileStateError("The file has no authoritative state.") from exc
            return self._snapshot(item_id, current)

    def require_available(self, item_id: str, expected_revision: int) -> FileStateSnapshot:
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("An expected file-state revision is required.")
        current = self.snapshot(item_id)
        if current.revision != expected_revision:
            raise StaleFileState("The item changed after this action was prepared.")
        if current.state != FileState.AVAILABLE:
            raise FileStateError(f"The item is {current.state.value} and cannot be used.")
        return current

    def lock_available(self, item_id: str, expected_revision: int) -> FileStateSnapshot:
        return self.transition(
            item_id, FileState.LOCKED, expected_revision=expected_revision)

    def unlock_verified(self, item_id: str, expected_revision: int) -> FileStateSnapshot:
        return self.transition(
            item_id, FileState.AVAILABLE, expected_revision=expected_revision,
            verified=True)

    def transition(
        self,
        item_id: str,
        target: object,
        *,
        expected_revision: int,
        operation_id: str | None = None,
        verified: bool = False,
        safe_cleanup: bool = False,
        recovery: bool = False,
    ) -> FileStateSnapshot:
        _validate_identifier(item_id)
        if not isinstance(target, FileState):
            raise TypeError("Target state must be a FileState value.")
        if type(expected_revision) is not int or expected_revision < 0:
            raise ValueError("Expected file-state revision must be a non-negative integer.")
        for label, value in (("verified", verified), ("safe cleanup", safe_cleanup),
                             ("recovery", recovery)):
            if type(value) is not bool:
                raise TypeError(f"{label.capitalize()} flag must be boolean.")
        with self._lock:
            try:
                source, revision, owner_id = self._states[item_id]
            except KeyError as exc:
                raise FileStateError("The file has no authoritative state.") from exc
            if revision != expected_revision:
                raise StaleFileState("The item changed after this action was prepared.")
            if target not in _FILE_STATE_TRANSITIONS[source]:
                raise FileStateError(
                    f"Invalid file-state transition: {source.value} to {target.value}.")
            if target in {FileState.PROCESSING, FileState.PENDING_VERIFICATION}:
                if not operation_id:
                    raise FileStateError("An owning operation is required for active file states.")
                operation = self._operations.get(operation_id)
                if operation.state != OperationState.RUNNING:
                    raise FileStateError("The owning operation must be running.")
                if source == FileState.PROCESSING and owner_id != operation_id:
                    raise FileStateError("Only the owning operation may advance this file.")
                if source == FileState.RECOVERY_REQUIRED and not recovery:
                    raise FileStateError("Recovery state may only be cleared by recovery.")
            if source == FileState.PROCESSING and target == FileState.AVAILABLE:
                if owner_id != operation_id or not safe_cleanup:
                    raise FileStateError("Processing can only be released after safe cleanup.")
            if source == FileState.LOCKED and target == FileState.AVAILABLE and not verified:
                raise FileStateError("A locked item must be verified before it is released.")
            if source == FileState.PENDING_VERIFICATION and target in {
                FileState.AVAILABLE, FileState.UNAVAILABLE,
            } and not verified:
                raise FileStateError("An item must pass verification before finalization.")
            if source == FileState.UNAVAILABLE and target == FileState.AVAILABLE:
                if not verified or not recovery:
                    raise FileStateError("Restoring an unavailable item requires verified recovery.")
            if target == FileState.RECOVERY_REQUIRED and source not in {
                FileState.PROCESSING, FileState.PENDING_VERIFICATION,
            }:
                raise FileStateError("Recovery is only valid after an interrupted active operation.")
            next_owner = operation_id if target in {
                FileState.PROCESSING, FileState.PENDING_VERIFICATION,
                FileState.RECOVERY_REQUIRED,
            } else None
            updated = (target, revision + 1, next_owner)
            self._states[item_id] = updated
            return self._snapshot(item_id, updated)

    def _snapshot(
        self, item_id: str, state: tuple[FileState, int, str | None],
    ) -> FileStateSnapshot:
        return FileStateSnapshot(
            item_token=_identifier_token(item_id),
            state=state[0],
            revision=state[1],
            operation_token=_identifier_token(state[2]) if state[2] else None,
        )


def advise_settings(settings: object) -> SettingsAdvice:
    """Describe explicit setting dependencies without applying or weakening settings."""
    if not isinstance(settings, Mapping):
        raise TypeError("Settings advice requires a mapping.")
    settings = cast(Mapping[str, object], settings)
    issues: list[SettingsDependencyIssue] = []
    ghost = settings.get("ghost", False)
    if type(ghost) is not bool:
        issues.append(SettingsDependencyIssue(
            "ghost", (), "Ghost mode must be explicitly enabled or disabled.", True))
    elif ghost:
        if settings.get("vmode", "mem") != "mem":
            issues.append(SettingsDependencyIssue(
                "ghost", (("vmode", "mem"),),
                "Ghost mode requires memory-only playback.", True))
        if settings.get("log", False) is not False:
            issues.append(SettingsDependencyIssue(
                "ghost", (("log", False),),
                "Ghost mode requires activity logging to be disabled.", True))
    return SettingsAdvice(valid=not issues, issues=tuple(issues))


def _validate_identifier(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 512:
        raise ValueError("Identifiers must be non-empty strings of at most 512 characters.")
    return value


def _validated_values(values: Iterable[object], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{label.capitalize()} must be an iterable of identifiers, not text.")
    try:
        result = tuple(_validate_identifier(value) for value in values)
    except TypeError as exc:
        raise TypeError(f"{label.capitalize()} must be iterable.") from exc
    if len(set(result)) != len(result):
        raise ValueError(f"{label.capitalize()} cannot contain duplicates.")
    return result


def _validated_descriptions(values: Iterable[object], label: str) -> tuple[str, ...]:
    if isinstance(values, (str, bytes)):
        raise TypeError(f"{label.capitalize()} must be an iterable of safe descriptions.")
    try:
        result = tuple(values)
    except TypeError as exc:
        raise TypeError(f"{label.capitalize()} must be iterable.") from exc
    safe_values: list[str] = []
    for value in result:
        if not isinstance(value, str) or not re.fullmatch(r"[a-z0-9_. -]{1,96}", value):
            raise ValueError(
                f"{label.capitalize()} must use non-sensitive descriptive identifiers.")
        safe_values.append(value)
    if len(set(result)) != len(result):
        raise ValueError(f"{label.capitalize()} cannot contain duplicates.")
    return tuple(safe_values)


def _identifier_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="strict")).hexdigest()[:16]


def _validate_action_identifier(value: object, label: str) -> str:
    forbidden = re.compile(r"password|passwd|secret|credential|plaintext|private.?key", re.IGNORECASE)
    if (not isinstance(value, str) or not re.fullmatch(r"[a-z0-9_.-]{1,64}", value)
            or forbidden.search(value)):
        raise ValueError(f"{label} must be a non-sensitive action identifier.")
    return value


__all__ = [
    "DependencyCycleError",
    "DuplicateOperationError",
    "FileState",
    "FileStateError",
    "FileStateManager",
    "FileStateSnapshot",
    "InvalidOperationTransition",
    "Operation",
    "OperationBlocked",
    "OperationCancelled",
    "OperationManager",
    "OperationResultReport",
    "OperationSnapshot",
    "OperationState",
    "SettingsAdvice",
    "SettingsDependencyIssue",
    "SimulationPlan",
    "StaleFileState",
    "TERMINAL_STATES",
    "advise_settings",
]
