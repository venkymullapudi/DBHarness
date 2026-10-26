"""Privileged Access Management: just-in-time elevation and approval workflows.

Two PAM primitives ship in the MVP:

* **Approval workflow.** When the policy marks an operation as requiring
  approval (e.g. an ``UPDATE`` on a sensitive table), the gate does *not* run it.
  It stores the already-rewritten, already-policy-checked statement as a pending
  approval and returns an ``approval_id``. A human approves out-of-band, and the
  gate then executes *exactly the statement that was approved* — the agent never
  gets to swap the SQL between approval and execution (no TOCTOU gap).

* **Just-in-time elevation.** A principal can be granted an extra role for a
  bounded window (minutes), after which it silently expires. Standing privilege
  is minimized; elevated privilege is temporary and auditable.

State is in-memory for the MVP (single-process gate). A multi-node deployment
would back this with a shared store; the interface would not change.
"""

from __future__ import annotations

import enum
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ApprovalStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    CONSUMED = "consumed"  # approved and already executed — cannot be reused
    EXPIRED = "expired"


@dataclass
class PendingApproval:
    id: str
    principal_id: str
    action: str
    risk: str
    raw_sql: str
    effective_sql: str  # the rewritten statement that will actually run
    reason: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: str = ""
    decided_at: Optional[datetime] = None

    def is_expired(self) -> bool:
        return _now() >= self.expires_at


@dataclass
class Elevation:
    role: str
    granted_by: str
    expires_at: datetime

    def is_active(self) -> bool:
        return _now() < self.expires_at


class PamError(RuntimeError):
    pass


class PamStore:
    """Persistence seam for PAM state (approvals + elevations).

    The default is in-process. For a multi-node gate, implement this against a
    shared store (Redis, a database table) so approvals raised on one node can be
    decided and consumed on another; the :class:`PamBroker` API is unchanged.
    """

    def put_approval(self, approval: PendingApproval) -> None:  # pragma: no cover
        raise NotImplementedError

    def get_approval(self, approval_id: str) -> "Optional[PendingApproval]":  # pragma: no cover
        raise NotImplementedError

    def all_approvals(self) -> List[PendingApproval]:  # pragma: no cover
        raise NotImplementedError

    def get_elevations(self, principal_id: str) -> List[Elevation]:  # pragma: no cover
        raise NotImplementedError

    def set_elevations(self, principal_id: str, elevations: List[Elevation]) -> None:  # pragma: no cover
        raise NotImplementedError


class InMemoryPamStore(PamStore):
    def __init__(self) -> None:
        self._approvals: Dict[str, PendingApproval] = {}
        self._elevations: Dict[str, List[Elevation]] = {}

    def put_approval(self, approval: PendingApproval) -> None:
        self._approvals[approval.id] = approval

    def get_approval(self, approval_id: str) -> "Optional[PendingApproval]":
        return self._approvals.get(approval_id)

    def all_approvals(self) -> List[PendingApproval]:
        return list(self._approvals.values())

    def get_elevations(self, principal_id: str) -> List[Elevation]:
        return list(self._elevations.get(principal_id, []))

    def set_elevations(self, principal_id: str, elevations: List[Elevation]) -> None:
        self._elevations[principal_id] = elevations


class PamBroker:
    def __init__(
        self,
        approval_ttl_minutes: int = 30,
        default_elevation_minutes: int = 15,
        store: "Optional[PamStore]" = None,
    ):
        self.approval_ttl = timedelta(minutes=approval_ttl_minutes)
        self.default_elevation = timedelta(minutes=default_elevation_minutes)
        self.store = store or InMemoryPamStore()

    # -- approvals ------------------------------------------------------------

    def create_approval(
        self,
        principal_id: str,
        action: str,
        risk: str,
        raw_sql: str,
        effective_sql: str,
        reason: str,
    ) -> PendingApproval:
        approval = PendingApproval(
            id=uuid.uuid4().hex[:12],
            principal_id=principal_id,
            action=action,
            risk=risk,
            raw_sql=raw_sql,
            effective_sql=effective_sql,
            reason=reason,
            created_at=_now(),
            expires_at=_now() + self.approval_ttl,
        )
        self.store.put_approval(approval)
        return approval

    def get_approval(self, approval_id: str) -> PendingApproval:
        approval = self.store.get_approval(approval_id)
        if approval is None:
            raise PamError(f"unknown approval {approval_id!r}")
        if approval.status is ApprovalStatus.PENDING and approval.is_expired():
            approval.status = ApprovalStatus.EXPIRED
        return approval

    def decide(self, approval_id: str, approve: bool, approver: str) -> PendingApproval:
        approval = self.get_approval(approval_id)
        if approval.status is not ApprovalStatus.PENDING:
            raise PamError(
                f"approval {approval_id!r} is {approval.status.value}, cannot decide"
            )
        approval.status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
        approval.decided_by = approver
        approval.decided_at = _now()
        return approval

    def consume(self, approval_id: str, principal_id: str) -> str:
        """Mark an approved statement as used and return its effective SQL.

        Enforces that the same principal that requested it is executing it, that
        it was approved, not expired, and not already consumed.
        """
        approval = self.get_approval(approval_id)
        if approval.principal_id != principal_id:
            raise PamError("this approval belongs to a different principal")
        if approval.status is ApprovalStatus.APPROVED and approval.is_expired():
            approval.status = ApprovalStatus.EXPIRED
        if approval.status is not ApprovalStatus.APPROVED:
            raise PamError(
                f"approval {approval_id!r} is {approval.status.value}, not runnable"
            )
        approval.status = ApprovalStatus.CONSUMED
        return approval.effective_sql

    def list_pending(self) -> List[PendingApproval]:
        out = []
        for a in self.store.all_approvals():
            if a.status is ApprovalStatus.PENDING and a.is_expired():
                a.status = ApprovalStatus.EXPIRED
            if a.status is ApprovalStatus.PENDING:
                out.append(a)
        return out

    # -- just-in-time elevation ----------------------------------------------

    def elevate(
        self,
        principal_id: str,
        role: str,
        granted_by: str,
        minutes: Optional[int] = None,
    ) -> Elevation:
        window = timedelta(minutes=minutes) if minutes else self.default_elevation
        elevation = Elevation(
            role=role,
            granted_by=granted_by,
            expires_at=_now() + window,
        )
        elevations = self.store.get_elevations(principal_id)
        elevations.append(elevation)
        self.store.set_elevations(principal_id, elevations)
        return elevation

    def active_roles(self, principal_id: str) -> List[str]:
        elevations = self.store.get_elevations(principal_id)
        # Drop expired ones lazily.
        live = [e for e in elevations if e.is_active()]
        self.store.set_elevations(principal_id, live)
        return [e.role for e in live]
