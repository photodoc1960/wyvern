"""In-memory store of quarantine records with a reversible lifecycle.

Phase 0 keeps state in memory; durable persistence + restart reconciliation
arrive in Phase 1 (that is a precondition for any real enforcement). The API is
deliberately small so a DB-backed implementation can drop in behind it.
"""

from __future__ import annotations

from dataclasses import replace

from .models import QState, QuarantineRecord


class QuarantineStore:
    def __init__(self, db=None) -> None:
        self._records: dict[str, QuarantineRecord] = {}
        self._db = db
        if db is not None:
            for row in db.load_quarantines():
                rec = QuarantineRecord.from_row(row)
                self._records[rec.id] = rec

    def _persist(self, record: QuarantineRecord) -> None:
        if self._db is not None:
            self._db.upsert_quarantine(record.to_row())

    def add(self, record: QuarantineRecord) -> QuarantineRecord:
        self._records[record.id] = record
        self._persist(record)
        return record

    def get(self, record_id: str) -> QuarantineRecord | None:
        return self._records.get(record_id)

    def all(self) -> list[QuarantineRecord]:
        return list(self._records.values())

    def active(self, now: float) -> list[QuarantineRecord]:
        """Records still in force (not expired/released) as of ``now``."""
        live = {QState.PROPOSED, QState.PENDING, QState.ACTIVE}
        return [r for r in self._records.values() if r.status in live and r.expires_at > now]

    def release(self, record_id: str, now: float) -> QuarantineRecord | None:
        """Manually lift a quarantine — the reversibility guarantee."""
        rec = self._records.get(record_id)
        if rec is None:
            return None
        rec = replace(rec, status=QState.RELEASED, released_at=now)
        self._records[record_id] = rec
        self._persist(rec)
        return rec

    def expire_due(self, now: float) -> list[QuarantineRecord]:
        """Transition any past-TTL live record to EXPIRED. Returns those expired."""
        expired: list[QuarantineRecord] = []
        live = {QState.PROPOSED, QState.PENDING, QState.ACTIVE}
        for rid, rec in list(self._records.items()):
            if rec.status in live and rec.expires_at <= now:
                rec = replace(rec, status=QState.EXPIRED)
                self._records[rid] = rec
                self._persist(rec)
                expired.append(rec)
        return expired
