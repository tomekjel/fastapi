def _mg_v44_owner_apply_term(iid, operation_id, expected_end, target_end, selection):
    """A single OWNER Save changes the absolute paid expiration in KeyGate.

    This is an OWNER setting change, NEVER a claim that money was received.
    The audit trail is independent of payment and uses an operation UUID.
    Service edition/permissions are untouched. KeyGate licence ID is reused.
    """
    if (selection not in ("3", "6", "12", "CALENDAR")
            or expected_end is None or target_end is None
            or expected_end.tzinfo is None or target_end.tzinfo is None):
        raise HTTPException(400, "Nieprawidłowy okres lub data licencji.")
    if target_end <= _utcnow():
        raise HTTPException(400, "Wybierz przyszłą datę.")
    _ensure_schema()
    with engine.begin() as con:
        # The audit table is additive. Existing payment and licence records
        # are not reinterpreted, removed or altered by this migration.
        con.execute(text("""
            CREATE TABLE IF NOT EXISTS guard.owner_license_term_changes (
                id uuid PRIMARY KEY,
                license_link_id uuid NOT NULL,
                previous_valid_until timestamptz NOT NULL,
                new_valid_until timestamptz NOT NULL,
                selection varchar(16) NOT NULL,
                created_at timestamptz NOT NULL DEFAULT now()
            )
        """))
        # Same lock order as selected-mode changes: installation first.
        pending = con.execute(text("""
            SELECT installation_id FROM guard.pending_installations
            WHERE installation_id=:iid FOR UPDATE
        """), {"iid": iid}).scalar_one_or_none()
        if pending is None:
            raise HTTPException(409, "Nie znaleziono komputera.")
        row = con.execute(text("""
            SELECT * FROM guard.license_links
            WHERE installation_id=:iid FOR UPDATE
        """), {"iid": iid}).mappings().one_or_none()
        if row is None:
            raise HTTPException(404, "Nie znaleziono licencji.")
        previous = con.execute(text("""
            SELECT * FROM guard.owner_license_term_changes WHERE id=:op
        """), {"op": operation_id}).mappings().one_or_none()
        if previous:
            if (previous["license_link_id"] != row["id"]
                    or previous["previous_valid_until"] != expected_end
                    or previous["new_valid_until"] != target_end
                    or previous["selection"] != selection):
                raise HTTPException(409, "Identyfikator operacji już wykorzystany.")
            return
        if _owner_effective_entitlement_mode(con, iid) != "CLIENT":
            raise HTTPException(409, "Komputer nie jest w trybie klienta.")
        if row["lifecycle"] != "ACTIVE" or row["valid_until"] != expected_end:
            raise HTTPException(409, "Data licencji zmieniła się. Odśwież tabelę.")
        if _owner_pending_plan_change(con, row["id"]):
            raise HTTPException(409, "Trwa zmiana edycji. Dokończ ją najpierw.")
        # Absolute-date KeyGate operation is retry-safe. Never revoke,
        # activate or replace the original paid licence key.
        _keygate_set_valid_until(row["keygate_license_id"], target_end)
        updated = con.execute(text("""
            UPDATE guard.license_links
            SET valid_until=:until, updated_at=now()
            WHERE id=:id
            RETURNING *
        """), {"until": target_end, "id": row["id"]}).mappings().one()
        _update_installation_mirror(con, _normalize_link(dict(updated)))
        con.execute(text("""
            INSERT INTO guard.owner_license_term_changes (
                id, license_link_id, previous_valid_until, new_valid_until, selection
            ) VALUES (:op, :id, :old, :new, :choice)
        """), {"op": operation_id, "id": row["id"], "old": expected_end,
               "new": target_end, "choice": selection})
