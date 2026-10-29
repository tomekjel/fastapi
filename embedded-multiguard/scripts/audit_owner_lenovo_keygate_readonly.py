"""Read-only OWNER audit: Lenovo KeyGate creation attempts. No tokens or keys."""
from sqlalchemy import text
from app.database import engine
with engine.connect() as db:
    rows=db.execute(text("""
      SELECT p.installation_id,p.hostname,p.manufacturer,p.model,
             p.status,p.assigned_license_id,
             a.state AS attempt_state,a.keygate_license_id AS attempted_id,
             a.edition,a.duration_months,
             l.keygate_license_id AS linked_id,l.lifecycle,
             w.enabled AS service_enabled,w.edition AS service_edition
      FROM guard.pending_installations p
      LEFT JOIN guard.direct_keygate_attempts a
        ON a.installation_id=p.installation_id
      LEFT JOIN guard.license_links l
        ON l.installation_id=p.installation_id
      LEFT JOIN guard.workshop_grants w
        ON w.installation_id=p.installation_id
      WHERE p.manufacturer ILIKE '%Lenovo%'
         OR p.hostname ILIKE '%Lenovo%'
         OR p.model ILIKE '%ThinkPad%'
      ORDER BY p.last_seen_at DESC NULLS LAST
      LIMIT 20
    """)).mappings().all()
    print("MATCHING_LENOVO_INSTALLATIONS",len(rows))
    for r in rows:
        print("INSTALLATION",str(r["installation_id"])[:8],
              "pending",r["status"],
              "attempt",r["attempt_state"] or "NONE",
              "linked",bool(r["linked_id"]),
              "ids_match",bool(r["attempted_id"] and r["attempted_id"]==r["linked_id"]),
              "assigned",bool(r["assigned_license_id"]),
              "plan",r["edition"] or "NONE",
              "months",r["duration_months"] or "NONE",
              "service",bool(r["service_enabled"]),
              "service_edition",r["service_edition"] or "NONE",
              "lifecycle",r["lifecycle"] or "NONE")
print("READ_ONLY_AUDIT_COMPLETE")
