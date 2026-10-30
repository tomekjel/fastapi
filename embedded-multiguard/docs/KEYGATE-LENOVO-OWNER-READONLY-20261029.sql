# Diagnostyka read-only przed odblokowaniem konkretnej instalacji KeyGate
# Uruchamiac WYŁĄCZNIE po ustaleniu rzeczywistego installation_id Lenovo.
# :installation_id -- parametr SQL; nie zawiera klucza licencyjnego.
SELECT p.installation_id, p.status AS installation_status,
       p.assigned_license_id, a.workspace_reference,
       a.state AS keygate_attempt_state, a.keygate_license_id,
       a.edition, a.duration_months, a.release_channel,
       l.id AS local_link_id, l.lifecycle AS local_lifecycle,
       l.keygate_license_id AS linked_keygate_id,
       w.enabled AS service_enabled, w.edition AS service_edition
FROM guard.pending_installations p
LEFT JOIN guard.direct_keygate_attempts a ON a.installation_id=p.installation_id
LEFT JOIN guard.license_links l ON l.installation_id=p.installation_id
LEFT JOIN guard.workshop_grants w ON w.installation_id=p.installation_id
WHERE p.installation_id=:installation_id;

-- Interpretacja:
-- (1) CREATED + linked_keygate_id = keygate_license_id:
--     istnieje już lokalne przypisanie; NIE wystawiać kolejnej licencji.
-- (2) STARTED / RECONCILIATION_REQUIRED, bądź CREATED bez linku:
--     sprawdzić referencję MG-DIRECT-<installation_id bez myślników>
--     w KeyGate (read-only); nie kasować audytu ani nie ponawiać POST.
-- (3) Jeśli KeyGate potwierdza licencję, wykonać osobną kontrolowaną
--     procedurę odzyskania przypisania z tym samym ID/kluczem po stronie
--     OWNER. Brak potwierdzenia NIE oznacza automatycznie, że jej nie ma.
-- (4) Sprawdzić aktywne workshop_grants PRZED przełączeniem na DIRECT.
