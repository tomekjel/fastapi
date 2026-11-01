# MultiGuard SERVICE PRO — przerwana zmiana profilu Windows

Status: procedura diagnostyczna do zatwierdzenia; **bez automatycznego odblokowania**, bez zmian produkcyjnych.

## Dlaczego blokada nie ma limitu czasu

`guard.workshop_profile_transition_locks` rezerwuje przejście CLIENT ↔ SERVICE_PRO dla jednego `installation_id` (identyfikator z `guard.pending_installations`, a nie wewnętrzny `guard.installations.id`). Rezerwacja blokuje tworzenie nowych sesji zarówno w `guard.workshop_remote_sessions`, jak i w `guard.remote_sessions`. Lokalna aplikacja uzyskuje UUID przed UAC i zwalnia go dopiero po zakończeniu wywołania Windows **oraz** weryfikacji profilu usługi SCM, SHA-256 i MSH.

Awaria zasilania, zamknięcie aplikacji, niejednoznaczny stan Windows lub błąd sieci przy `profile-transition-finish` pozostawia rezerwację aktywną. To pożądane zabezpieczenie; nie usuwamy jej po 5/15 minutach.

## Diagnostyka tylko do odczytu (OWNER)

1. W panelu **Zdalna pomoc** otwórz komputer z sekcji **Komputery serwisowe Pro**. Panel pokazuje docelowy tryb i datę rozpoczęcia blokady. Nie rozpoczynaj nowej sesji.
2. Ustal, czy okno UAC i proces uruchomiony z uprawnieniami administratora definitywnie się zakończyły. Przy niepewności komputer może wymagać kontrolowanego ponownego uruchomienia. Nie wyłączaj aktywnego pulpitu klienta.
3. Na **tym samym komputerze Windows** użyj zainstalowanego, chronionego inspektora MultiGuard (akcja `Inspect`) i zweryfikuj wynik SCM, własność usługi `multiguardagent`, SHA oraz zgodność profilu Mesh. Nie opieraj decyzji na samej nazwie pliku.
4. W bazie przeczytaj, bez zmieniania danych, stan rezerwacji i obydwu tabel sesji. **Płatne sesje** trzeba powiązać przez `guard.installations.installation_external_id`. Samo `guard.remote_sessions.installation_id = workshop installation_id` jest błędem.
5. Jeśli istnieje sesja REQUESTED/CONSENTED/CONNECT_READY/ACTIVE, nie zwalniaj rezerwacji, dopóki nie zostanie ona prawidłowo zakończona wraz z potwierdzeniem cofnięcia udostępnienia w MeshCentral.

Przykładowe zapytania do odczytu (podstaw właściwy `:iid`; nie uruchamiają operacji na usłudze):

```sql
SELECT installation_id, reservation_id, target_mode, created_at, released_at
FROM guard.workshop_profile_transition_locks
WHERE installation_id=:iid;

SELECT id, status, mesh_public_id
FROM guard.workshop_remote_sessions
WHERE installation_id=:iid
  AND status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE');

SELECT rs.id, rs.status, rs.mesh_public_id
FROM guard.remote_sessions rs
JOIN guard.installations gi ON gi.id=rs.installation_id
WHERE gi.installation_external_id=:iid
  AND rs.status IN ('REQUESTED','CONSENTED','CONNECT_READY','ACTIVE');
```

## Zwalnianie — tylko bezpieczną ścieżką

Dopuszczalna jest wyłącznie uwierzytelniona, identyfikowana przez dokładny `reservationId` operacja `/multiguard/agent/workshop/profile-transition-finish` **po** udokumentowanym potwierdzeniu ustalonego, zweryfikowanego stanu usługi. Ścieżka automatyczna aplikacji wykonuje te kontrole bezpośrednio po UAC. **Procedura OWNER-assisted recovery po nieodwracalnej utracie rezerwacji przez aplikację nie jest jeszcze wdrożona**; do czasu jej dodania rezerwacja pozostaje zablokowana, a obsługa wymaga osobnego audytu technicznego.

**NIE UŻYWAJ** `DELETE`, ręcznego `UPDATE released_at`, czyszczenia dziennika własności SCM, reinstalacji obcego MeshAgent ani wymuszania `Start-Service` SERVICE PRO. Nie przenoś też urządzenia pomiędzy grupami MeshCentral na podstawie samego hostname.

## Warunki przed wdrożeniem produkcyjnym

- PASS regresji serwerowej, w tym rozróżnienia wewnętrznego i zewnętrznego UUID oraz obu kierunków blokady sesji.
- PASS prywatnego kompilowania Windows po zmianie inspektora post-UAC.
- Testy laboratoryjne: anulowany UAC, odmowa dostępu administratora, częściowa zmiana SCM, utrata sieci w `finish`, zamknięcie aplikacji podczas UAC i odrębna procedura OWNER-assisted recovery.
- Po wdrożeniu: testy OWNER panel → FastAPI LXC103 → MeshCentral LXC106 → Windows test, z zachowaniem dotychczasowej zgody per-session dla płatnego Pro.

Do chwili spełnienia tych warunków nie oznaczać SERVICE PRO jako gotowego do instalacji u klientów.
