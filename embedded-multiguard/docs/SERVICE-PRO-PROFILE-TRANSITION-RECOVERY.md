# MultiGuard SERVICE PRO — przerwana zmiana profilu Windows

Status: procedura ręczna wdrożona w roboczych PR #31 i #33; **bez automatycznego odblokowania**, jeszcze bez testu Windows/MeshCentral na produkcji.

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

1. OWNER otwiera panel **Zdalna pomoc** i wybiera właściwy komputer serwisowy z aktywną blokadą. **Dopiero po potwierdzeniu zakończenia okna UAC i wszelkich procesów podwyższonych** zaznacza oświadczenie i wybiera **Zezwól na lokalne odzyskanie**. Serwer wymaga, by rezerwacja miała co najmniej 2 minuty, sprawdza brak sesji w obu tabelach i zapisuje 5-minutową zgodę powiązaną z dokładnym `reservationId`. Samo zatwierdzenie NICZEGO nie odblokowuje.
2. Na **tym samym komputerze** lokalny operator wybiera w MultiGuard **Sprawdź blokadę**. Serwer ujawnia ID i kierunek przełączenia tylko uwierzytelnionej instalacji z aktywnym upoważnieniem OWNER.
3. Operator wybiera **Odzyskaj po kontroli Windows**. Aplikacja uruchamia własnego inspektora chronionej usługi `multiguardagent` (własność, SHA-256, konfiguracja Mesh/MSH, stan SCM). Dopuszczalne wyniki: dla docelowego SERVICE_PRO — `SERVICE_PRO_DORMANT`, `CLIENT_STOPPED` lub `CLIENT_RUNNING`; dla docelowego CLIENT — `CLIENT_STOPPED` lub `SERVICE_PRO_DORMANT`. Działający SERVICE PRO ani jakikolwiek niezweryfikowany stan **nigdy** nie odblokowują rezerwacji.
4. Z tego samego urządzenia klient wywołuje uwierzytelnione `/multiguard/agent/workshop/profile-transition-recover` z dokładnym ID, kierunkiem i lokalnie zweryfikowanym profilem. Serwer pod blokadą transakcyjną ponownie sprawdza aktywność zgody OWNER, uprawnienie licencji, brak sesji komercyjnych i serwisowych oraz wymagane cofnięcie standing approval przy przejściu do CLIENT. Dopiero wtedy zapisuje audyt i zwalnia rezerwację.

Zgoda OWNER jest jednorazowa w obrębie konkretnej rezerwacji i ważna przez 5 minut. Brak sieci, brak upoważnienia, niezgodny identyfikator, aktywny pulpit lub niebezpieczny wynik inspektora pozostawia sesje zablokowane. Ta ścieżka nie uruchamia MeshAgent i nie zmienia SCM.

**NIE UŻYWAJ** `DELETE`, ręcznego `UPDATE released_at`, czyszczenia dziennika własności SCM, reinstalacji obcego MeshAgent ani wymuszania `Start-Service` SERVICE PRO. Nie przenoś urządzenia pomiędzy grupami MeshCentral na podstawie samego hostname.

**Ograniczenie:** FastAPI nie może zdalnie potwierdzić stanu SCM. Bezpieczne odblokowanie wymaga rzeczywistego sprawdzenia przez zainstalowaną aplikację i niezależnego potwierdzenia OWNER, że żaden proces UAC już nie pracuje. Wymaga to dalszych testów awaryjnych na Windows przed dopuszczeniem klientów.

## Warunki przed wdrożeniem produkcyjnym

- PASS regresji serwerowej, w tym rozróżnienia wewnętrznego i zewnętrznego UUID oraz obu kierunków blokady sesji.
- PASS prywatnego kompilowania Windows po zmianie inspektora post-UAC.
- Testy laboratoryjne: anulowany UAC, odmowa dostępu administratora, częściowa zmiana SCM, utrata sieci w `finish`, zamknięcie aplikacji podczas UAC i odrębna procedura OWNER-assisted recovery.
- Po wdrożeniu: testy OWNER panel → FastAPI LXC103 → MeshCentral LXC106 → Windows test, z zachowaniem dotychczasowej zgody per-session dla płatnego Pro.

Do chwili spełnienia tych warunków nie oznaczać SERVICE PRO jako gotowego do instalacji u klientów.
