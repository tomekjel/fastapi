# OWNER Multi-Servis Android: automatyczna diagnostyka chmurki

## Cel i granice
- Bez dodatkowej aplikacji i bez ręcznych testów użytkownika.
- Normalna podpisana aktualizacja Android Multi-Servis zbiera zdarzenia rozpoznawania
  połączeń (bez numerów telefonu, klientów, zleceń, danych nagrań lub URL API).
- OWNER-only Bearer auth zgodny z dotychczasowymi endpointami Multi-Servis.
  Nie używać Basic Auth panelu webowego ani haseł wszytych do APK.
- Brak jakiegokolwiek zdalnego sterowania telefonem. Zdalna sesja MultiGuard Windows
  nadal wymaga osobnej zgody klienta dla każdej sesji.

## Kontrakt API
- POST /mobile/diagnostics/caller: JSON `deviceId` (losowy UUID urządzenia do
  celów diagnostycznych), `events` 1..100 pozycji; każde zdarzenie to
  `eventId`, `occurredAt` (UTC), `source`, `event`, opcjonalne
  `activeJobs`, `latencyMs`, `errorClass` (wyłącznie nazwa klasy).
- GET /mobile/diagnostics/caller?limit=100: OWNER-only odczyt.
- Deduplikacja po (deviceId, eventId). Brak wysyłania numeru, nagrań,
  kontaktów, notatek lub nazwy telefonu w pakiecie.
- Retencja logiczna 7 dni; stare wpisy usuwane przy kolejnych żądaniach
  zapisu. Administracyjne okresowe czyszczenie tabeli należy włączyć
  przed produkcyjnym użyciem, gdy wymagana jest ścisła 7-dniowa retencja.
- Ograniczenie liczby wpisów (100), walidacja zakresu czasu, enum zdarzeń,
  wielkości pola błędu i statusów HTTP.
- 401/403 nie ujawniają danych. Inne role STAFF nie mają dostępu.

## Rollout i brak kolizji
- Odseparowana gałąź backendu: feature/mobile-caller-diagnostics-20261013,
  **bez zmian w istniejących routerach panelu i licencji**.
- Zmiana instalki backendu w tej gałęzi tylko dodaje import/router i backup
  nowego pliku. Nie wykonywać równoległych wdrożeń z drugim czatem.
- Android po 404 nie ponawia agresywnie (kolejny okresowy lub połączeniowy
  job WorkManager), zatrzymuje informacje lokalnie, aż API zacznie działać.
- Publikacja Android 1.10 musi nastąpić po weryfikacji podpisu oraz działającego
  endpointu API; nie podmieniać aplikacji produkcyjnej APK debug.
- Android PR #6 i webowe PR #14 to oddzielne zmiany. Nie scalać
  automatycznie do main i nie uruchamiać deployu na produkcję bez
  weryfikacji i kontroli konfliktów.

## Weryfikacja
1. Syntaktyczna walidacja nowego routera i `install.sh`.
2. Testy API: 401 bez tokenu, 403 STAFF, 200 OWNER, walidacja niedozwolonych
   danych oraz deduplikacja dwóch takich samych partii (bez podwójnego zapisu).
3. Po bezpiecznym wdrożeniu: /openapi.json zawiera GET i POST
   /mobile/diagnostics/caller. Wgląd OWNER do raportów.
4. Jedna końcowa kompilacja i podpis normalnej aplikacji, a potem standardowa
   aktualizacja na telefonie, bez bocznej instalacji.
