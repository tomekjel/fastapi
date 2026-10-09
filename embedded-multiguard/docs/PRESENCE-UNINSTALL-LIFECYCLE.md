# Multi-Guard — kontakt instalacji, wyszarzanie, deinstalacja i brak sygnału

Data ustalenia: 2026-10-09. Status: **wstępna implementacja statusów OWNER na gałęzi przeglądarkowej; nie wdrożono na produkcję**. Dalsze ograniczanie ruchu, komunikowanie wygasłych licencji i finalne usuwanie agenta wymagają osobnych zmian klienta Windows.

## Semantyka: trzy NIEWYMIENNE informacje

1. **Ważność licencji**: ACTIVE / EXPIRED / REVOKED, niezależnie od tego, czy komputer jest włączony i czy ma dostęp do sieci. Na panelu nie wolno utożsamiać ważnej licencji z aktywnym komputerem.
2. **Łączność z agentem**: `last_seen_at` (czas serwera przy poprawnie uwierzytelnionym heartbeat). Zielona kropka znaczy wyłącznie `ostatni kontakt w ciągu 24 h`, a NIE `klient obecnie włączył komputer`, `zalogował się` lub `jest online`. Ostatni kontakt zawsze z datą i godziną, oraz wersją MG.
3. **Sytuacja sprzętu**: historyczny poziom zdrowia GREEN/YELLOW/ORANGE/RED pochodzi z faktycznie otrzymanego pomiaru. Nie może się sam zamieniać w `CRITICAL` z powodu nieobecności komputera. Brak sygnału to `nieznane`, nie potwierdzenie awarii lub deinstalacji.

## Pasywne statusy (pierwsza implementacja na tej gałęzi)

- Świeży kontakt: <=24 h, zielona delikatnie świecąca kropka, etykieta `Kontakt w ciągu 24 h`.
- 1–7 dni: złota kropka, `Brak kontaktu 1–7 dni`.
- 7–30 dni: szara kropka, `Brak kontaktu 7–30 dni`.
- Ponad 30 dni: szara kropka, `Brak kontaktu ponad 30 dni`.
- Brak kiedykolwiek zarejestrowanego heartbeat: `Brak potwierdzonego kontaktu`.
- Odebrano podpisanym/uwierzytelnionym strumieniem zdarzeń `CLIENT_UNINSTALLED`
  z `reason=user_uninstall`, `source=windows_uninstaller`:
  `Odinstalowanie zgłoszone`, pozycja na końcu listy; nadal dostępna karta urządzenia, zdarzenia i historia napraw. Nie przesądza to nieodwołalnie tożsamości osoby wykonującej usunięcie; to raport o standardowym wywołaniu deinstalatora Windows.
- Po ponownej instalacji i poprawnym heartbeat dla tego samego `installation_id`: czyścimy aktywny znacznik odinstalowania, pozostawiamy zdarzenie historyczne. Przeniesienie na nowe urządzenie tworzy nowe powiązanie instalacji i nie przenosi historii innych urządzeń.

Nie zmieniamy teraz heurystyk health-state, raportów serwisowych ani edycji Standard/Pro. Zmiana dotyczy tylko właścicielskiego panelu i przyjęcia potwierdzonego zdarzenia.

## Co istnieje w Windows 0.3.35 (kod sprawdzony)

- `src-tauri/windows/hooks.nsh`: podczas **normalnej**, zatwierdzonej przez
  użytkownika deinstalacji wywołuje `Multi-Guard.exe --uninstall-notify`;
  podczas aktualizacji (UpdateMode) tego nie robi.
- `src-tauri/src/lib.rs::run_uninstall_notifier_if_requested` zapisuje
  `CLIENT_UNINSTALLED` do lokalnej kolejki i próbuje wysłać go przez
  `service_bridge::flush_outbox` z timeoutem 6 sekund.
- `src-tauri/src/lib.rs`: w działającym programie po pierwszym starcie
  wysyła `heartbeat` co 15 minut, a niezwiązane z licencją wykrywanie
  co minutę. W PRO osobny polling zdalnej pomocy co 12 sekund —
  to NIE jest heartbeat obecności, ale wymaga przyszłej optymalizacji
  (long-poll / SSE / push / rzadszy polling bez sesji).

## Uninstall OFFLINE: gwarancje i ograniczenia

**Nie można zagwarantować wysłania wiadomości po pełnym usunięciu aplikacji bez zostawienia dodatkowego komponentu, który w przyszłości miałby ją wysłać.**
Sama lokalna kolejka nie wyśle niczego po usunięciu programu.
Dlatego przy pełnej, czystej deinstalacji offline:
- próbujemy wysłać i potwierdzić zdarzenie PRZED zakończeniem deinstalacji,
- jeśli sieci nie ma, zapis może pozostać wyłącznie lokalnie i nigdy nie
  dotrzeć do serwera,
- nie oznaczamy wtedy PC jako potwierdzenie odinstalowany;
  pozostaje `brak kontaktu` z datą ostatniego heartbeat,
- ewentualne późniejsze ponowne zainstalowanie agenta może wysłać
  pozostałe zdarzenie, zależnie od zachowania danych i poświadczeń,
  ale tego nie gwarantujemy.

**Opcja rozwojowa** — jednorazowy *minimalny* helper wysyłający tylko
podpisany komunikat odinstalowania po odzyskaniu Internetu i usuwający
samego siebie po potwierdzeniu lub ustalonym terminie, bez zbierania
telemetrii. To NIE jest jeszcze zaakceptowana implementacja: pozostawia
czasowo plik/poświadczenie po deinstalacji, wymaga wyraźnej transparentności
dla klienta, audytu uprawnień, testów instalatora i bezpiecznego usuwania.
Nie wolno wprowadzać go jako ukrytego trwale działającego procesu.

Usunięcie dysku, czysta instalacja Windows, usunięcie katalogu, zniszczenie
systemu lub brak łączności nie uruchamiają poprawnej ścieżki deinstalatora.
Brak sygnału NIGDY nie pozwala rozpoznać, który z tych przypadków zaszedł.

## Projekt optymalizacji ruchu (nie wdrożony)

- Normalna komercyjna licencja: heartbeat po uruchomieniu usługi/agenta,
  potem proponowane co 6 godzin, z losowym niewielkim przesunięciem.
  Krytyczne zdarzenia można wysyłać natychmiast; nie czekają 6 godzin.
  Po odzyskaniu Internetu kolejka uzupełnia raporty z okresu, kiedy
  zbieranie danych było uprawnione.
- Serwis/diagnostyka STANDARD/PRO: nadal zbieramy pomiary odpowiednio do
  czasu badania, niezależnie od rzadkich heartbeatów obecności;
  dane wysyłamy w oszczędnych pakietach, ważne incydenty od razu.
- Nie potrzebujemy informacji `zalogowany`; nawet świeży heartbeat
  z procesu działającego w tle nie oznacza używania komputera przez osobę.
- Po wygaśnięciu licencji: zgodnie z projektem uśpienia Multi-Guard
  przestaje świadczyć ochronę/dalszą telemetrię. Panel zna koniec
  uprawnienia, nie zgłasza awarii z powodu zamierzonego uśpienia.
- PRO remote support ma własną semantykę `czekam na sesję`,
  wymagającą niskich opóźnień, ale nie musi pingować serwera co 12 s
  w nieskończoność przy nieaktywnej zdalnej pomocy. Optymalizacja
  potrzebuje odrębnych testów niezawodności.

## Widok kolejki i sortowanie

- Na początku instalacje z wymagającymi uwagi faktycznymi zdarzeniami
  i nieprzeczytanymi alertami, następnie aktualnie kontaktujące się,
  dalej brak kontaktu, wygasłe/uśpione, na końcu zgłoszone usunięcia.
- Ręczne filtry: `Wszystkie`, `Wymagają uwagi`, `Aktywne licencje`,
  `Brak kontaktu`, `Wygasłe`, `Odinstalowane`, i wyszukiwanie.
  Pierwsza wersja ma status i automatyczne przeniesienie zgłoszonej
  deinstalacji na koniec; pełna konfiguracja filtrów to kolejny etap.
- Żaden rekord nie jest trwale usuwany tylko dlatego, że aplikacja
  zniknęła. Historia fizycznego sprzętu zostaje w Multi-Servis.

## Testy przed wdrożeniem

- Normalna deinstalacja online -> dokładnie jeden raport, pojawia się
  w powiadomieniach OWNER i na końcu listy; aktualizacja EXE NIE jest
  raportowana jako usunięcie.
- Deinstalacja offline -> brak fałszywego potwierdzenia; pojawia się
  `brak kontaktu`, data ostatniej synchronizacji pozostaje.
- Nagła awaria HDD, brak Internetu, celowe wyłączenie komputera, sen /
  hibernacja -> brak fałszywego `świadomie odinstalowano`.
- Reinstall / powrót heartbeat -> znacznik odinstalowania znika, historia
  deinstalacji pozostaje.
- Expired/revoked -> brak funkcji MG i zgodność z zaplanowanym tray UX,
  bez wyłączania Windows Defender; ten element jeszcze niewdrożony.
- Wydajność: test z tysiącem instalacji, dużo zdarzeń i właścicielska lista
  nie wymagają skanowania `guard.events` dla każdej pozycji.

## Serwisowa licencja diagnostyczna — częstsze raportowanie

- Poprawna nazwa: **SERWISOWA / DIAGNOSTYCZNA**, nie „testowa”.
  Ten sam Multi-Guard, niezależnie od tego, czy działa w warsztacie,
  czy u klienta, i niezależnie od edycji Standard/Pro.
- Proponowany harmonogram specjalnie dla aktywnej licencji
  diagnostycznej: próbki lokalnie co **5–10 sekund**, pakiet danych
  na serwer co **60 sekund**, szczegółowe zestawienie zdarzeń co
  **5 minut**, istotny alert możliwie natychmiast.
- Diagnostyczny pakiet wysłany do serwera może zarazem potwierdzić
  „ostatnio widziany” — nie potrzebuje równoległych pingów obecności.
- Komercyjna licencja ma oszczędniejszy harmonogram, ale ważne
  alerty też nie mogą czekać wiele godzin na kolejny heartbeat.
- Zasada oszczędności: limity kolejki i wysyłki, pakietowanie,
  deduplikacja błędów, ograniczenie rozmiaru i retencji danych;
  wykrywanie problemów nie może samo pogarszać pracy sprzętu.
- To są ZAŁOŻENIA, NIE działający kod. Obecna implementacja klienta
  używa 15-minutowego heartbeat, nie rozróżnia jeszcze licencji
  komercyjnej i serwisowo-diagnostycznej w wysyłaniu raportów.
