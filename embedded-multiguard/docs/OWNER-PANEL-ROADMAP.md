# Multi-Servis × Multi-Guard — kanoniczna mapa wdrożenia panelu OWNER
Ustalenia właściciela: 9 października 2026. Status: **gałąź testowa; produkcyjny backend i aplikacja Android bez zmian**.

## Zatwierdzona reguła wizualna — panel tylko dla OWNER

- **Jedna aplikacja WWW Multi-Servis, jedna edycja dla właściciela.**
  Nie istnieją osobne Standard/Pro dla panelu administratora;
  Standard i Pro są wyłącznie cechami instalacji Multi-Guard u klienta.
- Stylistyka spokrewniona z zaakceptowanym Multi-Guard V12: ciemny
  granat, cienkie metaliczne złote i karmazynowe akcenty,
  delikatny relief i glow, wysoka jakość materiału bez kopiowania
  tarczy ani jej układu na każdą stronę.
- **Liternictwo regularne, bez pogrubionych fontów**, teksty użyteczne
  ~15–16 px lub większe, wyraźne nagłówki o grubości 400,
  brak miniaturowych etykiet, czytelne formularze i tabele.
- Każda funkcja zachowuje własny układ: pulpit operacyjny, techniczna
  karta urządzenia, lista zleceń, analityka zdarzeń, historia wydań,
  licencje i konfiguracja. Żadnego automatycznego kopiowania siatki
  kafli we wszystkich ekranach.
- Wspólne wizualne tokeny są w
  `app/routers/multiguard_panel_theme.py` (`PANEL_CSS`).
  Wspólny szkielet, nawigacja i znak marki:
  `multiguard_license.py::_panel_html`.
  Dzięki temu kolejne warianty wizualne nie wymagają przebudowy
  licencjonowania ani logiki serwisu.
- W GitHub CI rzeczywista przeglądarka Chromium renderuje HTML+CSS
  pochodzące z produkcyjnie używanego renderera, **na jawnie
  fikcyjnych danych poglądowych**, dla desktop i mobile.
  Te obrazy nie są screenshotem live backendu. Realne screenshoty
  serwera i test dostępu do klientów są osobnym etapem wdrożeniowym.
- W przyszłości aplikacja Android Multi-Servis ma uzyskać spójny styl
  rodziny, lecz nie jest modyfikowana w tej transzy.

## Kierunek architektury: nie „przespawane” ekrany
- Ten sam fizyczny komputer (`core.devices.id`) jest osią relacji pomiędzy
  naprawą, zdjęciami, instalacją programu, licencjami, incydentami i powrotami
  serwisowymi. Powiązanie nie może opierać się wyłącznie na modelu, hostname,
  numerze seryjnym ani nazwisku.
- Oddzielne moduły WWW: `multiguard_runtime.py` (stany i telemetria),
  `multiguard_service_panel.py` (tylko czyta zlecenia),
  `multiguard_panel_settings.py` (zmienne progi/lista + dziennik zmian),
  `multiguard_panel_devices.py` (notatki i priorytety OWNER + audyt),
  `multiguard_updates.py` (kanaliki i manifesty),
  `multiguard_license.py` (podpisana autoryzacja).
- Stosować istniejący wygląd V12 panelu (ciemny granat, metaliczne złoto,
  delikatna czerwień), ale niezależne układy dla różnych funkcji, nie
  kopiować siatki dashboardu Multi-Guard do wszystkich stron.
- Każda nowa funkcja ma osobny moduł i test migracji/kontraktów; dane starego
  klienta pozostają kompatybilne. Zmiany produkcyjnej bazy danych i
  publikacje release'ów muszą mieć pełne kopie i zatwierdzenie OWNER.

## Stan gałęzi preview: kod wykonany
1. Dashboard: licencje, ostatni kontakt, stan techniczny, licznik historii
   serwisowej, liczba zdarzeń, bez zgadywania online/zalogowania.
2. Linki z instalacji Multi-Guard do powiązanych fizycznie napraw,
   w tym braku historii napraw, z dalszym przejściem do karty zlecenia.
3. Historia BETA/STABLE z rzeczywistych wpisów katalogu serwerowego;
   osobne etykiety Dodano/Naprawiono/Zmieniono/Usunięto.
4. Potwierdzone przez standardowy deinstalator Windows zdarzenie
   `CLIENT_UNINSTALLED` trafia do powiadomień, a komputer na koniec
   listy; brak kontaktu nie oznacza świadomej deinstalacji.
5. Dashboard: wyszukiwanie urządzeń i stronicowanie z ograniczeniem
   liczby widocznych pozycji; filtry kontaktu i deinstalacji.
6. OWNER może zmieniać przez chroniony formularz czas świeżego
   kontaktu, próg nieobecności, limit wierszy; zmiany zapisane do
   `guard.owner_panel_settings_audit`.
7. Na karcie urządzenia OWNER może dodać/zmienić prywatną notatkę
   oraz priorytet NORMAL/WATCH/URGENT; audyt zapisany osobno,
   ważne pozycje wyżej w zestawieniu, odinstalowane nadal na dole.
8. Wdrożenie instalatorem backendowym ma ścieżkę backupu modułów;
   GitHub CI sprawdza źródła, lecz **nie jest jeszcze testem live DB**.

## Stan niewykonany, nie udawać że działa
- Wyświetlanie pełnych prywatnych zdjęć ze zleceń w WWW: obecnie tylko
  lista plików. Potrzebny endpoint z kontrolą OWNER, odczyt magazynu,
  test dostępu i retencji.
- Wystawienie zwykłej licencji dla komputera bez zlecenia serwisowego:
  stary `guard.license_links.reception_id` wymaga zlecenia; bezpieczna
  migracja musi poprzedzić funkcję.
- Licencja SERWISOWA/DIAGNOSTYCZNA Standard/Pro, przedłużana 7/14 dni
  bez KeyGate i bez zmiany EXE; wymaga podpisanego, odrębnego typu
  licencji i testów. Nie ma osobnej edycji „testowej”.
- Intensywna telemetria z serwisowej licencji: docelowe propozycje
  5–10 s próbkowanie, co 60 s pakiet, co 5 min raport, krytyczne
  zdarzenia od razu. Aktualnie agent używa heartbeat 15 min.
- Konfiguracja harmonogramów monitoringu z panelu dopiero, kiedy
  rzeczywisty agent potrafi bezpiecznie odbierać/walidować profile.
- Historia decyzji o incydentach (triage), etykiety przyczyn, korelacja
  z commitami BETA i liczby dotkniętych komputerów do dodania.
- Wizualny odczyt pełnej telemetrycznej osi czasu 7/14 dni w zleceniach
  nie jest ukończony.
- Automatyczny rollback BETA, 7-dniowe wygaszanie ikony tray oraz
  ponowna aktywacja bez GUI — wymagają zmian Multi-Guard Windows.
- Odinstalowanie offline bez ponownego uruchomienia agenta nie może
  gwarantować dostarczenia komunikatu; nie podszywać się pod potwierdzenie.
- Publikacja prawdziwej STABLE nie może polegać na przemianowaniu starej
  TEST-preview ze skrótem licencyjnym dev.

## Kolejność prac i bramki wydania
**FAZA P (teraz): panel OWNER.**
Test źródeł, warstwa konfiguracji i historii, notatki, wyszukiwarka,
zdarzenia; wykonać kontrolowane testy end-to-end na kopii bazy,
sprawdzić uprawnienia OWNER, zdjęcia, przeglądarki i wpływ na Androida.
Dopiero po pełnej walidacji + backup + zgodzie właściciela publikować na
serwerze; wdrożenie skryptu `install.sh` restartuje backend i uruchamia
synchronizację wydań, więc jest operacją produkcyjną wysokiego ryzyka.

**FAZA B: Multi-Guard 0.3.35 BETA.**
Osobna licencjonowana kompilacja bez dev bypass, kanał serwerowy
`PILOT` (UI: BETA), test fizycznego Windows, kopia stanu
`C:\ProgramData\Multi-Guard` i przywracanie wersji. Nie usuwać
istniejącego TEST-preview przed zweryfikowaniem procesu BETA.

**FAZA S: STABLE.**
Po zaakceptowaniu przez właściciela zamrozić commit BETA, podpisać
nowe wydanie, przeprowadzić testy licencji/Windows/SQLite i publikować
partiami. Pozostawić niezależną gałąź BETA do eksperymentowania.
Dopiero wtedy zakończyć publiczne oferowanie `TEST/LICENSE_TEST`,
z zachowaniem bezpiecznych archiwów do odzyskiwania.

## Kryteria testów fazy P
- Model i numer seryjny identyczne na dwóch różnych komputerach
  nie mieszają danych właściciela; powiązanie po UUID.
- Instalacja bez historii serwisowej: nie tworzy fikcyjnej naprawy.
- 1000+ rekordów: wyszukiwanie i 50-wierszowa paginacja nie blokują UI.
- Zmiana progów przez OWNER działa bez restartu i nie zmienia
  licencji ani harmonogramu agenta.
- POST bez CSRF zwraca 403, nieautoryzowane żądania 401,
  dane w HTML są escapowane, próba SQL injection pozostaje tekstem.
- Zapis prywatnej notatki nie zmienia zdarzeń klienta ani
  jego licencji; istotne komputery sortowane na górze.
- Zdarzenie deinstalowania generuje flagę i powiadomienie tylko
  po odbiorze z autoryzowanego agenta.
- Migracje na istniejącej bazie są idempotentne; rollback kodu
  zachowuje dane audytowe i nie uszkadza Androida.

## Transza 1 — uaktualnienie (9 października 2026)

- Zatwierdzono i zakodowano wspólny design system V12 panelu WWW oraz
  jeden układ OWNER, bez rozdzielania administratora na Standard/Pro.
- Nowa typografia normal-weight, boczna nawigacja desktop,
  pozioma mobilna, wyraźne karty, przeznaczone dla funkcji widoki.
- Gotowe jest źródłowe renderowanie 7 ekranów poglądowych z **danymi
  fikcyjnymi**, sprawdzane screenshotami Chromium w GitHub Actions.
- Status: testowana gałąź, **nie publikowana produkcyjnie**;
  sprawdzenie rzeczywistych danych, widoku zdjęć i integracji z
  Androidem nadal wymagane. Bramka wdrożenia i kopia serwera
  pozostają obowiązkowe.
