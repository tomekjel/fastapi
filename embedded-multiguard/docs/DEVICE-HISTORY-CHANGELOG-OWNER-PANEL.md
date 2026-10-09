# Multi-Servis × Multi-Guard: historia wersji, sprzętu i analiza problemów

Status: przygotowanie panelu do testów. **Nie wdrożono na serwer produkcyjny.**
Cel: jedna karta fizycznego komputera łączy instalację Multi-Guard, sygnały
telemetrii i faktyczne zlecenia serwisowe, również gdy nie ma historii napraw.

## Nawigacja i źródła danych (pierwsza implementacja na tej gałęzi)

- `/multiguard/panel/dashboard`: zarejestrowane instalacje, problemy,
  liczba rzeczywistych wpisów serwisowych oraz przejście do konkretnego PC.
- `/multiguard/panel/device/{installation_id}`: licencja, kanał i wersja,
  zdarzenia Multi-Guard, zgłoszenia, wizyty i zlecenia z `service.service_orders`
  dopasowane **wyłącznie przez `guard.installations.service_device_id =
  service.service_orders.device_id`**.
- `/multiguard/panel/service/{order_id}`: karta serwisowa — opis, notatki,
  statusy, finanse i METADANE załączników; z niej wracamy do listy zleceń.
- `/multiguard/panel/versions`: BETA (`PILOT`) i STABLE z faktycznej tabeli
  `guard.release_versions`, wraz z zapisanym opisem zmian i stanem wydania.
  Wewnętrzne TEST/LICENSE_TEST nie występują na zwykłej liście wersji.

Jeżeli komputer nie ma żadnego wpisu `service.service_orders`, pokazujemy
`Brak powiązanych wizyt lub napraw`. Samo posiadanie licencji nie jest
dowodem naprawy. Nigdy nie wnioskujemy automatycznie o tożsamości urządzenia
wyłącznie z nazwy hosta, numeru seryjnego lub numeru telefonu.

## Rozbieżność ujawniona w istniejącym backendzie: licencja bez naprawy

Obecnie `guard.license_links.reception_id` jest obowiązkowe, a wystawienie
licencji wymaga `service.service_orders`. Nie wolno generować fikcyjnego
zlecenia naprawy dla sprawnego PC kupującego wyłącznie Multi-Guard.

**Wymagane osobne zadanie migracyjne przed wdrożeniem tego procesu**:
1. Umożliwić samodzielną kartę `core.devices` i legalną sprzedaż/instalację
   Multi-Guard bez rekordu `service.service_orders`.
2. Zachować kompatybilność istniejących licencji i powiązań z dotychczasowymi
   zleceniami; nie przerywać ważności aktywnych licencji i nie nadpisywać
   `service_device_id`.
3. Zastąpić obowiązkową zależność `guard.license_links.reception_id`
   opcjonalnym powiązaniem ze zleceniem oraz osobnym typem źródła
   `SERVICE_ORDER` / `LICENSE_ONLY` i unikalną tożsamością licencji.
4. Przejrzeć: wystawianie KeyGate, generowanie tokenu, przypisanie oczekującej
   instalacji, SERVICE_TEST, akceptację dokumentów, przeniesienie licencji,
   raporty owner i księgowanie. Zrobić migrację i testy transakcyjne przed
   wdrożeniem. Nie osłabiać weryfikacji podpisu/licencji.
5. Klient przychodzący wyłącznie po Multi-Guard nie powinien otrzymać
   sztucznej historii naprawy. Może mieć historię **zakupu/instalacji**.

## Zdjęcia i dostępność archiwum

W wersji testowej panel widzi liczbę i metadane plików dołączonych do zleceń;
nie renderuje jeszcze prywatnych zdjęć. Aby pokazać ich miniatury i pełny
podgląd należy wykonać osobny chroniony endpoint/adapter z kontrolą OWNER,
który korzysta z istniejącego mechanizmu odczytu obiektów w
`core.storage_objects`. Nie wolno publikować samych `object_key`,
ścieżek dyskowych, publicznych folderów lub bezterminowych adresów plików.
Sprawdzić istniejące trasy serwera Multi-Servis i implementację dostępu do
plików przed podjęciem decyzji o adapterze.

## Dalszy rozwój: diagnostyka i poprawki oparte na zdarzeniach

- Rejestrować błędy z `guard.events` wraz z instalacją, wersją programu,
  kanałem, modułem, czasem, klasą błędu i minimalnymi metadanymi.
- W panelu właściciela obsługa zgłoszenia: **Nowe / Analizowane /
  Potwierdzone / Fałszywy alarm / Naprawione**.
- Łączyć podobne problemy w jedną klasę diagnostyczną; pokazywać ile różnych
  komputerów dotyczy problemu i od jakiej wersji występuje.
- Dodawać notatkę diagnostyczną i powiązanie z wersją BETA, która naprawiła
  problem. Bez samodzielnego wykonywania niezweryfikowanych zmian na sprzęcie
  klienta.
- Oddzielać błędy aplikacji od rzeczywistych usterek sprzętowych; anomalie
  sprzętowe nie są dowodem awarii podzespołu.
- Zbierać tylko dane potrzebne do diagnostyki, bez niepotrzebnych danych
  osobowych i bez automatycznego kopiowania prywatnych plików klientów.

## Wymagania historii wydań

Opis wydania musi być konkretny i oparty na rzeczywistych commitach/testach.
Dla wpisu w `guard.release_versions.notes` można już zapisać np.:

    ADDED: Podgląd wizyt serwisowych przypisanych do urządzenia.
    FIXED: Naprawiono obliczanie statusu wybranego czujnika.
    CHANGED: Ujednolicono ekran aktualizacji.
    REMOVED: Wyłączono przestarzały przycisk.
    SECURITY: Zmieniono kontrolę dostępu do raportów.

To są PRZYKŁADY FORMATU, nie opis faktycznie wydanej wersji.
Parser panelu pokaże etykietę `Dodano/Naprawiono/Zmieniono/Usunięto`.
Brak notatki to `Brak opisu zmian`, nigdy automatycznie wymyślone zmiany.
Zapisana historia STABLE musi odnosić się do zamrożonej rewizji, a BETA
nigdy nie staje się automatycznie STABLE.

## Warunki odbioru

- PC bez zleceń: brak fikcyjnej naprawy, widoczna licencja i telemetria.
- PC z co najmniej dwiema wizytami: pokazane wszystkie powiązane zlecenia,
  stan, opis, liczba plików, przejście do karty zamówienia.
- Dwa różne komputery o takim samym modelu/serialu/hostname nie mogą
  zobaczyć nawzajem cudzej historii (wiązanie tylko po UUID z bazy).
- Zmiana lub transfer licencji nie może usuwać historii fizycznego urządzenia.
- Historyczny wpis zlecenia nie jest automatycznie oznaczany `naprawa`,
  jeżeli był to tylko zakup lub instalacja.
- Historia wydań nie pokazuje wewnętrznych TEST jako produkcyjnego STABLE.
- Pełne zdjęcia widoczne jedynie po dodatkowym testowanym module bezpiecznego
  dostępu — obecnie funkcja nieukończona.
- Integrację danych i przepływy OWNER przetestować na testowej bazie przed
  wdrożeniem na żywych danych.
