# MultiGuard — dokumenty aktywacyjne (projekt, NIE DO PUBLIKACJI)

## Stan i zasady
W panelu OWNER licencja DIRECT Standard/Pro jest nadawana w stanie `SERVICE_TEST`. Oddzielne przekazanie zmienia ją na `PENDING_ACCEPTANCE`. W trakcie odświeżania klient otrzymuje dokładnie trzy dokumenty z `MULTIGUARD_REQUIRED_DOCUMENTS`. Po zweryfikowanej akceptacji serwer nadaje `ACTIVE` i ustawia daty ważności. Klucz i instalacja nie zmieniają się.

Nie ustawiać `ACTIVE` ręcznie, nie wpisywać fikcyjnego `accepted_at`, nie tworzyć duplikatu licencji, nie rozpoczynać naliczania okresu przed akceptacją. Dane Lenovo i klucze produkcyjne nie są częścią niniejszego pliku.

## Schemat konfiguracji (bez treści)
Konfiguracja jest listą **dokładnie trzech** obiektów z polami:
- `kind`: unikalny techniczny identyfikator dokumentu;
- `version`: numer wersji;
- `title`: tytuł widoczny klientowi;
- `content_markdown`: **pełna, zatwierdzona treść** dokumentu (nie tytuł ani placeholder).

Backend liczy SHA-256 treści, przesyła ją do aplikacji i porównuje rodzaj, wersję oraz skrót przy akceptacji.

Źródłem ustawienia jest środowisko `MULTIGUARD_REQUIRED_DOCUMENTS` (JSON) lub odpowiedni klucz w JSON konfiguracji MultiGuard. Zmianę wprowadzać dopiero po zatwierdzeniu dokumentów. Testować na staging i sprawdzić `_required_documents()` = 3 przed wdrożeniem.

## Trzy dokumenty do opracowania i zatwierdzenia
1. Regulamin i warunki licencji MultiGuard (Standard/Pro, 3/6/12 miesięcy, aktualizacje, reklamacje, odstąpienie konsumenta, zdalna pomoc).
2. Polityka prywatności (pełne dane administratora, kontakt, cele i podstawy prawne, kategorie danych, odbiorcy, transfery, okresy przechowywania, prawa użytkownika, zabezpieczenia).
3. Informacja o monitorowaniu, diagnostyce i funkcjach zdalnych (co jest niezbędne do realizacji umowy, co jest opcjonalne, zasady zgody na konkretną sesję).

**Uwaga prawna**: zapoznanie się z polityką prywatności nie jest równoznaczne ze zgodą na każde przetwarzanie. Dobrowolne zgody wymagają niezależnych, domyślnie niezaznaczonych kontrolek oraz możliwości późniejszego wycofania. Aktualny protokół akceptacji przewiduje jeden zbiorczy zestaw trzech potwierdzeń i **nie modeluje** niezależnych opcjonalnych zgód — nie używać trzeciego dokumentu do wymuszania takich zgód. Jeśli będą potrzebne, rozbudować osobno API i klienta.

## Kontrola przed produkcją
- Zatwierdzone treści (bez pól do uzupełnienia), zidentyfikowany przedsiębiorca i komplet informacji RODO.
- Rzeczywisty przepływ danych i retencja sprawdzone z kodem oraz konfiguracją serwera.
- Staging: dokumenty po przekazaniu, komplet trzech treści, odrzucenie zmodyfikowanego SHA lub starszej wersji, brak aktywacji bez dokumentów.
- Po akceptacji: identyfikator licencji bez zmian; `ACTIVE`, `accepted_at`, `valid_from` oraz `valid_until` zgodne z 3/6/12 miesiącami; następnie test Standard → Pro oraz przedłużenia.
- Nie publikować draftów jako wiążących dokumentów.
