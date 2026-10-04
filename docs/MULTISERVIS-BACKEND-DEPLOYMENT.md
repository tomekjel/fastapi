# Wdrożenie backendu Multi-Servis / Multi-Guard

Ten dokument dotyczy wdrożenia nowych endpointów Multi-Guard używanych przez aplikację Android Multi-Servis 1.7.

## Stan kodu

Kod backendu i instalator są w repozytorium `tomekjel/fastapi`.

Instalator:

`embedded-multiguard/install.sh`

Workflow ręcznego wdrożenia:

`.github/workflows/deploy-multiservis-backend.yml`

Workflow nie uruchamia się po zwykłym pushu. Wdrożenie wymaga ręcznego uruchomienia i wpisania dokładnie `DEPLOY`.

## Jednorazowa konfiguracja GitHub

W repozytorium trzeba dodać sekrety:

- `MULTISERVIS_BACKEND_HOST` — adres SSH serwera/kontenera dostępny z runnera GitHub Actions,
- `MULTISERVIS_BACKEND_PORT` — port SSH; jeśli pusty, używany jest 22,
- `MULTISERVIS_BACKEND_USER` — użytkownik SSH,
- `MULTISERVIS_BACKEND_SSH_KEY` — prywatny klucz SSH.

Użytkownik musi być rootem albo mieć bezhasłowe `sudo` dla operacji wykonywanych przez instalator.

Jeżeli serwer nie jest osiągalny z publicznych runnerów GitHub Actions, workflow nie będzie mógł połączyć się po SSH. Wtedy nadal można użyć tego samego `install.sh` bezpośrednio na serwerze.

## Co robi instalator

1. Tworzy backup `main.py` oraz istniejących routerów Multi-Guard.
2. Pobiera router licencji i runtime z dokładnego wskazanego commita.
3. Instaluje wymaganą bibliotekę `cryptography`.
4. Wpina oba routery do FastAPI.
5. Sprawdza składnię Pythona przed restartem.
6. Restartuje `multiservis-api.service`.
7. Czeka na powrót endpointu `/health`.
8. Sprawdza produkcyjny `openapi.json`, w tym Centrum OWNER, heartbeat/event i `releaseChannel`.
9. Przy błędzie automatycznie przywraca poprzednie pliki i restartuje usługę.

## Wymagane trasy po poprawnym wdrożeniu

- `/multiguard/licenses/receptions/{reception_id}`
- `/multiguard/licenses/receptions/{reception_id}/generate`
- `/multiguard/licenses/receptions/{reception_id}/release-channel`
- `/multiguard/overview`
- `/multiguard/notifications`
- `/multiguard/support-requests`
- `/multiguard/agent/heartbeat`
- `/multiguard/agent/event`
- `/multiguard/events/{event_id}`

Po wdrożeniu `GenerateLicenseRequest` musi zawierać pole `releaseChannel`.

## Test po wdrożeniu

Po zielonym workflow należy na telefonie odświeżyć ekran:

**Multi-Guard → Centrum właściciela**

Błąd `HTTP 404 {"detail":"Not Found"}` nie powinien się już pojawiać. Następnie można przetestować zapis kanału Stabilna/Beta oraz dalszą integrację z Multi-Guard dla Windows.
