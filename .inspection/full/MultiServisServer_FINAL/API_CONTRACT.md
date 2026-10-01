# Multi-Servis API 2.0 – kontrakt pod aplikację Android

Backend obejmuje wszystkie funkcje uzgodnione dla aplikacji właściciela i przyszłych kont recepcji.

## System
- `GET /health`
- `GET /capabilities`
- `GET /docs`

## Autoryzacja / użytkownicy
- `POST /auth/login`
- `GET /auth/me`
- `POST /auth/set-my-password`
- `GET /users`
- `POST /users`
- `PATCH /users/{id}`

`AUTH_REQUIRED=false` pozwala rozwijać Androida bez logowania. Mechanizm logowania i ról jest już w kodzie; później wystarczy konfiguracja, bez dopisywania endpointów.

## Przyjęcia
- `GET /receptions?scope=active|completed|cancelled|all&search=...`
- `GET /receptions/{id}`
- `POST /receptions`
- `PATCH /receptions/{id}`
- `PATCH /receptions/{id}/status`
- `POST /receptions/{id}/notify-client`
- `GET /receptions/{id}/status-history`
- `GET/POST /receptions/{id}/notes`
- `GET/POST /receptions/{id}/media`
- `GET /receptions/media/{media_id}/content`
- `POST /receptions/{id}/ocr`

Numery przyjęć są nadawane centralnie przez PostgreSQL i startują codziennie od 11.

## Klienci
- `GET /clients?search=...`
- `GET /clients/by-phone/{phone}`
- `GET /clients/{id}`
- `PATCH /clients/{id}`
- `POST /clients/{id}/phones`

## Finanse prywatne właściciela
- `GET/PUT /receptions/{id}/finances`
- `GET /reports/finances?group_by=month|quarter|year`

Endpointy wymagają roli OWNER/ADMIN po włączeniu autoryzacji.

## Rozmowy i nagrania
- `GET/POST /calls`
- `GET /calls/match/{phone}`
- `PATCH /calls/{call_id}/attach/{reception_id}`
- `POST /calls/{call_id}/recording`
- `GET /calls/recordings`
- `GET /calls/recordings/{id}/content`
- `POST /calls/import-recording`

## SMS i opinie Google
- `GET/POST /sms`
- `GET/POST /reviews`
- `PATCH /reviews/{id}`

## Import telefonu
- `POST /imports/phone/bulk`

Obsługuje niesaved numery, ręcznie wybrane kontakty oraz historię połączeń. Nagrania mogą być importowane przez `/calls/import-recording`.

## Assist/Breeze – wspólny klient
- `GET /assist/client/{client_id}`

Zwraca instalacje Assist, licencje, alerty oraz powiązanie urządzenia z Breeze.

## Ustawienia
- `GET /settings`
