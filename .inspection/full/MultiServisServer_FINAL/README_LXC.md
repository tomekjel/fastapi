# MultiServisServer FINAL – Debian 12 LXC

To jest kompletna wersja FastAPI przygotowana pod uzgodnioną funkcjonalność aplikacji Android Multi-Servis. Po wdrożeniu dalsza praca nad Androidem ma polegać na podpinaniu istniejących endpointów, bez dopisywania serwera dla funkcji już objętych tym kontraktem.

## Wymagania
- LXC Debian 12
- połączenie z VM PostgreSQL (obecnie `192.168.1.202:5432`)
- baza utworzona z finalnego `schema.sql`

## Instalacja
Po skopiowaniu katalogu do LXC jako root:

```bash
bash install_lxc.sh
```

Instalator:
- instaluje Python/venv,
- kopiuje backend do `/opt/multiservis`,
- instaluje zależności,
- tworzy storage,
- uruchamia usługę `multiservis-api`,
- włącza autostart po restarcie LXC.

## Kontrola

```bash
systemctl status multiservis-api
```

```bash
curl http://127.0.0.1:8000/health
```

Swagger:
`http://ADRES_LXC:8000/docs`

## Konfiguracja
`.env` zawiera połączenie z PostgreSQL. Kod nie wymaga zmian przy przeniesieniu z Windows na LXC.

`AUTH_REQUIRED=false` jest celowe na czas rozwijania Androida. Autoryzacja, użytkownicy i role są już zaimplementowane. Po przejściu na logowanie nie trzeba dopisywać backendu – jedynie ustawić konfigurację i użyć istniejącego `/auth/login` w Androidzie.

## Zakres
Pełna lista istniejących endpointów znajduje się w `API_CONTRACT.md` oraz automatycznie w `/docs`.
