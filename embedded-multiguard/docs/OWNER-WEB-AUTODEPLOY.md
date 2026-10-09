# Multi-Servis — automatyczne wdrażanie wyłącznie panelu przeglądarkowego OWNER

Stan: mechanizm opracowany 2026-10-09. **Do pierwszego wdrożenia agenta potrzebne jest jednorazowe uruchomienie instalatora z kontenera FastAPI**, którego dotychczasowy panel to commit `892a8c66e1e3cae662136ddf1360bf880b785ba8`.

## Po co

Właściciel ocenia i akceptuje wygląd/funkcje panelu WWW w rozmowie. Dalsze instalacje nie wymagają logowania do Proxmoxa lub ręcznego przeklejania komend. Agent działa wyłącznie z kontenera `fastapi` i wykonuje wychodzące połączenia HTTPS do GitHub. Nie otwiera portów, nie przechowuje SSH ani hasła do bazy lub panelu w GitHubie.

**Nie jest to zdalna powłoka ani nieograniczony dostęp administratora do serwera.** Umożliwia tylko zatwierdzone zmiany z ustalonego repozytorium, po zdanym CI, w osłoniętym zestawie modułów WWW i z kopią/rollbackiem.

## Mechanizm

1. `/usr/local/libexec/multiservis-owner-v12-agent.py` odpala timer systemd co ok. 5 minut. Uruchamiana lokalna kopia programu i skryptu wdrożeniowego jest przypięta do niezmiennego commita; manifest nie może podać nazwy polecenia, ścieżki skryptu ani dowolnego adresu.
2. Pobiera publiczny plik `embedded-multiguard/deploy/owner-v12-release.json` z gałęzi `multiservis-panel-multiguard-gold-crimson-v1`. Początkowo `sequence=0` i `target_sha=892a8c...` oznaczają wyłącznie **już zainstalowaną** wersję: agent po instalacji nie robi wdrożenia.
3. Gdy właściciel zaakceptuje **konkretną** nową wersję WWW, osoba wykonująca zmianę po pozytywnym CI podnosi `sequence` i wpisuje pełny 40-znakowy SHA tego zatwierdzonego commita do `target_sha`. Zwykłe commity lub testy NIE uruchamiają wdrożenia.
4. Agent dopuszcza jedynie SHA z gałęzi docelowej i potwierdzony `success` całego workflow `multiservis-panel-preview-ci.yml` (testy PostgreSQL, przeglądarkowe, ochrony zdjęć, praw). Sprawdza też, że wszystkie zmiany od ostatniego wdrożenia mieszczą się w liście dopuszczonych plików. Zmiany w Android, aktualizacjach klienta Windows, Cloudflare i obcych komponentach są blokowane.
5. Stały skrypt `deploy-owner-web-v12.sh` wykonuje read-only kontrolę tabel i magazynu zdjęć, sprawdza nienaruszalność definicji istniejących punktów API, zabezpiecza pliki, wdraża tylko kod panelu, sprawdza `/health` i wymagane adresy API; w razie błędu przywraca stare pliki.
6. Udane wdrożenie zapisuje `applied_sha` i numer manifestu na dysku lokalnym (`/var/lib/multiservis-owner-v12/state.json`). Nieudana próba jest wstrzymana — ponowna próba tego samego żądania nie restartuje serwera w kółko. Nowy numer manifestu wymaga świadomej decyzji.

## Instalacja / obsługa

Jednorazowe uruchomienie `embedded-multiguard/install-owner-v12-agent.sh` jako `root` na LXC 103 `fastapi`, wskazując przetestowany pełny SHA źródeł. Instaluje usługę i timer. Nie rusza bieżącej aplikacji. W razie problemu bootstrap kończy się błędem i nie zmienia stanu backendu, ponieważ pierwsze wywołanie agenta jest wyłącznie kontrolą no-op.

Podstawowa kontrola stanu (tylko dla administratora serwera):
```sh
systemctl status multiservis-owner-v12-pull.timer
journalctl -u multiservis-owner-v12-pull.service -n 30 --no-pager
```

Wyłączenie automatycznych instalacji bez ruszania aplikacji:
```sh
systemctl disable --now multiservis-owner-v12-pull.timer
```

Nie należy dodawać haseł lub prywatnego klucza SSH do manifestu, wiadomości, repo lub raportów CI. Skompromitowanie uprawnień zapisu do gałęzi repozytorium może umożliwić publikację kodu, dlatego publikowanie wymaga uzgodnionej kontroli commita i pozytywnych testów.

## Zakres

Dostęp obejmuje tylko część WWW OWNER. Nie obejmuje Android OWNER/STAFF, modułów Windows Multi-Guard, konfiguracji Proxmox, zawartości prywatnych dokumentów ani dowolnych poleceń shell. Produkcyjny backend i baza pozostają w normalnej eksploatacji; w czasie samego wdrożenia następuje krótki restart API.
