#!/usr/bin/env python3
"""Render REAL common owner panel HTML + CSS into clearly labelled demo fixtures.

For visual review only. The data below are fictitious and deliberately marked.
Production routes are not called and no real client data are accessed.
"""
from __future__ import annotations
import ast
import html
import sys
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("owner-preview")
OUT.mkdir(parents=True, exist_ok=True)


def render_fn():
    theme = ast.parse((BASE/"app/routers/multiguard_panel_theme.py").read_text())
    assignments = [x for x in theme.body if isinstance(x, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id=="PANEL_CSS" for t in x.targets)]
    namespace = {}
    exec(compile(ast.Module(body=assignments, type_ignores=[]), "panel-theme", "exec"), namespace)
    src = ast.parse((BASE/"app/routers/multiguard_license.py").read_text())
    fn = next(x for x in src.body if isinstance(x, ast.FunctionDef) and x.name=="_panel_html")
    exec(compile(ast.Module(body=[fn],type_ignores=[]), "panel-render", "exec"),namespace)
    return namespace["_panel_html"]


render = render_fn()
notice = '<p class="muted"><span class="badge mg-gold">PREVIEW</span> Dane przykładowe — demonstracja rzeczywistego szablonu HTML/CSS, nie podgląd produkcyjnej bazy.</p>'
def section(title, text, inner, classes=""):
    return f'<section class="card {classes}"><div class="section-head"><div><h2>{title}</h2><p>{text}</p></div></div>{inner}</section>'
def metric(title,n,tone):
    return f'<div class="metric accent-{tone}"><b>{title}</b><strong>{n}</strong></div>'
def table(headers,rows):
    return '<div class="table-wrap"><table><thead><tr>'+''.join(f'<th>{h}</th>' for h in headers)+'</tr></thead><tbody>'+''.join('<tr>'+''.join(f'<td>{v}</td>' for v in row)+'</tr>' for row in rows)+'</tbody></table></div>'

devices = [
    ("MG-46AA72B4","Lenovo ThinkPad T14","SERWIS · PRO","0.3.35","Kontakt w ciągu 24 h","WHEA · 2","W obserwacji"),
    ("MG-945BD1FA","Dell Latitude 5420","STANDARD","0.3.35","Kontakt w ciągu 24 h","Brak","Prawidłowy"),
    ("MG-628FF09B","HP Pavilion 15","PRO","0.3.34","Brak kontaktu do 7 dni","Kernel-Power · 1","Sprawdzić"),
    ("MG-187DDB15","Acer Aspire A515","SERWIS · STANDARD","0.3.35","Odinstalowanie zgłoszone","—","Archiwalny"),
]
rows=[
    (f'<a class="strong-link" href="#">{i}</a>',name,f'<span class="badge mg-gold">{lic}</span>' if 'PRO' in lic else f'<span class="badge mg-red">{lic}</span>',
     vers,f'<span class="presence-label"><span class="presence-dot presence-{"removed" if "Odinstalowanie" in last else ("recent" if "24" in last else "delayed")}"></span>{last}</span>',
     issue,status) for i,name,lic,vers,last,issue,status in devices
]
dashboard=f"""
<section class="card panel-hero dashboard-hero">
 <div class="eyebrow">MULTI-SERVIS / CENTRUM WŁAŚCICIELA</div>
 <h1>Pulpit</h1>
 <p>Aktualny stan serwisu i Multi-Guard. Kliknij oczekujące instalacje, aby przypisać licencję.</p>
 {notice}
 <div class="metrics">
 {metric("Aktywne komputery","124","blue")}
 {metric("Wymagają uwagi","3","red")}
 {metric("Krytyczne","2","red")}
 {metric("Oczekujące instalacje","7","gold")}
 {metric("Nieodczytane powiadomienia","5","blue")}
 {metric("Otwarte zgłoszenia","3","green")}
 </div>
</section>
<section class="card">
 <div class="section-head"><div><div class="eyebrow">SKRÓTY</div><h2>Szybki dostęp</h2></div></div>
 <div class="hub-grid">
 <a class="hub-tile" href="/multiguard/panel/computers">
  <span class="hub-symbol">▤</span><strong>Komputery</strong><span>Lista instalacji, zdarzenia i historia napraw</span>
  <small>88 Standard · 36 Pro →</small></a>
 <a class="hub-tile" href="/multiguard/panel/service">
  <span class="hub-symbol">◇</span><strong>Zlecenia serwisowe</strong><span>Statusy napraw, zdjęcia, dokumentacja, kwoty</span>
  <small>Otwórz rejestr zleceń →</small></a>
 <a class="hub-tile" href="/multiguard/panel/statistics">
  <span class="hub-symbol">▥</span><strong>Statystyki</strong><span>Finanse, materiały z dawcy i rozliczenia</span>
  <small>Dostęp właściciela →</small></a>
 <a class="hub-tile" href="/multiguard/panel/licenses">
  <span class="hub-symbol">▣</span><strong>Licencje</strong><span>Standard, Pro i przypisanie instalacji</span>
  <small>Otwórz licencje →</small></a>
 </div>
</section>
"""
inventory=f"""
<section class="card panel-hero computers-hero">
 <div class="eyebrow">MULTI-SERVIS / KOMPUTERY KLIENTÓW</div>
 <h1>Komputery</h1>
 <p>Samodzielny rejestr instalacji Multi-Guard, ich ostatniego kontaktu, stanu technicznego i historii serwisu.</p>
 {notice}
 <div class="inventory-headline"><span class="badge mg-blue">Lista i historia urządzeń</span>
 <span class="muted">Stan łączności pochodzi z ostatniego raportu agenta.</span></div>
</section>
<section class="card" id="devices">
 <h2>Rejestr komputerów</h2>
 <p>Filtrowanie i wyszukiwanie nie przenoszą do pulpitu. Na ekranie są wyłącznie urządzenia i ich historia.</p>
 <div class="filter-tabs"><a class="filter-tab selected" href="#">WSZYSTKIE</a>
 <a class="filter-tab" href="#">BRAK KONTAKTU</a>
 <a class="filter-tab" href="#">ZGŁOSZONE ODINSTALOWANIE</a></div>
 <div class="service-search"><label>Wyszukaj komputer<input value="" placeholder="Model, numer seryjny, hostname lub numer zlecenia"></label>
 <button type="button">SZUKAJ</button></div>
 {table(["ID","Komputer","Uprawnienie","Wersja","Łączność","Zdarzenia","Stan"],
 [(f'<a href="#">{i}</a>',name,lic,vers,last,issue,status) for i,name,lic,vers,last,issue,status in devices])}
</section>
"""
device = f"""
<section class="card panel-hero device-hero">
 <div class="eyebrow">MULTI-SERVIS / KARTA FIZYCZNEGO URZĄDZENIA</div>
 <h1>Lenovo ThinkPad T14</h1>
 <p>MG-46AA72B4 · Serwis Pro · diagnostyka do 24.10.2026</p>
 {notice}
 <div class="detail-facts">
 <div class="detail-fact"><b>Licencja</b><span>Serwis / diagnostyczna Pro</span></div>
 <div class="detail-fact"><b>Ostatni kontakt</b><span><span class="presence-dot presence-recent"></span> 09.10.2026 09:40</span></div>
 <div class="detail-fact"><b>Wersja</b><span>Multi-Guard 0.3.35</span></div>
 <div class="detail-fact"><b>Stan</b><span>Obserwacja usterki</span></div>
 </div>
</section>
{section("Historia zleceń serwisowych","Karta komputera łączy wcześniejsze naprawy z bieżącą diagnostyką.",
 table(["Zlecenie","Przyjęto","Status","Opis","Pliki"],[("MS-2026-164","28.09.2026","Wydany","Kontrola układu chłodzenia","5"),("MS-2026-211","09.10.2026","Diagnostyka","Samoczynne wyłączenia po naprawie","3")]))}
{section("Notatki właściciela","Edytowalny priorytet i uwagi nie trafiają do klienta.",
 '<div class="detail-facts"><div class="detail-fact"><b>Priorytet</b><span><span class="badge mg-gold">Do obserwacji</span></span></div><div class="detail-fact"><b>Uwaga</b><span>Weryfikować temperatury i WHEA podczas pracy na baterii.</span></div></div>')}
"""
telemetry=f"""
<section class="card panel-hero telemetry-hero">
 <div class="eyebrow">MULTI-GUARD / TELEMETRIA I ROZWÓJ</div>
 <h1>Wzorce problemów</h1>
 <p>Zdarzenia z komputerów klientów, częstotliwość i historia diagnoz.</p>{notice}
 <div class="metrics">
 {metric("Zdarzenia / 30 dni","28","blue")}
 {metric("Powtarzające się problemy","6","gold")}
 {metric("Krytyczne","2","red")}
 </div>
</section>
{section("Weryfikacja anomalii","Brak odczytu czujnika nie oznacza potwierdzonej awarii sprzętu.",
 table(["Kod","Moduł","Komputery","Zdarzenia","Ostatnio"],[
 ("WHEA-Logger","CPU / płyta","2","4","09.10.2026"),("Kernel-Power 41","Stabilność Windows","1","2","08.10.2026"),("SENSOR_UNAVAILABLE","Czujniki GPU","3","16","06.10.2026")]))}
"""
service=f"""
<section class="card panel-hero service-hero">
 <div class="eyebrow">MULTI-SERVIS / OBSŁUGA SERWISOWA</div>
 <h1>Zlecenia serwisowe</h1>
 <p>Domyślnie wyświetlamy zlecenia wymagające pracy. Zbiorcze kwoty są w Statystykach.</p>{notice}
 <div class="metrics">
 {metric("W naprawie","18","blue")}
 {metric("Gotowe do odbioru","5","gold")}
 {metric("Wydane","104","green")}
 </div>
</section>
<section class="card">
 <div class="section-head"><div><h2>W trakcie naprawy</h2><p>Lista aktywnych zleceń · 20 na stronę</p></div></div>
 <div class="filter-tabs">
  <span class="filter-tab selected">W trakcie naprawy</span><span class="filter-tab">Gotowe do odbioru</span>
  <span class="filter-tab">Wydane</span><span class="filter-tab">Anulowane</span>
  <span class="filter-tab">Wszystkie</span>
 </div>
 {table(["Numer","Sprzęt","Klient","Status","Przyjęto"],[
  ("MS-2026-211","Lenovo ThinkPad T14","Przykładowy klient",'<span class="badge mg-blue">W naprawie</span>',"09.10.2026"),
  ("MS-2026-210","Dell Latitude 5420","Przykładowy klient",'<span class="badge mg-blue">W naprawie</span>',"08.10.2026"),
  ("MS-2026-207","Asus TUF Gaming","Przykładowy klient",'<span class="badge mg-blue">W naprawie</span>',"06.10.2026")])}
</section>
"""
statistics=f"""
<section class="card panel-hero statistics-hero">
 <div class="eyebrow">MULTI-SERVIS / ANALITYKA WŁAŚCICIELA</div>
 <h1>Statystyki</h1>
 <p>Finanse wydanych napraw w okresie: <strong>październik 2026</strong>.</p>{notice}
 <div class="filter-tabs statistics-filter-tabs">
  <span class="filter-tab selected">Miesiąc</span><span class="filter-tab">Kwartał</span>
  <span class="filter-tab">Rok</span><span class="filter-tab">Własny okres</span>
 </div>
 <div class="statistics-period-controls"><a class="button-link compact">←</a>
   <label>Miesiąc <input type="month" value="2026-10"></label>
   <a class="button-link compact">→</a>
 </div>
</section>
<section class="card">
 <div class="section-head"><div><h2>Podsumowanie okresu</h2>
  <p>Osobno pokazujemy koszt zakupionych części i wartość materiałów z dawcy.</p></div></div>
 <div class="metrics statistics-metrics">
 {metric("Wydane zlecenia","24","blue")}
 {metric("Przychód z usług","5 870 zł","green")}
 {metric("Koszt materiałów","1 240 zł","red")}
 {metric("Materiał z dawcy","460 zł","gold")}
 {metric("Zysk rzeczywisty","4 630 zł","blue")}
 {metric("Zysk ekonomiczny","4 170 zł","green")}
 </div>
</section>
<section class="card statistics-trend">
 <div class="section-head"><div><h2>Przychody i koszty w czasie</h2>
  <p>Jasny pasek: przychód · czerwony: zakupione materiały.</p></div></div>
 <div class="finance-trend-row"><span>01.10</span><div class="finance-trend-bars"><i class="finance-trend-revenue" style="width:64%"></i><i class="finance-trend-cost" style="width:15%"></i></div><b>1 540 zł</b></div>
 <div class="finance-trend-row"><span>08.10</span><div class="finance-trend-bars"><i class="finance-trend-revenue" style="width:80%"></i><i class="finance-trend-cost" style="width:28%"></i></div><b>1 940 zł</b></div>
 <div class="finance-trend-row"><span>15.10</span><div class="finance-trend-bars"><i class="finance-trend-revenue" style="width:45%"></i><i class="finance-trend-cost" style="width:11%"></i></div><b>1 090 zł</b></div>
 <div class="finance-trend-row"><span>22.10</span><div class="finance-trend-bars"><i class="finance-trend-revenue" style="width:54%"></i><i class="finance-trend-cost" style="width:19%"></i></div><b>1 300 zł</b></div>
</section>
<details class="card statistics-table-disclosure"><summary>Pełne zestawienie okresów ▾</summary></details>
"""
licenses=f"""
<section class="card panel-hero license-hero">
 <div class="eyebrow">MULTI-SERVIS / UPRAWNIENIA</div>
 <h1>Licencje Multi-Guard</h1>
 <p>Jeden panel właściciela dla Standard, Pro oraz planowanych licencji serwisowo-diagnostycznych.</p>{notice}
</section>
{section("Przypisane licencje","Informacje o wydaniach, komputerach i terminach ważności.",
 table(["Urządzenie","Edycja","Kanał","Wersja","Ważna do"],[
 ("Lenovo ThinkPad T14",'<span class="badge mg-gold">Pro</span>',"STABLE","0.3.35","24.10.2026"),
 ("Dell Latitude",'<span class="badge mg-red">Standard</span>',"STABLE","0.3.35","11.10.2027"),
 ("HP Pavilion",'<span class="badge mg-gold">Pro</span>',"BETA","0.3.35","13.05.2027")]))}
"""
versions=f"""
<section class="card panel-hero license-hero">
 <div class="eyebrow">MULTI-GUARD / HISTORIA ROZWOJU</div>
 <h1>Historia wersji</h1>
 <p>Co dodano, poprawiono, zmieniono i usunięto w konkretnych wydaniach.</p>{notice}
</section>
<section class="card">
 <div class="release-timeline">
 <article class="release-card"><div class="section-head"><div><div class="eyebrow">BETA / 0.3.35</div><h2>Multi-Guard 0.3.35</h2></div><span class="badge mg-gold">BETA</span></div>
 <p>Przykładowy wpis — nie jest informacją o faktycznie wydanej wersji.</p>
 <ul class="release-changes"><li><span class="badge mg-green">Dodano</span> Widok historii napraw</li>
 <li><span class="badge mg-blue">Poprawiono</span> Obsługę przykładowego sensora</li></ul></article>
 <article class="release-card"><div class="section-head"><div><div class="eyebrow">STABLE / 0.3.34</div><h2>Multi-Guard 0.3.34</h2></div><span class="badge mg-gold">STABLE</span></div>
 <p>Przykładowy wpis wizualny — NIE oznacza, że wersja TEST 0.3.34 została opublikowana jako STABLE.</p>
 </article></div>
</section>
"""
settings=f"""
<section class="card panel-hero settings-hero">
 <div class="eyebrow">MULTI-SERVIS / KONFIGURACJA</div>
 <h1>Ustawienia panelu</h1>
 <p>Dostosuj progi prezentacji bez przebudowy Multi-Guard na komputerach.</p>{notice}
</section>
<section class="card">
 <h2>Komputery i ostatni kontakt</h2>
 <div class="detail-facts">
 <div class="detail-fact"><b>Zielona kropka</b><span>24 godziny</span></div>
 <div class="detail-fact"><b>Brak kontaktu</b><span>7 dni</span></div>
 <div class="detail-fact"><b>Wiersze na stronie</b><span>50</span></div></div>
 <p>Rzeczywista trasa ustawień zawiera edytowalny, chroniony formularz.</p>
</section>
"""
for name,body in [
  ("01-pulpit",dashboard),("02-karta-komputera",device),("08-komputery",inventory),
  ("03-telemetria",telemetry),("04-serwis",service),("09-statystyki",statistics),
  ("05-licencje",licenses),("06-historia-wersji",versions),
  ("07-ustawienia",settings)
]:
    page=render(body)
    assert 'workspace-shell' in page
    assert 'PANEL_CSS' not in page
    assert 'font-weight:700' not in page and 'font-weight:800' not in page
    (OUT / f"{name}.html").write_text(page,encoding="utf-8")
print(f"Created {len(list(OUT.glob('*.html')))} faithful shared-template previews in {OUT}")
