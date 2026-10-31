def _mg_v44_grid_transform(doc: str) -> str:
    """Keep existing V4.4 rows compact: one expiry control, popup outside table."""
    import re
    from html import escape
    doc = re.sub(
        r'<script[^>]*data-mg-v44-term-version="1"[^>]*>.*?</script>',
        '', doc, flags=re.I | re.S,
    )
    table = re.search(r'<table\b[^>]*>.*?</table>', doc, re.I | re.S)
    if not table or 'licenses' not in table.group(0).lower():
        raise RuntimeError('Brak tabeli licencji V4.4')
    markup = table.group(0)
    headings = re.search(r'<thead[^>]*>(.*?)</thead>', markup, re.I | re.S)
    if not headings:
        raise RuntimeError('Brak nagłówków V4.4')
    labels = [re.sub(r'<[^>]*>', '', x).strip().lower() for x in
              re.findall(r'<th[^>]*>(.*?)</th>', headings.group(1), re.I | re.S)]
    col = next((i for i, x in enumerate(labels) if 'ważn' in x), None)
    if col is None:
        raise RuntimeError('Nie znaleziono kolumny Ważna do')
    row_pattern = re.compile(r'<tr\b[^>]*>.*?</tr>', re.I | re.S)
    counter = [0]

    def render_row(match):
        row = match.group(0)
        if not re.search(r'/multiguard/panel/licenses-grid/[^"\s]+/save', row):
            return row
        selector = re.search(
            r'''(<select\b[^>]*name=["']target_edition["'][^>]*>)(.*?)</select>''',
            row, re.I | re.S,
        )
        if not selector:
            raise RuntimeError('Brak listy edycji')
        form_match = re.search(
            r'''<form\b(?=[^>]*action=["'][^"']+/save["'])[^>]*>''',
            row, re.I | re.S,
        )
        if not form_match:
            raise RuntimeError('Brak formularza Zapisz')
        fid_match = re.search(r'''id=["']([\w-]+)["']''', form_match.group(0))
        if not fid_match:
            raise RuntimeError('Brak ID formularza')
        fid = escape(fid_match.group(1), quote=True)
        selected_match = re.search(
            r'''<option\b[^>]*value=["'](PRO|STANDARD|SERVICE)["'][^>]*selected''',
            selector.group(2), re.I,
        )
        selected = selected_match.group(1).upper() if selected_match else 'STANDARD'
        options = ''.join(
            '<option value="' + v + '"' + (' selected' if v == selected else '') +
            '>' + label + '</option>'
            for v, label in [('PRO','Pro'),('STANDARD','Standard'),('SERVICE','Service')]
        )
        select_start = selector.group(1)
        select_start = select_start[:-1] + ' data-original-edition="' + selected + '">'
        row = row[:selector.start()] + select_start + options + '</select>' + row[selector.end():]
        cells = list(re.finditer(r'<td\b[^>]*>.*?</td>', row, re.I | re.S))
        if col >= len(cells):
            raise RuntimeError('Brak komórki Ważna do')
        cell = cells[col]
        old = cell.group()
        date = re.search(r'\b\d{2}\.\d{2}\.\d{2,4}\b|\b\d{4}-\d{2}-\d{2}\b', old)
        if not date:
            raise RuntimeError('Brak obecnej daty w tabeli')
        days = re.search(r'\b\d+\s+dni\s+pozostało\b',
                         re.sub(r'<[^>]*>', ' ', old), re.I)
        opening = re.match(r'<td\b[^>]*>', old, re.I).group()
        if 'class=' in opening.lower():
            opening = re.sub(
                r'''class=["']([^"']*)["']''',
                lambda m: 'class="' + m.group(1) + ' mg-compact-date-cell"',
                opening, count=1, flags=re.I,
            )
        else:
            opening = opening[:-1] + ' class="mg-compact-date-cell">'
        label = escape(date.group(0))
        new_cell = (
            opening +
            '<details class="mg-compact-date">'
            '<summary aria-label="Wybierz datę ważności">' + label + ' ▾</summary>'
            '<div class="mg-compact-popup" hidden>'
            '<div class="mg-compact-presets">'
            '<button type="button" data-month="12">12 mies.</button>'
            '<button type="button" data-month="6">6 mies.</button>'
            '<button type="button" data-month="3">3 mies.</button>'
            '<button type="button" data-perpetual disabled title="Licencja bez daty końcowej; okres można później zmienić">Bezterm.</button>'
            '</div>'
            '<input class="mg-compact-calendar" type="date" name="term_date" form="' + fid + '" aria-label="Wybierz datę ważności">'
            '</div></details>'
            '<select class="mg-compact-choice" name="term_choice" form="' + fid + '">'
            '<option value="KEEP" selected>Bez zmian</option>'
            '<option value="12">12</option><option value="6">6</option>'
            '<option value="3">3</option><option value="CALENDAR">Kalendarz</option>'
            '<option value="PERPETUAL">Bezterminowa</option></select>' +
            ('<small class="mg-compact-days">' + escape(days.group(0)) + '</small>'
             if days else '') + '</td>'
        )
        row = row[:cell.start()] + new_cell + row[cell.end():]
        row = re.sub(r'''(<form\b[^>]*?)\s+onsubmit=(["']).*?\2''',
                     r'\1', row, count=1, flags=re.I | re.S)
        row = row.replace('<tr', '<tr data-mg-compact="yes"', 1)
        counter[0] += 1
        return row

    new_table = row_pattern.sub(render_row, markup)
    if not counter[0]:
        raise RuntimeError('Brak wierszy licencji do poprawy')
    doc = doc[:table.start()] + new_table + doc[table.end():]
    extra = r"""
<style>
.grid-licenses td.mg-compact-date-cell{overflow:visible!important;white-space:nowrap}
.mg-compact-date{display:inline-block;position:relative}
.mg-compact-date>summary{cursor:pointer;list-style:none;border:1px solid #426b89;
 border-radius:3px;padding:3px 5px;font-size:11px;white-space:nowrap}
.mg-compact-date>summary::-webkit-details-marker{display:none}
.mg-compact-days{display:block;font-size:10px;opacity:.7;margin-top:2px}
.mg-compact-choice{display:none!important}
.mg-compact-popup{position:fixed;z-index:2147483000;width:286px;padding:6px;
 border:1px solid #507d9d;border-radius:0;background:#14283c;color:#eaf4fa;
 box-shadow:0 8px 20px #000a}
.mg-compact-popup[hidden]{display:none!important}
.mg-compact-presets{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:3px;margin:0 0 6px}
.mg-compact-popup .mg-compact-presets button{display:block!important;box-sizing:border-box!important;
 min-width:0!important;max-width:none!important;width:100%!important;
 height:30px!important;min-height:30px!important;max-height:30px!important;
 padding:3px 1px!important;margin:0!important;white-space:nowrap!important;
 border:1px solid #567c9b!important;border-radius:0!important;box-shadow:none!important;
 background:#203b54!important;color:#eff6fb!important;
 font-size:10px!important;font-weight:500!important;line-height:20px!important;
 text-align:center!important;text-transform:none!important;cursor:pointer}
.mg-compact-popup .mg-compact-presets button:disabled{opacity:.45!important;cursor:not-allowed}
.mg-compact-popup .mg-compact-presets button:not(:disabled):hover{background:#2c5877!important}
.mg-compact-popup .mg-compact-presets button[aria-pressed=true]{background:#28628a!important;
 border-color:#6cbbeb!important}
.mg-compact-popup input.mg-compact-calendar[type=date]{display:block!important;
 width:100%!important;min-width:0!important;box-sizing:border-box!important;
 height:30px!important;min-height:30px!important;max-height:30px!important;
 margin:0!important;padding:3px 6px!important;font-size:12px!important;
 border:1px solid #547b98!important;border-radius:0!important;
 background:#112b41!important;color:#fff!important}

</style>
<script>
(function(){
document.querySelectorAll('tr[data-mg-compact=yes]').forEach(function(row){
 var ed=row.querySelector('select[name=target_edition]');
 var pick=row.querySelector('.mg-compact-date');
 var choice=row.querySelector('select[name=term_choice]');
 if(!ed||!pick||!choice)return;
 var popup=pick.querySelector('.mg-compact-popup');
 var date=popup.querySelector('input[type=date]');
 var forever=popup.querySelector('[data-perpetual]');
 var fid=choice.getAttribute('form');
 var save=row.querySelector('button.grid-save')||row.querySelector('button[type=submit][form="'+fid+'"]');
 var form=document.getElementById(fid);
 var original=ed.dataset.originalEdition||ed.value;
 if(!form)return;
 document.body.appendChild(popup);
 function position(){
  var rect=pick.querySelector('summary').getBoundingClientRect();
  popup.style.left=Math.max(3,Math.min(rect.left,innerWidth-292))+'px';
  popup.style.top=(rect.bottom+96<innerHeight?rect.bottom+3:Math.max(3,rect.top-96))+'px';
  popup.hidden=false;
 }
 function refresh(){
  popup.querySelectorAll('[data-month]').forEach(function(b){
   b.setAttribute('aria-pressed',String(choice.value===b.dataset.month));
  });
  forever.setAttribute('aria-pressed',String(choice.value==='PERPETUAL'));
  forever.disabled=ed.value!=='SERVICE';
  if(save&&(choice.value!=='KEEP'||ed.value!==original))save.disabled=false;
 }
 pick.addEventListener('toggle',function(){if(pick.open)position();else popup.hidden=true;});
 popup.querySelectorAll('[data-month]').forEach(function(b){b.addEventListener('click',function(){
  choice.value=b.dataset.month;date.value='';refresh();
 });});
 date.addEventListener('change',function(){if(date.value){choice.value='CALENDAR';refresh();}});
 forever.addEventListener('click',function(){choice.value='PERPETUAL';date.value='';refresh();});
 ed.addEventListener('change',refresh);
 document.addEventListener('click',function(e){
  if(pick.open&&!pick.contains(e.target)&&!popup.contains(e.target))pick.open=false;
 });
 form.addEventListener('submit',function(e){
  if(choice.value==='CALENDAR'&&!date.value){e.preventDefault();pick.open=true;position();date.focus();}
 });
 refresh();
});
})();
</script>
"""
    return re.sub(r'</body>', lambda m:extra+m.group(), doc, count=1, flags=re.I) if re.search(r'</body>',doc,re.I) else doc+extra
