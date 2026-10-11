#!/usr/bin/env python3
"""Chromium smoke of the ACTUAL OWNER shell JS, without production data or network."""
from __future__ import annotations
import ast
from pathlib import Path
from playwright.sync_api import sync_playwright

root=Path(__file__).resolve().parents[1]
source=(root/"app/routers/multiguard_license.py").read_text(encoding="utf-8")
tree=ast.parse(source)
func=next(x for x in tree.body if isinstance(x,ast.FunctionDef) and x.name=="_panel_html")
namespace={"PANEL_CSS":""}
exec(compile(ast.Module(body=[func],type_ignores=[]),"<actual-owner-panel-shell>","exec"),namespace)
render=namespace["_panel_html"]

body="""
<section class="card">
  <form method="post" action="/test-submit" data-owner-service-form>
    <input type="hidden" name="csrf_token" value="CI"/>
    <input type="hidden" name="service_confirm" value=""/>
    <label>Okres <select name="months">
      <option value="12">12 miesięcy</option>
      <option value="SERVICE">Tryb serwisowy</option>
      <option value="3">3 miesiące</option>
    </select></label>
    <button type="submit" data-owner-service-submit>PRZYPISZ LICENCJĘ</button>
    <dialog class="owner-service-confirm-dialog">
      <h3>Czy na pewno włączyć tryb serwisowy?</h3>
      <button type="button" onclick="this.closest('dialog').close()">ANULUJ</button>
      <button type="button" data-service-approve>TAK, WŁĄCZ TRYB SERWISOWY</button>
    </dialog>
  </form>
  <form method="post" action="/monitor-save" data-owner-monitor-form>
    <label><input type="checkbox" name="monitoring_enabled" value="yes"
      data-owner-monitor-toggle>Monitorowanie rozszerzone</label>
    <select name="profile" data-owner-monitor-profile disabled>
      <option value="STANDARD">Standardowy</option>
      <option value="OBSERVATION">Obserwacja</option>
      <option value="INTENSIVE">Intensywny</option>
    </select>
  </form>
  <input data-owner-order-suggest name="reception_number"
     list="ci-order-hints" autocomplete="off">
  <datalist id="ci-order-hints"></datalist>
</section>
"""
html=render(body)

with sync_playwright() as p:
    browser=p.chromium.launch(headless=True)
    page=browser.new_page()
    submissions=[]
    def respond(route):
        url=route.request.url
        if url.endswith("/test-submit"):
            submissions.append(route.request.post_data or "")
            route.fulfill(status=200,content_type="text/html",body="<p>OK</p>")
        elif "/service-orders/suggest?" in url:
            route.fulfill(status=200,content_type="application/json",
                body='{"results":[{"number":"MS-2026-00123","label":"MS-2026-00123 — ASUS"}]}')
        else:
            route.fulfill(status=200,content_type="text/html",body=html)
    page.route("https://panel.multi-servis.test/**",respond)
    page.goto("https://panel.multi-servis.test/multiguard/panel/pending/ci")
    select=page.locator('form[data-owner-service-form] select[name="months"]')
    button=page.locator('[data-owner-service-submit]')
    assert button.inner_text()=="PRZYPISZ LICENCJĘ"
    page.locator('[data-owner-monitor-profile]').is_disabled()
    assert page.locator('[data-owner-monitor-profile]').is_disabled()
    page.locator('[data-owner-monitor-toggle]').check()
    assert page.locator('[data-owner-monitor-profile]').is_enabled()
    page.locator('[data-owner-monitor-profile]').select_option("OBSERVATION")
    page.locator('[data-owner-monitor-toggle]').uncheck()
    assert page.locator('[data-owner-monitor-profile]').is_disabled()
    assert page.locator('[data-owner-monitor-profile]').input_value()=="OBSERVATION"
    page.locator('[data-owner-order-suggest]').fill("123")
    page.wait_for_function("document.getElementById('ci-order-hints').children.length > 0")
    assert page.locator('#ci-order-hints option').first.get_attribute("value")=="MS-2026-00123"

    select.select_option("SERVICE")
    assert button.inner_text()=="WŁĄCZ TRYB SERWISOWY"
    button.click()
    assert page.locator("dialog.owner-service-confirm-dialog").evaluate("(d)=>d.open")
    assert submissions==[], "Initial service click MUST NOT submit."
    page.locator('dialog button:has-text("ANULUJ")').click()
    assert not page.locator("dialog.owner-service-confirm-dialog").evaluate("(d)=>d.open")
    assert submissions==[], "Cancel MUST NOT grant a service entitlement."
    button.click()
    page.locator('[data-service-approve]').click()
    page.wait_for_url("**/test-submit")
    assert len(submissions)==1, submissions
    assert "months=SERVICE" in submissions[0] and "service_confirm=CONFIRM_WORKSHOP" in submissions[0]

    page.goto("https://panel.multi-servis.test/multiguard/panel/pending/ci")
    page.locator('[data-owner-service-submit]').click()
    page.wait_for_url("**/test-submit")
    assert len(submissions)==2
    assert "months=12" in submissions[1]
    assert "service_confirm=CONFIRM_WORKSHOP" not in submissions[1]
    browser.close()

print("PASS: actual OWNER JavaScript: two-step SERVICE, cancel, 12m one click, OFF toggle and 3-digit hints.")
