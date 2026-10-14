"""Browser checks against HTML exported by the isolated PostgreSQL test."""
import os
from pathlib import Path
from playwright.sync_api import sync_playwright

folder = Path(os.environ["OWNER_TEST_HTML_DIR"])
for name in ("licenses", "computers", "dashboard", "service-mode", "remote", "license-management"):
    assert (folder / (name + ".html")).is_file(), (
        "Missing PostgreSQL fixture: " + name + ". Run the integration test first."
    )
with sync_playwright() as p:
    browser = p.chromium.launch(headless=True, timeout=30000)
    for width, height in ((1440, 900), (390, 844)):
        page = browser.new_page(viewport={"width": width, "height": height})
        def serve(route):
            name = route.request.url.split("/")[-1]
            route.fulfill(content_type="text/html", body=(folder / (name + ".html")).read_text(encoding="utf-8"))
        page.route("https://owner.test/multiguard/panel/*", serve)
        page.goto("https://owner.test/multiguard/panel/licenses")
        assert page.locator('.workspace-sidebar nav a').all_text_contents() == ['⌂Pulpit','▤Komputery','▣Licencje','⌁Tryb serwisowy','▥Zdalna pomoc','◇Zlecenia']
        assert page.locator('#pending').count() == 1
        assert page.locator('#assigned').count() == 1
        assert page.locator('.workspace-sidebar [aria-current="page"]').inner_text().strip().endswith("Licencje")
        page.locator('.pending-edit-name').first.click()
        assert page.locator('.pending-name-dialog').first.evaluate('(el)=>el.open')
        page.locator('.pending-name-dialog').first.locator('button', has_text="ANULUJ").click()
        page.locator('.pending-archive-trigger').first.click()
        dialog = page.locator('.pending-archive-dialog').first
        assert dialog.evaluate('(el)=>el.open')
        dialog.locator('button', has_text="ANULUJ").click()
        assert not dialog.evaluate('(el)=>el.open')
        page.locator('.table-wrap').evaluate_all('(els)=>els.forEach(el=>el.scrollLeft=0)')
        page.screenshot(path=str(folder / f'licenses-{width}.png'), full_page=True)
        page.goto("https://owner.test/multiguard/panel/computers")
        assert page.locator('#pending').count() == 0
        assert page.locator('#devices').count() == 1
        assert page.locator('.owner-inventory-table').count() == 1
        machine_name = page.locator('.owner-inventory-table .owner-machine-display').first
        assert machine_name.count() == 1, "Inventory must keep a readable editable name"
        assert machine_name.evaluate('(el) => getComputedStyle(el).whiteSpace') == 'normal'
        assert machine_name.evaluate('(el) => getComputedStyle(el).webkitLineClamp') == '2'
        # A very long manufacturer/model may take two lines, never only one
        # and never three; verify on both wide and narrow browser viewports.
        name_lines = machine_name.evaluate("""el => {
            const original = el.textContent;
            el.textContent = 'Multi-Servis ' + 'ASUS-ROG-ZEPHYRUS-'.repeat(20);
            const lineHeight = parseFloat(getComputedStyle(el).lineHeight);
            const totalHeight = el.getBoundingClientRect().height;
            el.textContent = original;
            return totalHeight / lineHeight;
        }""")
        assert 1.8 <= name_lines <= 2.2, (
            "Editable computer name must occupy up to two lines, not one or three",
            name_lines,
        )
        page.screenshot(path=str(folder / f'computers-{width}.png'),full_page=True)
        page.goto('https://owner.test/multiguard/panel/service-mode')
        assert page.locator('[data-owner-monitor-toggle]').count() >= 1
        assert page.locator('.workspace-sidebar [aria-current="page"]').inner_text().strip().endswith('Tryb serwisowy')
        page.screenshot(path=str(folder / f'service-mode-{width}.png'),full_page=True)
        page.goto('https://owner.test/multiguard/panel/remote')
        assert page.locator('.owner-remote-layout').count()==1
        assert page.locator('.workspace-sidebar [aria-current="page"]').inner_text().strip().endswith('Zdalna pomoc')
        page.screenshot(path=str(folder / f'remote-{width}.png'),full_page=True)
        page.goto('https://owner.test/multiguard/panel/license-management')
        assert page.locator('#license-plan-change summary').count()==1
        assert page.locator('#license-plan-change input[name="target_edition"]').count()==1
        page.locator('#license-shortening summary').click()
        assert page.locator('input[name="new_last_day"]').is_visible()
        confirmation = page.locator('input[name="confirmed"]')
        assert confirmation.evaluate('(el)=>el.required')
        assert confirmation.evaluate('(el)=>el.closest("label").classList.contains("owner-license-confirm-label")')
        check_box = confirmation.bounding_box()
        assert check_box and 12 <= check_box["width"] <= 24 and 12 <= check_box["height"] <= 24, check_box
        page.locator('#license-shortening label.owner-license-confirm-label').click()
        assert confirmation.is_checked(), "Clicking confirmation label must toggle checkbox"
        heading = page.locator('h1.owner-license-number')
        assert heading.count() == 1
        assert heading.evaluate("""el => {
            const original = el.textContent;
            el.textContent = 'Licencja ' + 'A'.repeat(110);
            const wraps = el.scrollWidth <= el.clientWidth + 1;
            el.textContent = original;
            return wraps;
        }"""), "Long reception number escapes the responsive heading"
        percent = page.locator('.owner-license-percent')
        assert percent.count() == 1
        assert '%' in percent.inner_text()
        assert page.locator('input[name="paid_amount"]').count() == 0
        assert page.get_by_text('Historia zmian okresu', exact=True).count()==1
        page.screenshot(path=str(folder / f'license-management-{width}.png'),full_page=True)
        page.goto("https://owner.test/multiguard/panel/dashboard")
        assert page.locator('.hub-tile,.owner-overview-tile').count() == 0
        assert page.get_by_text('Szybkie działania', exact=True).count() == 0
        assert page.locator('a[href="/multiguard/panel/licenses#pending"]').count() == 1
        page.screenshot(path=str(folder / f'dashboard-{width}.png'), full_page=True)
        page.close()
    browser.close()
print('PASS: actual PostgreSQL-rendered queue, dialogs and dashboard in desktop/mobile Chromium')
