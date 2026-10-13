# KeyGate integration test fixture — 2026-10-13

State: setup ready; real backend API test blocked before any test licence was created.

## Test-only catalogue

- Host: https://license.multi-servis.pl
- Product: Multi-Guard TEST
- Slug: multi-guard-test
- Product ID: ec3e106e-87f4-48eb-a07c-4749fc196230
- Plans: multi-guard-test-assist-3m, multi-guard-test-assist-6m, multi-guard-test-assist-12m, multi-guard-test-assist-pro-3m, multi-guard-test-assist-pro-6m, multi-guard-test-assist-pro-12m.
- Plan type: perpetual; 1 activation; 0 trial days; 0 grace days. The UI disables duration for perpetual plans. Actual 3/6/12-month expiry must be set by the Multi-Servis acceptance flow, not inferred from the plan name.
- Temporary API key label: Multi-Guard TEST — tymczasowa weryfikacja 2026-10-13.
- Scope: licenses:write only. No token value is stored in this repository. In KeyGate source 246c418, product_id on API keys is informational and does not enforce product isolation; test code must independently require the exact test product UUID and slug.

## Observed blocker

A plain Python urllib GET /api/v1/products/multi-guard-test/plans returned HTTP 403 with body `error code: 1010`. The admin browser session works. This result applies to the tested caller; it does not establish that requests from the production server fail.

Cloudflare documents 1010 as a client/browser-signature block. Browser Integrity Check can reject non-browser API callers. No Cloudflare security setting has been changed, no browser identity has been spoofed, and the API token has not yet been sent to a test endpoint.

Possible owner-reviewed correction: skip only Browser Integrity Check for host license.multi-servis.pl and path prefix /api/v1/. Keep all other protections and KeyGate API authentication. Inspect existing Cloudflare rules first and obtain action-time confirmation before any security change. Never disable BIC globally as part of this test.

## Remaining validation and cleanup

Use the real backend _keygate_* functions for test-only licence creation, reveal, activation, expiry update, deactivation and revocation; then combine the result with the already-passing PostgreSQL/Chromium tests. Never report a real KeyGate PASS until those calls complete.

After tests, revoke/remove the temporary API key and remove disposable test licences, plans and the test product after preserving a non-secret result. Production Multi-Guard catalogue and ADMIN FULL licence are outside the cleanup scope.
