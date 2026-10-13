# KeyGate integration test — 2026-10-13

State: real KeyGate helper tests passed; OWNER production deployment and real Windows client validation remain pending.

## Test-only catalogue

- Host: https://license.multi-servis.pl
- Product: Multi-Guard TEST; slug: multi-guard-test
- Product ID: ec3e106e-87f4-48eb-a07c-4749fc196230
- Plans: multi-guard-test-assist-3m, multi-guard-test-assist-6m, multi-guard-test-assist-12m, multi-guard-test-assist-pro-3m, multi-guard-test-assist-pro-6m, multi-guard-test-assist-pro-12m.
- Plan type: perpetual; 1 activation; 0 trial; 0 grace. The UI disables duration for perpetual plans. Actual paid expiry is set by the Multi-Servis acceptance flow.
- Temporary API key label: Multi-Guard TEST — tymczasowa weryfikacja 2026-10-13; scope licenses:write.
- KeyGate 246c418 treats API-key product_id as informational. Test code independently pins the TEST product UUID and slug. No secret appears in this report or repository.

## Cloudflare correction and observed results

The original Python urllib request returned HTTP 403 / error 1010. The owner deployed configuration rule "KeyGate API — BIC", scoped to hostname license.multi-servis.pl AND URI path starting /api/v1/, following the agreed BIC-off setting. The rule list showed Active with the exact hostname and path. The list itself does not display the Off value.

After the change, the same ordinary Python urllib caller received HTTP 200 and all six test plans. An authenticated request for an intentionally nonexistent licence reached KeyGate and returned its JSON NOT_FOUND / HTTP 404. No User-Agent spoofing or certificate bypass was used.

## Real API tests

The unmodified backend functions _keygate_request, _find_plan_id, _keygate_create_license, _keygate_activate, _keygate_license, _keygate_reveal, _keygate_set_valid_until and _keygate_deactivate were compiled from the source AST and called against real KeyGate. Environment settings were TEST-only. The local harness supplied the configuration lookup and HTTPException compatibility class because the scratch interpreter has no FastAPI installation; HTTP and KeyGate responses were not mocked.

- All six Standard/Pro 3/6/12-month plan mappings resolved.
- Standard 3m licence 8ee29e91-e5f3-4ba3-a357-b906ee25840a: TEST product verified, initially no valid_until, activation responded, exact 3-month expiry saved, key reveal matched, device deactivated, licence revoked, persisted revoked status verified, subsequent activation rejected.
- Pro 6m licence d4f31103-1be3-4dd5-8714-7d56120d8e52: TEST product verified, initially no valid_until, activation status activated with token and matching licence ID, exact 6- and 12-month expiry values saved/read back, device deactivated, persisted revoked status verified.
- Both test licences are revoked. These are API fixture checks; no production customer licence was changed.

## Other validation

- Local rerun: 22 DIRECT assignment atomicity tests passed; deployment AST guard passed including rejection of unrelated endpoint/signature mutations.
- ROG run 38409508660: local Windows runner regression passed.
- PostgreSQL run 38410002661: three real PostgreSQL DIRECT concurrency/rollback checks and OWNER integration passed. KeyGate was a controlled double in that database test.
- Chromium + PostgreSQL run 38410530971 at 44aed7f144384abf76b8547609bb5ff98ce3f9cd passed after the latest production notes fixes were incorporated.

## Remaining work and cleanup

This does not prove live OWNER acceptance/assignment against real KeyGate, Windows 0.3.40 activation/offline handling or signed client revocation. Do not label the full system ready based on helper tests.

The broad development branch contains root tests and additional workflows/triggers outside the pinned server agent allowlist. A release package must include only permitted OWNER files. The pinned on-server deployment script also needs the reviewed exact acceptance hardening exception; a repository edit alone does not update that pinned file.

Cleanup performed: temporary API key removed through the admin UI and its former token now returns HTTP 401. The local token file and licence-key values were removed from scratch. Four unused plans were deleted: Standard 6m/12m and Pro 3m/12m. Both test licences remain revoked with no active device activations.

Cleanup limitation: KeyGate 246c418 has no admin licence deletion endpoint or UI action. Its DeleteProduct explicitly rejects products with any licences (HAS_LICENSES), and DeletePlan rejects plans referenced by licences. Therefore the TEST product and Standard 3m/Pro 6m plans remain as historical fixture records; do not claim they were deleted. Full removal would require a separately reviewed server/database maintenance procedure. Production Multi-Guard product 9843d5fd-f090-4534-9d32-d66b64999acb and ADMIN FULL licence were untouched.

## Release package

Draft PR #16 packages only permitted OWNER paths at initial revision 605e224dab495a1655d4f4801f9cb87772522a42. The original agent allowlist accepted its diff from sequence-13 target f7186463c64b711d8933590c95dae6c5af5772b7. The release manifest sequence is unchanged, so this does not deploy production.
