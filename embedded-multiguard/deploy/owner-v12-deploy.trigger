Multi-Servis OWNER WEB controlled release — 2026-10-10
Explicit owner authorization: provide manual removal of stale Multi-Guard WAITING entries before reinstalling Windows clients.
Scope: OWNER web console, status ARCHIVED, audit records, reconnect recovery. No Android/client binaries.
Web QA: workflow 38035835490 SUCCESS, Python syntax, existing security checks and audit invariants.
Release process: backup + READ-ONLY preflight + strict non-owner API compatibility check + automatic rollback + health verification.
Trigger: web-owner-pending-cleanup-rev1
