Multi-Servis OWNER WEB controlled release
Authorised by owner in ChatGPT: deploy web panel to activate registered Multi-Guard 0.3.37, and prepare a second Standard installation.
Scope: existing OWNER web interface only. Preserve Android API, service orders, and Windows binaries.
Validated source commit: 0c04f4e16045397b5de8da2daecc5e0b6d789b4b
Validation: GitHub Actions 37987538606 SUCCESS (isolated PostgreSQL, Chromium, security checks)
Production path: backup + read-only schema preflight + guarded API compatibility check + restart/health verification + automatic rollback.
