#!/usr/bin/env python3
"""Install INTERNAL ONLY MultiGuard document fixture into existing JSON config.

Run only on a non-public, closed test deployment after copying fixture to host.
Never modifies license records or KeyGate; restarts are a separate operator step.
Use: python install_internal_activation_docs.py FIXTURE.json CONFIG.json --confirm-internal
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def run():
    p = argparse.ArgumentParser()
    p.add_argument("fixture", type=Path)
    p.add_argument("config", type=Path)
    p.add_argument("--confirm-internal", action="store_true")
    a = p.parse_args()
    if not a.confirm_internal:
        p.error("Odmowa: tylko zamknięte testy, wymagane --confirm-internal")
    from check_activation_documents import validate_document_bundle
    docs = json.loads(a.fixture.read_text(encoding="utf-8"))
    validated = validate_document_bundle(docs)
    if {v["kind"] for v in validated} != {"terms", "privacy", "safety"}:
        raise ValueError("Wymagane typy: terms, privacy, safety")
    if any(not v["version"].endswith("-internal") for v in validated):
        raise ValueError("Nie znaleziono oznaczeń wersji testowej")
    if any("WYŁĄCZNIE TEST WEWNĘTRZNY" not in x["content_markdown"] for x in docs):
        raise ValueError("Dokument nie ma ostrzeżenia o wersji wewnętrznej")

    # Environment variable takes precedence over JSON configuration and
    # cannot be overridden safely by editing this file.
    if os.getenv("MULTIGUARD_REQUIRED_DOCUMENTS"):
        raise RuntimeError("Zmienna środowiskowa ma pierwszeństwo. Przerwano instalację.")

    if not a.config.is_file():
        raise FileNotFoundError(f"Brak pliku konfiguracji: {a.config}")
    original = json.loads(a.config.read_text(encoding="utf-8"))
    if not isinstance(original, dict):
        raise ValueError("Plik konfiguracyjny nie jest obiektem JSON")
    updated = dict(original)
    updated["MULTIGUARD_REQUIRED_DOCUMENTS"] = docs

    # Preserve permissions, save backup and atomically replace JSON.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = a.config.with_name(f"{a.config.name}.before-internal-docs-{stamp}.bak")
    shutil.copy2(a.config, backup)
    mode = a.config.stat().st_mode & 0o777
    fd, tmp = tempfile.mkstemp(prefix=".multiguard-docs-", dir=a.config.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(updated, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, a.config)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    print("ZAPISANO KONFIGURACJĘ TESTOWĄ:", a.config)
    print("KOPIA ZAPASOWA:", backup)
    print("DOKUMENTY:", len(validated))
    print("UWAGA: Uruchom usługę ponownie kontrolowaną procedurą po walidacji.")


if __name__ == "__main__":
    try:
        run()
    except Exception as exc:
        print(f"ODMOWA INSTALACJI: {exc}", file=sys.stderr)
        raise SystemExit(1)
