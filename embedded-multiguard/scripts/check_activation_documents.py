#!/usr/bin/env python3
"""Read-only preflight for approved MultiGuard activation document JSON.

Usage: python check_activation_documents.py /path/to/approved-documents.json
No network, database or secrets; prints only document metadata and SHA256.
The input is an array of exactly three objects (kind, version, title, content_markdown).
"""
from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path


def validate_document_bundle(data: object) -> list[dict[str, str]]:
    if not isinstance(data, list) or len(data) != 3:
        raise ValueError("Wymagane są dokładnie trzy dokumenty.")
    kinds: set[str] = set()
    output: list[dict[str, str]] = []
    for i, doc in enumerate(data, 1):
        if not isinstance(doc, dict):
            raise ValueError(f"Dokument {i} ma błędną strukturę.")
        keys = ("kind", "version", "title", "content_markdown")
        if any(not isinstance(doc.get(k), str) or not doc[k].strip() for k in keys):
            raise ValueError(f"Dokument {i} ma brakujące lub puste pola.")
        if doc["kind"] in kinds:
            raise ValueError("Powtórzony rodzaj dokumentu.")
        kinds.add(doc["kind"])
        body = doc["content_markdown"]
        if any(marker in body.lower() for marker in ("[do uzupełnienia", "[do ustalenia", "todo", "projekt — wersja")):
            raise ValueError(f"Dokument {i} wygląda na niezatwierdzony projekt.")
        output.append({
            "kind": doc["kind"], "version": doc["version"],
            "title": doc["title"],
            "sha256": hashlib.sha256(body.encode("utf-8")).hexdigest(),
        })
    return output


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("Użycie: python check_activation_documents.py zatwierdzone.json", file=sys.stderr)
        return 2
    try:
        bundle = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
        items = validate_document_bundle(bundle)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"BLOKADA PUBLIKACJI: {exc}", file=sys.stderr)
        return 1
    print("PREFLIGHT OK — komplet trzech dokumentów; nie stanowi zatwierdzenia prawnego")
    for item in items:
        print(f'{item["kind"]} | {item["version"]} | {item["title"]} | {item["sha256"]}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
