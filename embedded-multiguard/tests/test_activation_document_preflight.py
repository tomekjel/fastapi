#!/usr/bin/env python3
"""Self-contained tests of read-only document preflight."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

source = pathlib.Path(__file__).resolve().parents[1] / "scripts/check_activation_documents.py"
spec = importlib.util.spec_from_file_location("activation_preflight", source)
module = importlib.util.module_from_spec(spec)
assert spec and spec.loader
spec.loader.exec_module(module)


def sample():
    return [
        {"kind": kind, "version": "1.0", "title": title,
         "content_markdown": "Zatwierdzony dokument aktywacyjny — pełna treść."}
        for kind, title in (
            ("terms", "Regulamin"), ("privacy", "Polityka prywatności"),
            ("safety", "Informacja o monitoringu"))
    ]


class PreflightTest(unittest.TestCase):
    def test_three_complete_docs(self):
        results = module.validate_document_bundle(sample())
        assert len(results) == 3
        assert all(len(d["sha256"]) == 64 for d in results)

    def test_missing_or_extra(self):
        for count in (0, 1, 2, 4):
            with self.subTest(count=count):
                docs = sample()
                while len(docs) < count:
                    docs.append({**docs[0], "kind": f"extra{len(docs)}"})
                with self.assertRaises(ValueError):
                    module.validate_document_bundle(docs[:count])

    def test_duplicate_type(self):
        docs = sample()
        docs[1]["kind"] = "terms"
        with self.assertRaises(ValueError):
            module.validate_document_bundle(docs)

    def test_draft_placeholder_rejected(self):
        docs = sample()
        docs[0]["content_markdown"] += " [Do uzupełnienia: NIP]"
        with self.assertRaises(ValueError):
            module.validate_document_bundle(docs)

    def test_missing_fields(self):
        for key in ("kind", "version", "title", "content_markdown"):
            docs = sample()
            docs[0][key] = " "
            with self.subTest(key=key), self.assertRaises(ValueError):
                module.validate_document_bundle(docs)


if __name__ == "__main__":
    unittest.main()
