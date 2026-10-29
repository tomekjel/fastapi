#!/usr/bin/env python3
"""Isolated contract checks for MultiGuard activation document parsing.

Executes the exact production _required_documents function AST without
importing the database-connected application or production settings.
"""
from __future__ import annotations

import ast
import hashlib
import json
import unittest
from pathlib import Path


class HTTPException(Exception):
    def __init__(self, status_code, detail):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)


SOURCE = Path(__file__).resolve().parents[1] / "app/routers/multiguard_license.py"
tree = ast.parse(SOURCE.read_text(encoding="utf-8"))
selected = next(
    node for node in tree.body
    if isinstance(node, ast.FunctionDef) and node.name == "_required_documents"
)
settings = {"value": []}
scope = {
    "HTTPException": HTTPException,
    "hashlib": hashlib,
    "json": json,
    "_setting": lambda name, default=None: settings["value"],
}
exec(compile(ast.Module(body=[selected], type_ignores=[]), str(SOURCE), "exec"), scope)
parse_documents = scope["_required_documents"]


class ActivationDocumentContract(unittest.TestCase):
    def setUp(self):
        settings["value"] = []

    def assert_rejected(self, docs):
        settings["value"] = docs
        with self.assertRaises(HTTPException) as error:
            parse_documents()
        self.assertEqual(error.exception.status_code, 503)

    def test_missing_documents(self):
        self.assert_rejected([])

    def test_empty_string_config(self):
        self.assert_rejected("")
        self.assert_rejected("   ")

    def test_json_empty_list(self):
        self.assert_rejected("[]")

    def test_wrong_document_counts(self):
        for n in (1, 2, 4):
            with self.subTest(count=n):
                self.assert_rejected(self.docs(n))

    def test_duplicate_kinds(self):
        docs = self.docs(3)
        docs[1]["kind"] = docs[0]["kind"]
        self.assert_rejected(docs)

    def test_whitespace_content(self):
        docs = self.docs(3)
        docs[1]["content_markdown"] = "   "
        self.assert_rejected(docs)

    def test_invalid_json(self):
        self.assert_rejected("{not valid json")

    def test_incomplete_document_fields(self):
        for missing in ("kind", "version", "title", "content_markdown"):
            with self.subTest(missing=missing):
                docs = self.docs(3)
                docs[0].pop(missing)
                self.assert_rejected(docs)

    def test_wrong_json_shape(self):
        for malformed in ("{}", '{"documents":[]}', 'null', '123'):
            with self.subTest(value=malformed):
                self.assert_rejected(malformed)

    def test_nonstring_document_fields_are_rejected(self):
        for field, value in (
            ("kind", 123), ("version", 2), ("title", ["wrong"]),
            ("content_markdown", {"html": "wrong"}),
            ("version", None), ("title", True),
        ):
            with self.subTest(field=field, value=value):
                docs = self.docs(3)
                docs[0][field] = value
                self.assert_rejected(docs)

    def test_wrong_document_item_shape(self):
        docs = self.docs(3)
        docs[1] = "invalid"
        self.assert_rejected(docs)

    def test_unicode_hash_is_utf8(self):
        docs = self.docs(3)
        docs[1]["content_markdown"] = "Zażółć gęślą jaźń — prywatność"
        settings["value"] = docs
        parsed = parse_documents()
        self.assertEqual(
            parsed[1]["sha256"],
            hashlib.sha256(docs[1]["content_markdown"].encode("utf-8")).hexdigest(),
        )

    def test_valid_documents_hash_and_content(self):
        docs = self.docs(3)
        settings["value"] = json.dumps(docs, ensure_ascii=False)
        output = parse_documents()
        self.assertEqual(len(output), 3)
        for source, result in zip(docs, output):
            self.assertEqual(result["kind"], source["kind"])
            self.assertEqual(result["version"], source["version"])
            self.assertEqual(result["contentMarkdown"], source["content_markdown"])
            self.assertEqual(
                result["sha256"],
                hashlib.sha256(source["content_markdown"].encode("utf-8")).hexdigest(),
            )

    @staticmethod
    def docs(n):
        return [
            {"kind": f"doc-{i}", "version": "1.0", "title": f"Dokument {i}",
             "content_markdown": f"Pełna treść dokumentu {i}"}
            for i in range(n)
        ]


if __name__ == "__main__":
    unittest.main()
