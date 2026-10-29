"""Contract tests for the real MultiGuard document parser.

Run from embedded-multiguard with the same test dependencies as the API suite.
These tests use no production database or credentials.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.routers import multiguard_license as license_api


@pytest.fixture(autouse=True)
def no_external_documents(monkeypatch):
    monkeypatch.setattr(license_api, "_setting", lambda name, default=None: default)


def test_missing_documents_fail_closed():
    with pytest.raises(HTTPException) as err:
        license_api._required_documents()
    assert err.value.status_code == 503


@pytest.mark.parametrize("count", [1, 2, 4])
def test_wrong_count_is_rejected(monkeypatch, count):
    docs = [
        {"kind": f"kind{i}", "version": "1.0", "title": "Dokument",
         "content_markdown": "Pełny tekst dokumentu"}
        for i in range(count)
    ]
    monkeypatch.setattr(license_api, "_setting", lambda name, default=None: docs)
    with pytest.raises(HTTPException) as err:
        license_api._required_documents()
    assert err.value.status_code == 503


def test_blank_content_is_rejected(monkeypatch):
    docs = [
        {"kind": f"kind{i}", "version": "1", "title": "Dokument",
         "content_markdown": "   " if i == 1 else "Tekst"}
        for i in range(3)
    ]
    monkeypatch.setattr(license_api, "_setting", lambda name, default=None: docs)
    with pytest.raises(HTTPException) as err:
        license_api._required_documents()
    assert err.value.status_code == 503


def test_duplicate_kind_is_rejected(monkeypatch):
    docs = [
        {"kind": "same", "version": str(i), "title": "Dokument",
         "content_markdown": "Pełny tekst"}
        for i in range(3)
    ]
    monkeypatch.setattr(license_api, "_setting", lambda name, default=None: docs)
    with pytest.raises(HTTPException) as err:
        license_api._required_documents()
    assert err.value.status_code == 503


def test_three_documents_have_content_and_correct_sha256(monkeypatch):
    import hashlib
    docs = [
        {"kind": f"kind{i}", "version": "1.0", "title": f"Dokument {i}",
         "content_markdown": f"Treść dokumentu {i}"}
        for i in range(3)
    ]
    monkeypatch.setattr(license_api, "_setting", lambda name, default=None: docs)
    result = license_api._required_documents()
    assert len(result) == 3
    for raw, parsed in zip(docs, result):
        assert parsed["contentMarkdown"] == raw["content_markdown"]
        assert parsed["sha256"] == hashlib.sha256(
            raw["content_markdown"].encode("utf-8")
        ).hexdigest()
