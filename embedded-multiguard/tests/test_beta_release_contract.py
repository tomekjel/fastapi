"""Offline regression: Multi-Guard beta channel and release ordering."""
import ast
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]


def load_semver():
    path = ROOT / "app/routers/multiguard_updates.py"
    tree = ast.parse(path.read_text(encoding="utf-8"))
    regex = next(node for node in tree.body
                 if isinstance(node, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == "_SEMVER" for t in node.targets))
    function = next(node for node in tree.body
                    if isinstance(node, ast.FunctionDef) and node.name == "_semver")
    ns = {"re": re, "HTTPException": ValueError}
    # Keep pure SemVer logic independent of database, FastAPI and external services.
    exec(compile(ast.Module(body=[regex, function], type_ignores=[]), str(path), "exec"), ns)
    return ns["_semver"]


class BetaReleaseTests(unittest.TestCase):
    def test_beta_precedes_stable_and_ordered_builds(self):
        parse = load_semver()
        self.assertLess(parse("0.3.43"), parse("0.3.44-beta.1"))
        self.assertLess(parse("0.3.44-beta.1"), parse("0.3.44-beta.2"))
        self.assertLess(parse("0.3.44-beta.2"), parse("0.3.44"))
        self.assertLess(parse("0.3.44"), parse("0.3.45-beta.1"))

    def test_invalid_versions_rejected(self):
        parse = load_semver()
        for version in ("0.3.44-beta", "0.3.44-beta.a", "0.3.44-beta.1-extra", "0.3.44.1"):
            with self.subTest(version=version), self.assertRaises(Exception):
                parse(version)

    def test_github_beta_release_tag_accepted_by_sync(self):
        path = ROOT / "scripts/sync_multiguard_releases.py"
        tree = ast.parse(path.read_text(encoding="utf-8"))
        assignment = next(node for node in tree.body if isinstance(node, ast.Assign)
                          and any(isinstance(t, ast.Name) and t.id == "TAG_RE" for t in node.targets))
        ns = {"re": re}
        exec(compile(ast.Module(body=[assignment], type_ignores=[]), str(path), "exec"), ns)
        tag = ns["TAG_RE"].fullmatch("v0.3.44-beta.1-TEST")
        self.assertIsNotNone(tag)
        self.assertEqual(tag.group("version"), "0.3.44-beta.1")
        self.assertEqual(tag.group("channel"), "TEST")


if __name__ == "__main__":
    unittest.main()
