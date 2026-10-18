import ast
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
UPDATES = (ROOT / "app/routers/multiguard_updates.py").read_text(encoding="utf-8")
SYNC = (ROOT / "scripts/sync_multiguard_releases.py").read_text(encoding="utf-8")

class BetaChannelIsolation(unittest.TestCase):
    def test_sources_compile(self):
        ast.parse(UPDATES)
        ast.parse(SYNC)

    def test_beta_is_valid_release_ring(self):
        self.assertIn('"BETA"', UPDATES)
        self.assertIn("'TEST','LICENSE_TEST','BETA','PILOT','STABLE'", UPDATES)
        self.assertIn('return "TEST", installation_uuid', UPDATES)

    def test_sync_requires_explicit_beta_tag_not_test(self):
        tag = re.search(r'TAG_RE = re.compile\(\s*r"([^"]+)"', SYNC).group(1)
        pattern = re.compile(tag, re.IGNORECASE)
        self.assertEqual(pattern.fullmatch("v0.3.45-beta.1-BETA").group("channel").upper(), "BETA")
        self.assertEqual(pattern.fullmatch("v0.3.45-beta.1-TEST").group("channel").upper(), "TEST")
        self.assertIsNone(pattern.fullmatch("v0.3.45-beta.1-STABLE-EXTRA"))

    def test_unpublished_draft_releases_remain_excluded(self):
        self.assertIn('if release.get("draft"):', SYNC)
        self.assertIn('continue', SYNC[SYNC.index('if release.get("draft"):'):][:60])

if __name__ == "__main__":
    unittest.main()
