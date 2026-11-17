"""Static regression tests for MASTER 1.10 two-document acceptance.

No database, KeyGate, MeshCentral, or live installation is touched.
"""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[2]
SOURCE=(ROOT/"embedded-multiguard/app/routers/multiguard_license.py").read_text(encoding="utf-8")

class AcceptanceContract(unittest.TestCase):
    def test_only_two_current_documents_are_configured(self):
        self.assertIn('if len(result) != 2',SOURCE)
        self.assertIn('{"remote_policy", "browser_shield"}',SOURCE)
        self.assertIn('if len(required) != 2',SOURCE)
        self.assertNotIn('if len(required) != 3',SOURCE)
    def test_duplicate_or_outdated_acceptance_fails_before_keygate_changes(self):
        start=SOURCE.index('def acceptance(req: AcceptanceRequest)')
        part=SOURCE[start:SOURCE.index('    started = _utcnow()',start)]
        self.assertIn('len(req.documents) != 2',part)
        self.assertIn('len(received) != 2',part)
        self.assertIn('received != expected',part)
        self.assertNotIn('_keygate_set_valid_until',part)
    def test_existing_active_licenses_are_not_reset(self):
        self.assertIn('if link["lifecycle"] != "PENDING_ACCEPTANCE":',SOURCE)
        self.assertIn('accepted_documents',SOURCE)
if __name__=="__main__":
    unittest.main()
