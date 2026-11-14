#!/usr/bin/env python3
"""Offline regression tests: prerelease version ordering and updater asset naming."""
from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "embedded-multiguard" / "app" / "routers" / "multiguard_semver.py"
spec = importlib.util.spec_from_file_location("multiguard_semver", SOURCE)
assert spec is not None and spec.loader is not None
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class ReleaseSemverTests(unittest.TestCase):
    def test_beta_upgrade_same_core_version(self):
        self.assertLess(module.semver_key("0.3.46-beta.28"), module.semver_key("0.3.46-beta.29"))
        self.assertLess(module.semver_key("0.3.46-beta.9"), module.semver_key("0.3.46-beta.10"))
        self.assertLess(module.semver_key("0.3.46-beta.29"), module.semver_key("0.3.46"))

    def test_semver_precedence(self):
        self.assertLess(module.semver_key("0.3.46-alpha.8"), module.semver_key("0.3.46-beta.1"))
        self.assertLess(module.semver_key("0.3.46-beta.29"), module.semver_key("0.3.47-alpha.1"))
        self.assertEqual(module.semver_key("v0.3.46-beta.29+windows"), module.semver_key("0.3.46-beta.29"))
        with self.assertRaises(ValueError):
            module.semver_key("0.3.46-beta.029")
        with self.assertRaises(ValueError):
            module.semver_key("0.3.46-")
        with self.assertRaises(ValueError):
            module.semver_key("0.3.46-beta.29 junk")

    def test_release_tag_with_beta(self):
        match = module.TAG_RE.fullmatch("v0.3.46-beta.29-PILOT")
        self.assertIsNotNone(match)
        self.assertEqual(match.group("version"), "0.3.46-beta.29")
        self.assertEqual(match.group("channel"), "PILOT")

    def test_release_tag_legacy_stable_and_test(self):
        self.assertEqual(module.TAG_RE.fullmatch("v0.3.46-STABLE").group("version"), "0.3.46")
        self.assertEqual(module.TAG_RE.fullmatch("v0.3.46-beta.29-TEST-preview").group("version"), "0.3.46-beta.29")
        self.assertIsNone(module.TAG_RE.fullmatch("v0.3.46-beta.29-UNKNOWN"))

    def test_unique_signed_nsis_filename(self):
        self.assertTrue(module.is_windows_x64_nsis(
            "Multi-Guard_0.3.46-beta.29_x64-8a7f5cc4972d-20261113-231804-b7e7ffacc3a5-setup.exe"))
        self.assertTrue(module.is_windows_x64_nsis("Multi-Guard_0.3.46_x64-setup.exe"))
        self.assertFalse(module.is_windows_x64_nsis("Multi-Guard_0.3.46-beta.29_arm64-setup.exe"))
        self.assertFalse(module.is_windows_x64_nsis("../Multi-Guard_0.3.46_x64-setup.exe"))
        self.assertFalse(module.is_windows_x64_nsis("Multi-Guard_0.3.46_x64-setup.exe.sig"))


if __name__ == "__main__":
    unittest.main()
