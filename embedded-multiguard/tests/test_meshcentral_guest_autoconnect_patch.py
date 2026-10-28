"""Offline tests for the opt-in MeshCentral guest viewer auto-connect patch."""
from __future__ import annotations

import importlib.util
import pathlib
import unittest

PATCH_FILE = pathlib.Path(__file__).resolve().parents[1] / "tools" / "meshcentral_sharing_autoconnect.py"
spec = importlib.util.spec_from_file_location("mesh_sharing_patch", PATCH_FILE)
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class MeshSharingAutoConnectTests(unittest.TestCase):
    def setUp(self):
        self.source = """<script>
        var urlargs = parseUriArgs();
        function connectDesktop(e, contype, tsid, consent) {}
        start();
    </script>"""

    def test_explicit_opt_in_and_native_connect_only(self):
        result = module.patch(self.source)
        self.assertIn("String(urlargs.mgautoconnect || '') === '1'", result)
        self.assertIn("connectDesktop(null, 3)", result)
        self.assertIn("button.disabled", result)
        self.assertIn("attempts >= limit", result)
        self.assertNotIn("eval(", result)

    def test_meshcentral_125_alternate_closing_tag_spacing(self):
        template = self.source.replace("        start();\n    </script>", "        start();\n        </script>")
        result = module.patch(template)
        self.assertIn(module.MARKER, result)
        self.assertEqual(result.count("</script>"), 1)
        self.assertIn("connectDesktop(null, 3)", result)

    def test_patcher_is_idempotence_safe(self):
        result = module.patch(self.source)
        with self.assertRaises(ValueError):
            module.patch(result)

    def test_unknown_upstream_template_fails_closed(self):
        with self.assertRaises(ValueError):
            module.patch(self.source.replace("start();", "begin();"))
        with self.assertRaises(ValueError):
            module.patch(self.source.replace("parseUriArgs();", "new URLSearchParams();"))


if __name__ == "__main__":
    unittest.main()
