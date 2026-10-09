"""Offline owner panel security checks against production source (no real customer data)."""
from __future__ import annotations
import ast
import tempfile
import types
import unittest
from pathlib import Path, PurePosixPath

ROOT=Path(__file__).resolve().parents[1]
SERVICE=(ROOT/"app/routers/multiguard_service_panel.py").read_text(encoding="utf-8")
DIAG=(ROOT/"app/routers/multiguard_panel_diagnostics.py").read_text(encoding="utf-8")


class StubHTTPException(Exception):
    def __init__(self,status_code,detail):
        self.status_code=status_code
        super().__init__(detail)


class PanelSecurityTests(unittest.TestCase):
    def test_file_root_and_symlink_confinement(self):
        source_ast=ast.parse(SERVICE)
        fn=next(n for n in source_ast.body
                if isinstance(n,ast.FunctionDef) and n.name=="_media_file_path")
        with tempfile.TemporaryDirectory() as home, tempfile.TemporaryDirectory() as elsewhere:
            media=Path(home)
            (media/"service").mkdir()
            good=media/"service"/"ok.jpg"
            good.write_bytes(b"file-data")
            link=media/"service"/"shortcut.jpg"
            remote=Path(elsewhere)/"another.jpg"
            remote.write_bytes(b"not-in-media-root")
            link.symlink_to(remote)
            ns={"Path":Path,"PurePosixPath":PurePosixPath,
                "HTTPException":StubHTTPException,
                "settings":types.SimpleNamespace(media_root=home)}
            exec(compile(ast.Module(body=[fn],type_ignores=[]),"<owner-media>", "exec"),ns)
            resolve=ns["_media_file_path"]
            self.assertEqual(good,resolve("service/ok.jpg"))
            for invalid in ("", "service/not-here.jpg", str(remote), str(Path("..")/"elsewhere.jpg"),"service/shortcut.jpg"):
                with self.subTest(key=invalid):
                    with self.assertRaises(StubHTTPException) as caught:
                        resolve(invalid)
                    self.assertEqual(404,caught.exception.status_code)

    def test_no_public_photo_or_cross_order_read(self):
        for expected in (
            '@router.get("/multiguard/panel/service/{order_id}/media/{media_id}")',
            'Depends(_panel_auth)',
            "m.id=:media_id AND m.service_order_id=:order_id",
            "m.deleted_at IS NULL AND o.deleted_at IS NULL",
            "X-Content-Type-Options",
            'media_type=mime if can_inline else "application/octet-stream"',
            "Cache-Control",
            "Content-Security-Policy",
            '"image/jpeg","image/png","image/webp","image/gif"',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected,SERVICE)

    def test_diagnostic_plans_do_not_activate_commercial_license(self):
        for expected in (
            "guard.owner_diagnostic_plans_audit",
            "guard.owner_diagnostic_plans",
            "planned_duration_days",
            "PREPARED",
            "CANCELLED",
            "_token_valid(csrf_token)",
            "Depends(_panel_auth)",
            "no customer activation",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected,DIAG)
        self.assertNotIn("_keygate_create_license(",DIAG)
        self.assertNotIn("_signed_envelope(",DIAG)
        self.assertNotIn("UPDATE guard.license_links",DIAG)
        self.assertNotIn("UPDATE guard.installations",DIAG)


if __name__=="__main__":
    unittest.main(verbosity=2)
