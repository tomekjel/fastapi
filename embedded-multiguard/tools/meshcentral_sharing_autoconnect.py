"""Patch a pinned MeshCentral sharing.handlebars with opt-in MultiGuard auto-connect.

Never patches production implicitly. Run against a staging *copy*, then review diff.
The guest-sharing URL remains the authorization boundary; this only invokes the
same on-page Connect action after the MeshCentral guest page enables it.
"""
from __future__ import annotations

import argparse
from pathlib import Path

MARKER = "/* MULTIGUARD_GUEST_AUTOCONNECT_V1 */"
ANCHOR = "        start();\n    </script>"
INSERT = """        start();
        /* MULTIGUARD_GUEST_AUTOCONNECT_V1 */
        // Opt-in only: never alter other MeshCentral sharing links.
        if (String(urlargs.mgautoconnect || '') === '1') {
            (function () {
                var attempts = 0;
                var limit = 60; // 15 seconds at 250ms; no unbounded retry.
                var poll = setInterval(function () {
                    attempts += 1;
                    var button = document.getElementById('connectbutton1');
                    if (!button || button.disabled) {
                        if (attempts >= limit) clearInterval(poll);
                        return;
                    }
                    clearInterval(poll);
                    // Use MeshCentral's own normal guest desktop action.
                    connectDesktop(null, 3);
                }, 250);
            })();
        }
    </script>"""


def patch(source: str) -> str:
    if MARKER in source:
        raise ValueError("Already patched; no double injection")
    if source.count(ANCHOR) != 1:
        raise ValueError("Unexpected MeshCentral template version; review manually")
    if "function connectDesktop(e, contype, tsid, consent)" not in source:
        raise ValueError("Expected native desktop connector missing")
    if "var urlargs = parseUriArgs();" not in source:
        raise ValueError("Expected URL argument parser missing")
    return source.replace(ANCHOR, INSERT)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="staging copy of sharing.handlebars")
    parser.add_argument("destination", type=Path, help="new patched output path")
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ; no in-place production editing")
    if args.destination.exists():
        parser.error("destination already exists; refusing overwrite")
    args.destination.write_text(patch(args.source.read_text(encoding="utf-8")), encoding="utf-8")


if __name__ == "__main__":
    main()
