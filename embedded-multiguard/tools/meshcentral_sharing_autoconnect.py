"""Patch a pinned MeshCentral sharing.handlebars with opt-in MultiGuard auto-connect.

Never patches production implicitly. Run against a staging *copy*, then review diff.
The guest-sharing URL remains the authorization boundary; this only invokes the
same on-page Connect action after the MeshCentral guest page enables it.
"""
from __future__ import annotations

import argparse
from pathlib import Path

MARKER = "/* MULTIGUARD_GUEST_AUTOCONNECT_V1 */"
ANCHOR = "        start();"
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
    if source.count(ANCHOR) != 1 or "function connectDesktop(e, contype, tsid, consent)" not in source:
        raise ValueError("Unexpected MeshCentral template version; review manually")
    if "function connectDesktop(e, contype, tsid, consent)" not in source:
        raise ValueError("Expected native desktop connector missing")
    if "var urlargs = parseUriArgs();" not in source:
        raise ValueError("Expected URL argument parser missing")
    # Preserve upstream whitespace and script closing tags across MeshCentral 1.2.5 builds.
    addition = INSERT.split("    </script>", 1)[0].rstrip("\n")
    if "\r\n" in source:
        addition = addition.replace("\n", "\r\n")
    return source.replace(ANCHOR, addition)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path, help="staging copy of sharing.handlebars")
    parser.add_argument("destination", type=Path, help="new patched output path")
    args = parser.parse_args()
    if args.source.resolve() == args.destination.resolve():
        parser.error("source and destination must differ; no in-place production editing")
    if args.destination.exists():
        parser.error("destination already exists; refusing overwrite")
    # newline="" prevents implicit CRLF-to-LF conversion in the original template.
    with args.source.open("r", encoding="utf-8", newline="") as source_file:
        original = source_file.read()
    updated = patch(original)
    with args.destination.open("w", encoding="utf-8", newline="") as target_file:
        target_file.write(updated)


if __name__ == "__main__":
    main()
