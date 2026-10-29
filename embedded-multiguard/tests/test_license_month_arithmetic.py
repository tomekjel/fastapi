#!/usr/bin/env python3
"""Isolated tests of actual MultiGuard licence month arithmetic."""
from __future__ import annotations

import ast
import calendar
import unittest
from datetime import datetime, timezone
from pathlib import Path

source = Path(__file__).resolve().parents[1] / "app/routers/multiguard_license.py"
tree = ast.parse(source.read_text(encoding="utf-8"))
fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "_add_months")
ns = {"datetime": datetime, "calendar": calendar}
exec(compile(ast.Module(body=[fn], type_ignores=[]), str(source), "exec"), ns)
add_months = ns["_add_months"]


class LicenceMonthArithmetic(unittest.TestCase):
    def test_three_six_twelve_months(self):
        start = datetime(2026, 10, 29, 21, 0, tzinfo=timezone.utc)
        for months, year, month in ((3, 2027, 1), (6, 2027, 4), (12, 2027, 10)):
            with self.subTest(months=months):
                end = add_months(start, months)
                self.assertEqual((end.year, end.month, end.day), (year, month, 29))
                self.assertEqual(end.tzinfo, timezone.utc)
                self.assertEqual((end.hour, end.minute), (21, 0))

    def test_last_day_and_leap_year(self):
        jan31 = datetime(2027, 1, 31, tzinfo=timezone.utc)
        self.assertEqual(add_months(jan31, 1).date().isoformat(), "2027-02-28")
        leap = datetime(2024, 1, 31, tzinfo=timezone.utc)
        self.assertEqual(add_months(leap, 1).date().isoformat(), "2024-02-29")

    def test_extension_adds_to_existing_end_not_now(self):
        current_end = datetime(2027, 1, 29, tzinfo=timezone.utc)
        self.assertEqual(add_months(current_end, 12).date().isoformat(), "2028-01-29")

    def test_year_rollover(self):
        start = datetime(2026, 12, 15, tzinfo=timezone.utc)
        self.assertEqual(add_months(start, 3).date().isoformat(), "2027-03-15")


if __name__ == "__main__":
    unittest.main()
