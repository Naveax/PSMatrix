from __future__ import annotations

import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PUBLISHER = ROOT / "scripts" / "ga" / "publish_final_immutable_release.py"
VERIFIER = ROOT / "scripts" / "ga" / "verify_final_immutable_release.py"


class ImmutablePublicationReservationBindingTests(unittest.TestCase):
    def test_publisher_binds_reservation_after_reserve_before_execute(self) -> None:
        text = PUBLISHER.read_text(encoding="utf-8")
        main_start = text.index("def main")
        reserve = text.index("_reserve_publication_output(", main_start)
        bind = text.index(
            'plan["publication_receipt_output_reserved_before_mutation"] = True',
            main_start,
        )
        execute = text.index("execute_plan(", main_start)
        self.assertLess(reserve, bind)
        self.assertLess(bind, execute)

    def test_verifier_requires_and_propagates_reservation_binding(self) -> None:
        text = VERIFIER.read_text(encoding="utf-8")
        self.assertIn(
            'publication_operation.get(\n        "publication_receipt_output_reserved_before_mutation"',
            text,
        )
        self.assertIn(
            'result["publication_receipt_output_reserved_before_mutation"] = True',
            text,
        )


if __name__ == "__main__":
    unittest.main()
