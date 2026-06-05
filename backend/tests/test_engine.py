"""Run all synthetic cases through the investigation engine and print results.

Usage:
    cd backend
    python -m tests.test_engine
"""

from __future__ import annotations

import asyncio
import json
import sys

from ..investigation.engine import InvestigationEngine
from .synthetic_alerts import SYNTHETIC_ALERTS

# ANSI colours
_RED = "\033[91m"
_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_CYAN = "\033[96m"
_BOLD = "\033[1m"
_RESET = "\033[0m"

_LEVEL_COLOURS = {
    "LOW": _GREEN,
    "MEDIUM": _YELLOW,
    "HIGH": _RED,
    "CRITICAL": _RED + _BOLD,
}
_ACTION_COLOURS = {
    "CLEAR": _GREEN,
    "REVIEW": _YELLOW,
    "ESCALATE": _RED,
    "BLOCK": _RED + _BOLD,
}


def _colour(text: str, colour: str) -> str:
    return f"{colour}{text}{_RESET}"


async def test_all_cases() -> None:
    engine = InvestigationEngine()
    passed = 0

    print(f"\n{_BOLD}{'='*70}{_RESET}")
    print(f"{_BOLD}  FraudOS — Synthetic Alert Test Runner{_RESET}")
    print(f"{_BOLD}{'='*70}{_RESET}\n")

    for i, alert in enumerate(SYNTHETIC_ALERTS, 1):
        print(f"{_CYAN}{_BOLD}[{i}/{len(SYNTHETIC_ALERTS)}] {alert.alert_type.value}{_RESET}")
        print(f"  TXN ID : {alert.transaction_id}")
        print(f"  Amount : ₹{alert.amount:,.2f}")
        print(f"  Trigger: {alert.rule_trigger}")

        try:
            report = await engine.investigate(alert)

            level_col = _LEVEL_COLOURS.get(report.risk_level.value, "")
            action_col = _ACTION_COLOURS.get(report.recommended_action.value, "")

            print(f"  {_BOLD}Risk Score  :{_RESET} {_colour(str(report.risk_score), level_col)}/100")
            print(f"  {_BOLD}Risk Level  :{_RESET} {_colour(report.risk_level.value, level_col)}")
            print(f"  {_BOLD}Action      :{_RESET} {_colour(report.recommended_action.value, action_col)}")
            print(f"  {_BOLD}Confidence  :{_RESET} {report.confidence:.0%}")
            print(f"  {_BOLD}Flags       :{_RESET} {', '.join(report.flags) if report.flags else 'none'}")
            print(f"  {_BOLD}Latency     :{_RESET} {report.processing_time_ms}ms")
            print(f"  {_BOLD}Narrative   :{_RESET}")
            # Wrap narrative at ~80 chars
            narrative = report.investigation_narrative
            for chunk in [narrative[j:j+78] for j in range(0, len(narrative), 78)]:
                print(f"    {chunk}")
            passed += 1
        except Exception as exc:
            print(f"  {_RED}ERROR: {exc}{_RESET}")

        print()

    print(f"{_BOLD}{'='*70}{_RESET}")
    status = _GREEN if passed == len(SYNTHETIC_ALERTS) else _RED
    print(
        f"  Results: {_colour(str(passed), status)}/{len(SYNTHETIC_ALERTS)} cases completed successfully"
    )
    print(f"{_BOLD}{'='*70}{_RESET}\n")

    if passed < len(SYNTHETIC_ALERTS):
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(test_all_cases())
