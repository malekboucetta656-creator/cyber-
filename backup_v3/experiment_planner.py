#!/usr/bin/env python3

import json
import sys
from pathlib import Path


class ExperimentPlanner:

    def __init__(self, context):
        self.context = context

    def hypotheses(self):
        values = self.context.get("hypotheses", [])

        if not isinstance(values, list):
            return []

        return sorted(
            [
                h for h in values
                if isinstance(h, dict)
                and h.get("name")
            ],
            key=lambda x: x.get("confidence", 0),
            reverse=True,
        )

    def plan_for(self, hypothesis):
        name = hypothesis["name"]
        confidence = hypothesis.get("confidence", 0)
        reason = hypothesis.get("reason", "")

        return {
            "hypothesis": name,
            "confidence": confidence,
            "reason": reason,
            "status": "PLANNED",
            "requires": {
                "runtime": True,
                "browser": "DOM" in name
                or "Navigation" in name
                or "XSS" in name,
                "bot": "Bot" in name,
            },
            "observables": [
                "stdout",
                "stderr",
                "returncode",
                "created_files",
                "modified_files",
            ],
            "flag_search": True,
        }

    def build(self):
        return [
            self.plan_for(h)
            for h in self.hypotheses()
        ]

    def run(self):
        plans = self.build()

        return {
            "planner": "ExperimentPlanner",
            "challenge": self.context.get(
                "challenge"
            ),
            "plans": plans,
            "count": len(plans),
        }


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python -m agent.experiment_planner "
            "<challenge>"
        )
        raise SystemExit(1)

    challenge = Path(sys.argv[1]).resolve()
    context_file = (
        challenge / ".cyberai" / "context.json"
    )

    if not context_file.exists():
        print(
            f"[!] Context introuvable : {context_file}"
        )
        raise SystemExit(1)

    with context_file.open() as f:
        context = json.load(f)

    planner = ExperimentPlanner(context)
    result = planner.run()

    print()
    print("=" * 70)
    print("🧠 CYBERAI — EXPERIMENT PLANNER")
    print("=" * 70)

    print()
    print(
        "Expériences planifiées :",
        result["count"],
    )

    for i, plan in enumerate(
        result["plans"], 1
    ):
        print()
        print(
            f"[{i}] {plan['hypothesis']}"
        )
        print(
            "    Confidence :",
            plan["confidence"],
        )
        print(
            "    Browser    :",
            plan["requires"]["browser"],
        )
        print(
            "    Bot        :",
            plan["requires"]["bot"],
        )
        print(
            "    Flag scan  :",
            plan["flag_search"],
        )


if __name__ == "__main__":
    main()
