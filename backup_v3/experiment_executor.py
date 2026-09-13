#!/usr/bin/env python3

import json
import sys
from pathlib import Path

from agent.experiment_runner import ExperimentRunner
from agent.flag_engine import FlagEngine


class ExperimentExecutor:

    def __init__(self, challenge):
        self.challenge = Path(challenge).resolve()
        self.context_file = (
            self.challenge / ".cyberai" / "context.json"
        )

        self.runner = ExperimentRunner(
            str(self.challenge),
            timeout=30,
        )

    def load_context(self):
        if not self.context_file.exists():
            raise FileNotFoundError(
                f"Context introuvable : {self.context_file}"
            )

        with self.context_file.open(
            "r",
            encoding="utf-8",
        ) as f:
            return json.load(f)

    def get_plans(self, context):
        """
        Utilise les hypothèses présentes dans le contexte
        et les transforme en plans d'exécution.
        """

        hypotheses = context.get("hypotheses", [])

        if not isinstance(hypotheses, list):
            return []

        hypotheses = [
            h for h in hypotheses
            if isinstance(h, dict)
            and h.get("name")
        ]

        hypotheses.sort(
            key=lambda x: x.get("confidence", 0),
            reverse=True,
        )

        plans = []

        for index, hypothesis in enumerate(
            hypotheses,
            1,
        ):
            name = hypothesis["name"]

            plans.append({
                "id": f"exp-{index:03d}",
                "hypothesis": name,
                "confidence": hypothesis.get(
                    "confidence",
                    0,
                ),
                "reason": hypothesis.get(
                    "reason",
                    "",
                ),
                "status": "PLANNED",
            })

        return plans

    def execute_probe(self):
        """
        Première expérience générique.

        Elle vérifie que l'environnement d'exécution
        fonctionne réellement.

        Aucune hypothèse n'est considérée comme validée
        avec ce probe.
        """

        return self.runner.run(
            [
                sys.executable,
                "-c",
                (
                    "print('CYBERAI_RUNTIME_OK')"
                ),
            ]
        )

    def scan_result(self, result, experiment_id):
        """
        Analyse stdout/stderr avec le FlagEngine.
        """

        flags = []

        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")

        if stdout:
            flags.extend(
                FlagEngine.extract_from_text(
                    stdout,
                    f"{experiment_id}.stdout",
                )
            )

        if stderr:
            flags.extend(
                FlagEngine.extract_from_text(
                    stderr,
                    f"{experiment_id}.stderr",
                )
            )

        return flags

    def execute(self):
        context = self.load_context()

        plans = self.get_plans(context)

        experiments = []
        all_flags = []

        print()
        print("=" * 70)
        print("🚀 CYBERAI — EXPERIMENT EXECUTOR")
        print("=" * 70)

        print()
        print(
            "Hypothèses à tester :",
            len(plans),
        )

        for plan in plans:

            experiment_id = plan["id"]

            print()
            print(
                f"[{experiment_id}] "
                f"{plan['hypothesis']}"
            )

            plan["status"] = "RUNNING"

            print("    → Runtime probe...")

            result = self.execute_probe()

            flags = self.scan_result(
                result,
                experiment_id,
            )

            plan["status"] = (
                "FLAG_FOUND"
                if flags
                else "COMPLETED"
            )

            experiment = {
                "id": experiment_id,
                "hypothesis": plan["hypothesis"],
                "confidence": plan["confidence"],
                "status": plan["status"],
                "runtime": result,
                "flags": flags,
            }

            experiments.append(experiment)

            all_flags.extend(flags)

            print(
                "    Status :",
                plan["status"],
            )

            print(
                "    Return :",
                result.get("returncode"),
            )

            print(
                "    Time   :",
                result.get("duration"),
                "s",
            )

            if flags:
                print(
                    "    🏁 FLAGS :",
                    len(flags),
                )
            else:
                print(
                    "    [-] Aucun flag"
                )

        context["experiments"] = experiments

        if all_flags:
            context["flags"] = all_flags

        context.setdefault(
            "metadata",
            {},
        )

        context["metadata"][
            "experiment_executor"
        ] = {
            "status": "COMPLETED",
            "experiments": len(experiments),
            "flags": len(all_flags),
        }

        self.context_file.parent.mkdir(
            parents=True,
            exist_ok=True,
        )

        with self.context_file.open(
            "w",
            encoding="utf-8",
        ) as f:
            json.dump(
                context,
                f,
                indent=2,
                ensure_ascii=False,
            )

        print()
        print("=" * 70)

        if all_flags:
            print(
                f"🏁 FLAGS TROUVÉS : {len(all_flags)}"
            )

            for flag in all_flags:
                print(
                    "   ",
                    flag,
                )
        else:
            print(
                "[-] Aucun flag trouvé par les expériences."
            )

        print()
        print(
            "[+] Context sauvegardé :",
            self.context_file,
        )

        return context


def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python -m agent.experiment_executor "
            "<challenge>"
        )
        raise SystemExit(1)

    executor = ExperimentExecutor(
        sys.argv[1]
    )

    executor.execute()


if __name__ == "__main__":
    main()
