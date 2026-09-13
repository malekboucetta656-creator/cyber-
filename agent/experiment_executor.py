#!/usr/bin/env python3

import json
import os
import sys
import traceback
from pathlib import Path

from agent.experiment_runner import ExperimentRunner
from agent.flag_engine import FlagEngine


class ExperimentExecutor:
    """
    Exécuteur global d'expériences CyberAI.

    Règle importante :
        observation != exploit validé

    Chaque moteur spécialisé doit retourner des preuves.
    L'Executor les stocke dans context.json afin que le Solver
    puisse décider de la prochaine expérience.
    """

    def __init__(self, challenge):
        self.challenge = Path(challenge).resolve()

        self.context_file = (
            self.challenge
            / ".cyberai"
            / "context.json"
        )

        self.runner = ExperimentRunner(
            str(self.challenge),
            timeout=30,
        )

    # ---------------------------------------------------------
    # CONTEXT
    # ---------------------------------------------------------

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

    def save_context(self, context):
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

    # ---------------------------------------------------------
    # GENERIC HYPOTHESES
    # ---------------------------------------------------------

    def get_plans(self, context):
        hypotheses = context.get(
            "hypotheses",
            [],
        )

        if not isinstance(hypotheses, list):
            hypotheses = []

        hypotheses = [
            h
            for h in hypotheses
            if isinstance(h, dict)
            and h.get("name")
        ]

        hypotheses.sort(
            key=lambda x: float(
                x.get("confidence", 0)
            ),
            reverse=True,
        )

        plans = []

        for index, hypothesis in enumerate(
            hypotheses,
            1,
        ):
            plans.append(
                {
                    "id": f"exp-{index:03d}",
                    "hypothesis": hypothesis["name"],
                    "confidence": hypothesis.get(
                        "confidence",
                        0,
                    ),
                    "reason": hypothesis.get(
                        "reason",
                        "",
                    ),
                    "status": "PLANNED",
                }
            )

        return plans

    # ---------------------------------------------------------
    # PWN MODULE
    # ---------------------------------------------------------

    def get_pwn_result(self, context):
        """
        Cherche le résultat du PwnEngine dans module_results.

        Compatible avec plusieurs noms afin que l'architecture
        reste évolutive.
        """

        module_results = context.get(
            "module_results",
            {},
        )

        if not isinstance(module_results, dict):
            return {}

        possible_names = (
            "agent.pwn_engine",
            "pwn_engine",
            "PwnEngine",
        )

        for name in possible_names:
            result = module_results.get(name)

            if isinstance(result, dict):

                # Cas module standard :
                # {
                #   status,
                #   module,
                #   result: {...}
                # }
                nested = result.get("result")

                if isinstance(nested, dict):
                    return nested

                return result

        return {}

    def run_pwn_runtime(self, context):
        """
        Lance le moteur runtime PWN.

        Aucun exploit n'est hardcodé ici.
        Le PwnRuntime doit découvrir les primitives
        dynamiquement.
        """

        try:
            from agent.pwn_runtime import PwnRuntimeEngine
        except Exception as exc:
            return {
                "status": "ERROR",
                "reason": (
                    "Impossible d'importer "
                    "PwnRuntimeEngine"
                ),
                "error": str(exc),
            }

        binary = self.find_binary(context)

        if binary is None:
            return {
                "status": "REJECTED",
                "reason": (
                    "Aucun binaire ELF trouvé "
                    "pour l'analyse PWN."
                ),
            }

        try:
            engine = PwnRuntimeEngine(
                str(binary)
            )

            result = engine.analyze()

            if isinstance(result, dict):
                return result

            return {
                "status": "RUNTIME_EVIDENCE",
                "result": result,
            }

        except TypeError:
            # Compatibilité avec les anciennes versions
            try:
                engine = PwnRuntimeEngine(
                    str(binary),
                    function=None,
                )

                result = engine.analyze()

                if isinstance(result, dict):
                    return result

                return {
                    "status": "RUNTIME_EVIDENCE",
                    "result": result,
                }

            except Exception as exc:
                return {
                    "status": "ERROR",
                    "error": str(exc),
                    "traceback": traceback.format_exc(),
                }

        except Exception as exc:
            return {
                "status": "ERROR",
                "error": str(exc),
                "traceback": traceback.format_exc(),
            }

    # ---------------------------------------------------------
    # BINARY DISCOVERY
    # ---------------------------------------------------------

    def find_binary(self, context):
        """
        Trouve un ELF dans le challenge.

        Priorité :
            1. résultats PwnEngine
            2. fichiers du contexte
            3. scan du dossier
        """

        pwn_result = self.get_pwn_result(
            context
        )

        binaries = pwn_result.get(
            "binaries",
            [],
        )

        if isinstance(binaries, list):

            for item in binaries:

                if isinstance(item, str):
                    path = Path(item)

                elif isinstance(item, dict):
                    path = Path(
                        item.get(
                            "file",
                            "",
                        )
                    )

                else:
                    continue

                if path.is_file():
                    return path.resolve()

        files = context.get(
            "files",
            [],
        )

        if isinstance(files, list):

            for item in files:

                if not isinstance(item, str):
                    continue

                path = Path(item)

                if not path.is_file():
                    continue

                try:
                    data = path.read_bytes()[:4]

                    if data == b"\x7fELF":
                        return path.resolve()

                except Exception:
                    continue

        root = self.challenge

        try:
            for path in root.iterdir():

                if not path.is_file():
                    continue

                try:
                    if path.read_bytes()[:4] == b"\x7fELF":
                        return path.resolve()

                except Exception:
                    continue

        except Exception:
            pass

        return None

    # ---------------------------------------------------------
    # GENERIC RUNTIME PROBE
    # ---------------------------------------------------------

    def execute_generic_probe(self):
        """
        Probe minimal pour les catégories ne possédant
        pas encore de runtime spécialisé.
        """

        return self.runner.run(
            [
                sys.executable,
                "-c",
                "print('CYBERAI_RUNTIME_OK')",
            ]
        )

    # ---------------------------------------------------------
    # FLAG ANALYSIS
    # ---------------------------------------------------------

    def scan_result(
        self,
        result,
        experiment_id,
    ):
        flags = []

        if not isinstance(result, dict):
            return flags

        stdout = result.get(
            "stdout",
            "",
        )

        stderr = result.get(
            "stderr",
            "",
        )

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

        # Certains moteurs utilisent output
        output = result.get(
            "output",
            "",
        )

        if output:
            flags.extend(
                FlagEngine.extract_from_text(
                    output,
                    f"{experiment_id}.output",
                )
            )

        # Déduplication
        unique = []

        for flag in flags:
            if flag not in unique:
                unique.append(flag)

        return unique

    # ---------------------------------------------------------
    # EXPERIMENT STATUS
    # ---------------------------------------------------------

    def normalize_status(self, result):
        if not isinstance(result, dict):
            return "RUNTIME_EVIDENCE"

        status = str(
            result.get(
                "status",
                "",
            )
        ).upper()

        allowed = {
            "FLAG_FOUND",
            "EXPLOIT_VALIDATED",
            "RUNTIME_EVIDENCE",
            "STATIC_EVIDENCE",
            "BLOCKED_INFRASTRUCTURE",
            "REJECTED",
            "ERROR",
        }

        if status in allowed:
            return status

        if result.get("flags"):
            return "FLAG_FOUND"

        return "RUNTIME_EVIDENCE"

    # ---------------------------------------------------------
    # MAIN EXECUTION
    # ---------------------------------------------------------

    def execute(self):

        context = self.load_context()

        category = context.get(
            "category",
            "unknown",
        )

        plans = self.get_plans(
            context
        )

        experiments = []
        all_flags = []

        print()
        print("=" * 70)
        print("🚀 CYBERAI — EXPERIMENT EXECUTOR V3")
        print("=" * 70)
        print()
        print(
            "Category :",
            category,
        )
        print(
            "Hypothèses :",
            len(plans),
        )

        # -----------------------------------------------------
        # PWN
        # -----------------------------------------------------

        if category == "pwn":

            print()
            print(
                "╔══════════════════════════════════════╗"
            )
            print(
                "║       PWN RUNTIME EXPERIMENT         ║"
            )
            print(
                "╚══════════════════════════════════════╝"
            )

            pwn_result = self.run_pwn_runtime(
                context
            )

            status = self.normalize_status(
                pwn_result
            )

            flags = self.scan_result(
                pwn_result,
                "pwn-runtime",
            )

            if flags:
                status = "FLAG_FOUND"

            experiment = {
                "id": "pwn-runtime-001",
                "hypothesis": (
                    "PWN runtime exploitation"
                ),
                "confidence": 100,
                "status": status,
                "runtime": pwn_result,
                "flags": flags,
            }

            experiments.append(
                experiment
            )

            all_flags.extend(
                flags
            )

            print(
                "[PWN] Status :",
                status,
            )

            if isinstance(
                pwn_result,
                dict,
            ):
                if pwn_result.get("reason"):
                    print(
                        "[PWN] Reason :",
                        pwn_result["reason"],
                    )

                if pwn_result.get(
                    "candidate"
                ):
                    print(
                        "[PWN] Candidate :",
                        pwn_result["candidate"],
                    )

                if pwn_result.get(
                    "strategy"
                ):
                    print(
                        "[PWN] Strategy :",
                        pwn_result["strategy"],
                    )

            if flags:
                print(
                    "🏁 FLAG DETECTED :",
                    len(flags),
                )

            else:
                print(
                    "[-] Aucun flag détecté."
                )

        # -----------------------------------------------------
        # OTHER CATEGORIES
        # -----------------------------------------------------

        else:

            for plan in plans:

                experiment_id = plan["id"]

                print()
                print(
                    f"[{experiment_id}] "
                    f"{plan['hypothesis']}"
                )

                plan["status"] = "RUNNING"

                result = (
                    self.execute_generic_probe()
                )

                flags = self.scan_result(
                    result,
                    experiment_id,
                )

                status = (
                    "FLAG_FOUND"
                    if flags
                    else "RUNTIME_EVIDENCE"
                )

                plan["status"] = status

                experiments.append(
                    {
                        "id": experiment_id,
                        "hypothesis": plan[
                            "hypothesis"
                        ],
                        "confidence": plan[
                            "confidence"
                        ],
                        "status": status,
                        "runtime": result,
                        "flags": flags,
                    }
                )

                all_flags.extend(
                    flags
                )

                print(
                    "    Status :",
                    status,
                )

        # -----------------------------------------------------
        # UPDATE CONTEXT
        # -----------------------------------------------------

        context["experiments"] = (
            experiments
        )

        if all_flags:
            context["flags"] = all_flags

        context.setdefault(
            "metadata",
            {},
        )

        context["metadata"][
            "experiment_executor"
        ] = {
            "version": "V3",
            "status": "COMPLETED",
            "category": category,
            "experiments": len(
                experiments
            ),
            "flags": len(
                all_flags
            ),
        }

        # Runtime observations
        context["metadata"][
            "runtime_state"
        ] = {
            "executed": True,
            "category": category,
            "validation_required": True,
        }

        self.save_context(
            context
        )

        print()
        print("=" * 70)

        if all_flags:

            print(
                f"🏁 FLAGS TROUVÉS : "
                f"{len(all_flags)}"
            )

            for flag in all_flags:
                print(
                    "   ",
                    flag,
                )

        else:
            print(
                "[-] Aucun flag trouvé "
                "par les expériences."
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
            "Usage: python3 -m "
            "agent.experiment_executor "
            "<challenge>"
        )

        raise SystemExit(1)

    executor = ExperimentExecutor(
        sys.argv[1]
    )

    executor.execute()


if __name__ == "__main__":
    main()
