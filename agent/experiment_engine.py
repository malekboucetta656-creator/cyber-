#!/usr/bin/env python3
"""
ExperimentEngine v0.3 - version minimale
Objectif : tester des hypothèses pwn de base et chercher un flag.
"""

from __future__ import annotations

import re
import subprocess
import time
from pathlib import Path
from typing import Any


FLAG_PATTERNS = [
    re.compile(r"FLAG\{[^\}]+\}", re.IGNORECASE),
    re.compile(r"flag\{[^\}]+\}", re.IGNORECASE),
    re.compile(r"CTF\{[^\}]+\}", re.IGNORECASE),
    re.compile(r"HTB\{[^\}]+\}", re.IGNORECASE),
]


class ExperimentEngine:
    def __init__(self, context):
        self.context = context
        self.experiments: list[dict[str, Any]] = []

    # ---------------------------------------------------------
    # Utilitaires
    # ---------------------------------------------------------

    def _find_binaries(self) -> list[Path]:
        binaries = []
        challenge = Path(self.context.challenge)

        # Depuis les résultats PwnEngine
        for name, result in self.context.module_results.items():
            if "pwn_engine" not in name:
                continue
            inner = result.get("result") if isinstance(result, dict) else None
            if not isinstance(inner, dict):
                continue
            for b in inner.get("binaries", []):
                p = Path(b)
                if p.exists() and p.is_file():
                    binaries.append(p)

        # Fallback : chercher des ELF dans le challenge
        if not binaries and challenge.exists():
            for p in challenge.rglob("*"):
                if p.is_file() and not p.name.endswith((".c", ".h", ".txt", ".md")):
                    try:
                        with p.open("rb") as f:
                            if f.read(4) == b"\x7fELF":
                                binaries.append(p)
                    except Exception:
                        pass

        return binaries

    def _search_flag(self, text: str) -> str | None:
        if not text:
            return None
        for pattern in FLAG_PATTERNS:
            match = pattern.search(text)
            if match:
                return match.group(0)
        return None

    def _run_binary(self, binary: Path, data: bytes, timeout: float = 1.5) -> dict:
        try:
            proc = subprocess.run(
                [str(binary)],
                input=data,
                capture_output=True,
                timeout=timeout,
            )
            stdout = proc.stdout.decode("utf-8", errors="replace")
            stderr = proc.stderr.decode("utf-8", errors="replace")
            return {
                "ok": True,
                "returncode": proc.returncode,
                "stdout": stdout,
                "stderr": stderr,
                "crashed": proc.returncode < 0,
            }
        except subprocess.TimeoutExpired:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": "timeout",
                "crashed": False,
                "error": "timeout",
            }
        except Exception as exc:
            return {
                "ok": False,
                "returncode": None,
                "stdout": "",
                "stderr": str(exc),
                "crashed": False,
                "error": str(exc),
            }

    # ---------------------------------------------------------
    # Expériences
    # ---------------------------------------------------------

    def exp_flag_in_strings(self, binary: Path) -> dict:
        """Cherche un flag directement dans les strings du binaire."""
        exp = {
            "id": f"flag_strings_{binary.name}",
            "hypothesis": "Flag present in binary",
            "category": "pwn",
            "type": "flag_strings",
            "status": "RUNNING",
            "binary": str(binary),
            "observations": [],
            "flag_found": None,
            "validated": False,
        }

        try:
            proc = subprocess.run(
                ["strings", "-a", "-n", "4", str(binary)],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = proc.stdout or ""
            flag = self._search_flag(output)
            exp["stdout"] = output[:2000]
            if flag:
                exp["flag_found"] = flag
                exp["validated"] = True
                exp["status"] = "VALIDATED"
                exp["observations"].append(f"Flag found in strings: {flag}")
            else:
                exp["status"] = "INCONCLUSIVE"
                exp["observations"].append("No flag pattern in strings")
        except Exception as exc:
            exp["status"] = "ERROR"
            exp["observations"].append(str(exc))

        return exp

    def exp_run_with_inputs(self, binary: Path) -> dict:
        """Lance le binaire avec plusieurs inputs et cherche un flag / crash."""
        exp = {
            "id": f"run_inputs_{binary.name}",
            "hypothesis": "Reach Win Function / Memory Corruption",
            "category": "pwn",
            "type": "run_inputs",
            "status": "RUNNING",
            "binary": str(binary),
            "observations": [],
            "flag_found": None,
            "validated": False,
            "runs": [],
        }

        payloads = [
            b"test\n",
            b"A" * 80 + b"\n",
            b"A" * 200 + b"\n",
            b"%x%x%x%x\n",
        ]

        for payload in payloads:
            result = self._run_binary(binary, payload)
            exp["runs"].append({
                "input_len": len(payload),
                "returncode": result.get("returncode"),
                "crashed": result.get("crashed"),
                "stdout": result.get("stdout", "")[:500],
                "stderr": result.get("stderr", "")[:300],
            })

            combined = (result.get("stdout") or "") + "\n" + (result.get("stderr") or "")
            flag = self._search_flag(combined)
            if flag:
                exp["flag_found"] = flag
                exp["validated"] = True
                exp["status"] = "VALIDATED"
                exp["observations"].append(f"Flag found in process output: {flag}")
                break

            if result.get("crashed"):
                exp["observations"].append(
                    f"Crash detected with input length {len(payload)}"
                )

        if exp["status"] == "RUNNING":
            if any("Crash detected" in o for o in exp["observations"]):
                exp["status"] = "INCONCLUSIVE"
                exp["observations"].append("Crash observed but no flag recovered")
            else:
                exp["status"] = "INCONCLUSIVE"
                exp["observations"].append("No flag and no clear crash")

        return exp

    # ---------------------------------------------------------
    # Boucle principale
    # ---------------------------------------------------------

    def run(self) -> list[dict]:
        print()
        print("╔══════════════════════════════════════════╗")
        print("║          EXPERIMENT ENGINE v0.3          ║")
        print("╚══════════════════════════════════════════╝")
        print()

        binaries = self._find_binaries()
        if not binaries:
            print("[-] Aucun binaire trouvé pour expérimentation.")
            return []

        print(f"[+] Binaires à tester : {len(binaries)}")
        for b in binaries:
            print(f"    • {b}")
        print()

        results = []

        for binary in binaries:
            # Expérience 1 : flag dans les strings
            print(f"[*] Experiment: flag_strings on {binary.name}")
            exp1 = self.exp_flag_in_strings(binary)
            results.append(exp1)
            self._print_exp(exp1)

            if exp1.get("validated") and exp1.get("flag_found"):
                self.context.flags.append(exp1["flag_found"])
                break

            # Expérience 2 : exécution avec inputs
            print(f"[*] Experiment: run_inputs on {binary.name}")
            exp2 = self.exp_run_with_inputs(binary)
            results.append(exp2)
            self._print_exp(exp2)

            if exp2.get("validated") and exp2.get("flag_found"):
                self.context.flags.append(exp2["flag_found"])
                break

        self.experiments = results
        self.context.experiments = results
        return results

    def _print_exp(self, exp: dict):
        status = exp.get("status")
        flag = exp.get("flag_found")
        print(f"    → status: {status}")
        if flag:
            print(f"    → FLAG: {flag}")
        for obs in exp.get("observations", []):
            print(f"    → {obs}")
        print()


def analyze(challenge=None, context=None):
    """
    Point d'entrée optionnel.
    Dans l'orchestrateur on appellera plutôt ExperimentEngine(context).run()
    """
    if context is None:
        return {"status": "ERROR", "error": "context required"}
    engine = ExperimentEngine(context)
    return engine.run()

