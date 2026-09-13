#!/usr/bin/env python3

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


class PwnEngine:
    """
    Analyseur PWN générique.

    IMPORTANT :
    - ne considère jamais une hypothèse comme exploit validé ;
    - ne contient aucune adresse ou solution spécifique à un challenge ;
    - produit des observations utilisables par GlobalSolver.
    """

    def __init__(self, challenge: str):
        self.challenge = Path(challenge).expanduser().resolve()
        self.result: dict[str, Any] = {
            "engine": "PwnEngine",
            "version": "1.0",
            "status": "ANALYZED",
            "files": [],
            "binaries": [],
            "sources": [],
            "protections": {},
            "symbols": [],
            "strings": [],
            "primitives": [],
            "targets": [],
            "hypotheses": [],
            "observations": [],
            "errors": [],
        }

    # ---------------------------------------------------------
    # UTILITIES
    # ---------------------------------------------------------

    def run_cmd(
        self,
        command: list[str],
        timeout: int = 10,
    ) -> tuple[int, str, str]:

        try:
            proc = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            return (
                proc.returncode,
                proc.stdout,
                proc.stderr,
            )

        except FileNotFoundError:
            return -127, "", f"command not found: {command[0]}"

        except subprocess.TimeoutExpired:
            return -124, "", "timeout"

        except Exception as exc:
            return -1, "", str(exc)

    # ---------------------------------------------------------
    # DISCOVERY
    # ---------------------------------------------------------

    def discover(self) -> None:

        if not self.challenge.exists():
            self.result["errors"].append(
                f"challenge not found: {self.challenge}"
            )
            self.result["status"] = "ERROR"
            return

        for path in self.challenge.rglob("*"):

            if not path.is_file():
                continue

            if any(
                part in {
                    ".git",
                    "node_modules",
                    "__pycache__",
                    ".venv",
                }
                for part in path.parts
            ):
                continue

            self.result["files"].append(str(path))

            if path.suffix.lower() in {
                ".c",
                ".cc",
                ".cpp",
                ".h",
            }:
                self.result["sources"].append(str(path))

        for path in self.challenge.rglob("*"):

            if not path.is_file():
                continue

            if not self.is_probable_elf(path):
                continue

            self.result["binaries"].append(str(path))

    # ---------------------------------------------------------
    # ELF DETECTION
    # ---------------------------------------------------------

    def is_probable_elf(self, path: Path) -> bool:

        try:
            with path.open("rb") as f:
                magic = f.read(4)

            return magic == b"\x7fELF"

        except Exception:
            return False

    # ---------------------------------------------------------
    # CHECKSEC
    # ---------------------------------------------------------

    def checksec(self, binary: str) -> None:

        if not shutil.which("checksec"):
            self.result["observations"].append(
                "checksec unavailable"
            )
            return

        code, stdout, stderr = self.run_cmd(
            ["checksec", "--file=" + binary]
        )

        if code == 0:
            self.result["protections"][binary] = stdout.strip()

        else:
            self.result["errors"].append(
                f"checksec failed for {binary}: {stderr.strip()}"
            )

    # ---------------------------------------------------------
    # SYMBOLS
    # ---------------------------------------------------------

    def analyze_symbols(self, binary: str) -> None:

        code, stdout, stderr = self.run_cmd(
            ["nm", "-an", binary]
        )

        if code != 0:
            self.result["errors"].append(
                f"nm failed for {binary}: {stderr.strip()}"
            )
            return

        interesting = {
            "main",
            "win",
            "flag",
            "game",
            "vuln",
            "shell",
            "gets",
            "system",
            "execve",
            "printf",
            "scanf",
            "fgets",
            "read",
            "write",
            "memcpy",
            "strcpy",
            "strncpy",
        }

        for line in stdout.splitlines():

            parts = line.split()

            if len(parts) < 3:
                continue

            address = parts[0]
            symbol_type = parts[1]
            name = parts[-1]

            if name in interesting:
                self.result["symbols"].append(
                    {
                        "binary": binary,
                        "address": address,
                        "type": symbol_type,
                        "name": name,
                    }
                )

    # ---------------------------------------------------------
    # STRINGS
    # ---------------------------------------------------------

    def analyze_strings(self, binary: str) -> None:

        code, stdout, stderr = self.run_cmd(
            ["strings", "-a", "-n", "4", binary]
        )

        if code != 0:
            return

        interesting_patterns = [
            r"flag",
            r"win",
            r"congrat",
            r"secret",
            r"shell",
            r"/bin/",
            r"/flag",
            r"password",
            r"token",
        ]

        compiled = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in interesting_patterns
        ]

        found = []

        for line in stdout.splitlines():

            line = line.strip()

            if not line:
                continue

            if any(regex.search(line) for regex in compiled):
                found.append(line)

        self.result["strings"].extend(
            {
                "binary": binary,
                "value": value,
            }
            for value in found
        )

    # ---------------------------------------------------------
    # SOURCE ANALYSIS
    # ---------------------------------------------------------

    def analyze_source(self, source: str) -> None:

        path = Path(source)

        try:
            text = path.read_text(
                encoding="utf-8",
                errors="replace",
            )

        except Exception as exc:
            self.result["errors"].append(
                f"cannot read {source}: {exc}"
            )
            return

        # -----------------------------------------------------
        # Dangerous functions
        # -----------------------------------------------------

        dangerous_functions = {
            "gets": r"\bgets\s*\(",
            "strcpy": r"\bstrcpy\s*\(",
            "strcat": r"\bstrcat\s*\(",
            "sprintf": r"\bsprintf\s*\(",
            "scanf": r"\bscanf\s*\(",
            "sscanf": r"\bsscanf\s*\(",
            "fscanf": r"\bfscanf\s*\(",
            "read": r"\bread\s*\(",
            "memcpy": r"\bmemcpy\s*\(",
            "printf": r"\bprintf\s*\(",
        }

        for name, pattern in dangerous_functions.items():

            matches = re.findall(pattern, text)

            if matches:

                self.result["primitives"].append(
                    {
                        "type": "dangerous_function",
                        "name": name,
                        "count": len(matches),
                        "source": source,
                    }
                )

        # -----------------------------------------------------
        # Arbitrary write patterns
        # -----------------------------------------------------

        write_patterns = [
            (
                "byte_write",
                r"\*\s*\([^)]*\*\)\s*[^;=\n]+\s*=",
            ),
            (
                "pointer_write",
                r"\*\s*[A-Za-z_][A-Za-z0-9_]*\s*=",
            ),
            (
                "mem_write",
                r"\bmemcpy\s*\(",
            ),
        ]

        for primitive_type, pattern in write_patterns:

            matches = list(
                re.finditer(
                    pattern,
                    text,
                    flags=re.MULTILINE,
                )
            )

            if matches:

                self.result["primitives"].append(
                    {
                        "type": primitive_type,
                        "count": len(matches),
                        "source": source,
                    }
                )

        # -----------------------------------------------------
        # Format string
        # -----------------------------------------------------

        if re.search(
            r"\bprintf\s*\(\s*[A-Za-z_][A-Za-z0-9_]*\s*\)",
            text,
        ):
            self.result["primitives"].append(
                {
                    "type": "format_string_candidate",
                    "source": source,
                }
            )

        # -----------------------------------------------------
        # Integer overwrite / win conditions
        # -----------------------------------------------------

        comparisons = re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*>\s*([0-9]{3,})",
            text,
        )

        for variable, value in comparisons:

            self.result["targets"].append(
                {
                    "type": "integer_condition",
                    "variable": variable,
                    "threshold": value,
                    "source": source,
                }
            )

        # -----------------------------------------------------
        # win()/flag patterns
        # -----------------------------------------------------

        if re.search(
            r"\b(win|winner|victory)\s*\(",
            text,
            re.IGNORECASE,
        ):
            self.result["targets"].append(
                {
                    "type": "win_function",
                    "source": source,
                }
            )

        if re.search(
            r'fopen\s*\(\s*["\']/flag["\']',
            text,
            re.IGNORECASE,
        ):
            self.result["targets"].append(
                {
                    "type": "flag_file",
                    "path": "/flag",
                    "source": source,
                }
            )

        # -----------------------------------------------------
        # Address-controlled write
        # -----------------------------------------------------

        if (
            re.search(r"scanf\s*\(\s*[\"']%l?x", text)
            and re.search(r"\*\s*\([^)]*\*\)", text)
            and re.search(r"=\s*\([^;]+\)", text)
        ):
            self.result["primitives"].append(
                {
                    "type": "controlled_address_write_candidate",
                    "source": source,
                }
            )

    # ---------------------------------------------------------
    # HYPOTHESIS GENERATION
    # ---------------------------------------------------------

    def generate_hypotheses(self) -> None:

        primitive_types = {
            p.get("type")
            for p in self.result["primitives"]
            if isinstance(p, dict)
        }

        target_types = {
            t.get("type")
            for t in self.result["targets"]
            if isinstance(t, dict)
        }

        if "controlled_address_write_candidate" in primitive_types:

            self.result["hypotheses"].append(
                {
                    "name": "Controlled Address Write",
                    "type": "ARBITRARY_WRITE",
                    "confidence": 90,
                    "status": "UNVALIDATED",
                    "reason": (
                        "Source appears to permit a user-controlled "
                        "memory write."
                    ),
                }
            )

        if "format_string_candidate" in primitive_types:

            self.result["hypotheses"].append(
                {
                    "name": "Format String",
                    "type": "FORMAT_STRING",
                    "confidence": 85,
                    "status": "UNVALIDATED",
                    "reason": (
                        "User-controlled value may reach printf "
                        "as a format string."
                    ),
                }
            )

        if "win_function" in target_types:

            self.result["hypotheses"].append(
                {
                    "name": "Reach Win Function",
                    "type": "WIN_FUNCTION",
                    "confidence": 80,
                    "status": "UNVALIDATED",
                    "reason": (
                        "A dedicated victory function was detected."
                    ),
                }
            )

        if "flag_file" in target_types:

            self.result["hypotheses"].append(
                {
                    "name": "Flag File",
                    "type": "FLAG_FILE",
                    "confidence": 75,
                    "status": "UNVALIDATED",
                    "reason": (
                        "The program directly references /flag."
                    ),
                }
            )

        self.result["hypotheses"].sort(
            key=lambda x: x.get("confidence", 0),
            reverse=True,
        )

    # ---------------------------------------------------------
    # MAIN
    # ---------------------------------------------------------

    def run(self) -> dict[str, Any]:

        self.discover()

        for binary in self.result["binaries"]:

            self.checksec(binary)
            self.analyze_symbols(binary)
            self.analyze_strings(binary)

        for source in self.result["sources"]:
            self.analyze_source(source)

        self.generate_hypotheses()

        self.result["summary"] = {
            "files": len(self.result["files"]),
            "sources": len(self.result["sources"]),
            "binaries": len(self.result["binaries"]),
            "primitives": len(self.result["primitives"]),
            "targets": len(self.result["targets"]),
            "hypotheses": len(self.result["hypotheses"]),
        }

        return self.result


def run_pwn_engine(challenge: str) -> dict[str, Any]:
    return PwnEngine(challenge).run()


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python3 -m agent.pwn_engine <challenge>"
        )
        raise SystemExit(1)

    result = run_pwn_engine(sys.argv[1])

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )

def analyze(challenge):
    """
    Point d'entrée compatible avec module_adapter.
    """
    engine = PwnEngine(challenge)
    engine.discover()

    for binary in engine.result.get("binaries", []):
        engine.checksec(binary)
        engine.analyze_symbols(binary)
        engine.analyze_strings(binary)

    for source in engine.result.get("sources", []):
        engine.analyze_source(source)

    engine.generate_hypotheses()
    return engine.result
