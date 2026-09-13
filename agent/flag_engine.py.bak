#!/usr/bin/env python3

import json
import os
import re
import sys
from pathlib import Path


# Formats génériques fréquents en CTF.
# Aucun flag réel n'est codé en dur.
FLAG_PATTERNS = [
    re.compile(r'(?i)\bflag\{[^{}\r\n]{1,500}\}'),
    re.compile(r'(?i)\bctf\{[^{}\r\n]{1,500}\}'),
    re.compile(r'(?i)\bpicoctf\{[^{}\r\n]{1,500}\}'),
    re.compile(r'(?i)\bhtb\{[^{}\r\n]{1,500}\}'),
    re.compile(r'(?i)\b[a-z0-9_-]{2,30}\{[^{}\r\n]{1,500}\}'),
]


class FlagEngine:
    """
    Recherche générique de flags.

    Important :
    - ne génère pas de flag ;
    - ne considère pas une hypothèse comme un flag ;
    - ne dépend pas d'un challenge particulier ;
    - retourne les preuves permettant de retrouver le flag.
    """

    def __init__(self, challenge):
        self.challenge = os.path.abspath(challenge)
        self.results = []

    def extract_from_text(self, text, source="unknown"):
        if not isinstance(text, str):
            return []

        found = []

        for pattern in FLAG_PATTERNS:
            for match in pattern.finditer(text):
                flag = match.group(0)

                item = {
                    "flag": flag,
                    "source": source,
                    "method": "regex",
                }

                if item not in found:
                    found.append(item)

        return found

    def scan_file(self, path):
        try:
            content = Path(path).read_text(
                encoding="utf-8",
                errors="ignore",
            )
        except Exception:
            return []

        return self.extract_from_text(
            content,
            source=str(path),
        )

    def scan_challenge_files(self):
        root = Path(self.challenge)

        if not root.exists():
            return []

        found = []

        for path in root.rglob("*"):

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

            # On reste volontairement large :
            # un flag peut être caché dans n'importe quel
            # artefact textuel.
            try:
                results = self.scan_file(path)
            except Exception:
                continue

            for result in results:
                if result not in found:
                    found.append(result)

        return found

    def scan_context(self, context):
        """
        Recherche dans les résultats de CyberAI :
        stdout, stderr, observations, exploits, etc.
        """

        found = []

        def walk(value, path="context"):

            if isinstance(value, str):

                results = self.extract_from_text(
                    value,
                    source=path,
                )

                for result in results:
                    if result not in found:
                        found.append(result)

                return

            if isinstance(value, dict):

                for key, child in value.items():
                    walk(
                        child,
                        f"{path}.{key}",
                    )

                return

            if isinstance(value, list):

                for index, child in enumerate(value):
                    walk(
                        child,
                        f"{path}[{index}]",
                    )

        walk(context)

        return found

    def run(self, context=None):

        self.results = []

        # 1. Artefacts du challenge
        self.results.extend(
            self.scan_challenge_files()
        )

        # 2. Résultats produits par CyberAI
        if context is not None:

            for result in self.scan_context(
                context
            ):
                if result not in self.results:
                    self.results.append(result)

        return self.results


def load_context(challenge):

    path = (
        Path(challenge)
        / ".cyberai"
        / "context.json"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"context.json introuvable : {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as f:
        return json.load(f)


def save_context(challenge, context):

    path = (
        Path(challenge)
        / ".cyberai"
        / "context.json"
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            context,
            f,
            indent=2,
            ensure_ascii=False,
        )


def main():

    if len(sys.argv) != 2:

        print(
            "Usage: "
            "python -m agent.flag_engine <challenge>"
        )

        sys.exit(1)

    challenge = os.path.abspath(
        sys.argv[1]
    )

    context = load_context(
        challenge
    )

    engine = FlagEngine(
        challenge
    )

    flags = engine.run(
        context
    )

    context["flags"] = flags

    save_context(
        challenge,
        context,
    )

    print()
    print("=" * 70)
    print("🏁 CYBERAI — FLAG ENGINE")
    print("=" * 70)

    print(
        f"\nFlags trouvés : {len(flags)}"
    )

    if not flags:
        print(
            "\n[-] Aucun flag trouvé."
        )

    else:

        for index, result in enumerate(
            flags,
            1,
        ):

            print(
                f"\n[{index}] "
                f"{result['flag']}"
            )

            print(
                f"    Source : "
                f"{result['source']}"
            )

            print(
                f"    Méthode : "
                f"{result['method']}"
            )

    print(
        "\n[+] Context sauvegardé."
    )


if __name__ == "__main__":
    main()
