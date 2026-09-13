#!/usr/bin/env python3
"""
CyberAI - Point d'entrée principal
Usage:
    python -m agent.main <chemin_du_challenge>
"""

import sys
from pathlib import Path

# Ajoute la racine du projet au path
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from agent.orchestrator import run


def main():
    print("╔══════════════════════════════════════════╗")
    print("║           CyberAI v0.2                   ║")
    print("║     CTF Assistant - Pwn Focus            ║")
    print("╚══════════════════════════════════════════╝")
    print()

    if len(sys.argv) < 2:
        print("Usage: python -m agent.main <chemin_du_challenge>")
        print()
        print("Exemple:")
        print("  python -m agent.main ./workspace")
        sys.exit(1)

    challenge = str(Path(sys.argv[1]).expanduser().resolve())

    if not Path(challenge).exists():
        print(f"[!] Challenge introuvable : {challenge}")
        sys.exit(1)

    print(f"[+] Challenge : {challenge}")
    print()

    # Lance directement la fonction run de l'orchestrateur
    run(challenge)


if __name__ == "__main__":
    main()
