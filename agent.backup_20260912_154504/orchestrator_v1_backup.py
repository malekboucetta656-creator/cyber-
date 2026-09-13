#!/usr/bin/env python3

import sys
from pathlib import Path


def banner():
    print("""
╔══════════════════════════════════════════╗
║        CYBERAI GLOBAL V1                 ║
║        CTF Autonomous Engine             ║
╚══════════════════════════════════════════╝
""")


def discover(challenge):
    print("[1] DISCOVERY")
    print(f"    Challenge : {challenge}")

    if not challenge.exists():
        print("    [!] Challenge introuvable")
        return False

    files = list(challenge.rglob("*"))
    files = [f for f in files if f.is_file()]

    print(f"    [+] Fichiers trouvés : {len(files)}")

    for f in files[:20]:
        print(f"       - {f.relative_to(challenge)}")

    if len(files) > 20:
        print(f"       ... +{len(files) - 20} fichiers")

    return True


def classify(challenge):
    print("\n[2] CLASSIFICATION")

    names = " ".join(
        str(f).lower()
        for f in challenge.rglob("*")
        if f.is_file()
    )

    scores = {
        "web": 0,
        "pwn": 0,
        "reverse": 0,
        "crypto": 0,
        "forensics": 0,
        "misc": 0,
    }

    if any(x in names for x in [
        "package.json", "server.js", "index.html",
        "dockerfile", "html", "javascript", ".js"
    ]):
        scores["web"] += 5

    if any(x in names for x in [
        ".c", ".cpp", ".cc", ".h", "elf", "binary"
    ]):
        scores["pwn"] += 3
        scores["reverse"] += 3

    if any(x in names for x in [
        ".pcap", ".pcapng", ".mem", "memory", ".raw"
    ]):
        scores["forensics"] += 5

    if any(x in names for x in [
        "rsa", "aes", "crypto", "cipher", "encrypt"
    ]):
        scores["crypto"] += 5

    if any(x in names for x in [
        ".py", ".sh", ".txt"
    ]):
        scores["misc"] += 1

    ordered = sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    )

    for category, score in ordered:
        print(f"    {category:10} {score}")

    best, score = ordered[0]

    if score == 0:
        best = "unknown"

    print(f"\n    [+] Type probable : {best.upper()}")

    return best


def run_existing_modules(challenge, category):
    print("\n[3] ANALYSE")

    modules = {
        "web": [
            "agent.scanner",
            "agent.detector",
            "agent.analyzer",
            "agent.web_analyzer",
            "agent.filter_analyzer",
            "agent.client_flow",
            "agent.hypothesis",
        ],
        "pwn": [
            "agent.scanner",
            "agent.detector",
            "agent.analyzer",
            "agent.hypothesis",
        ],
        "reverse": [
            "agent.scanner",
            "agent.detector",
            "agent.analyzer",
        ],
        "crypto": [
            "agent.scanner",
            "agent.detector",
        ],
        "forensics": [
            "agent.scanner",
            "agent.detector",
        ],
        "misc": [
            "agent.scanner",
            "agent.detector",
        ],
    }

    selected = modules.get(category, [
        "agent.scanner",
        "agent.detector",
    ])

    print("    Modules sélectionnés :")

    for module in selected:
        print(f"       [+] {module}")

    print("\n    [*] Intégration automatique des modules")
    print("    [*] Exploit engine : prochaine étape")
    print("    [*] Flag finder     : prochaine étape")


def main():
    banner()

    if len(sys.argv) != 2:
        print("Usage:")
        print("  python3 -m agent.orchestrator <challenge>")
        sys.exit(1)

    challenge = Path(sys.argv[1]).expanduser().resolve()

    if not discover(challenge):
        sys.exit(1)

    category = classify(challenge)

    run_existing_modules(challenge, category)

    print("\n[4] PLANNER")
    print("    [+] Préparation des hypothèses")

    print("\n[5] EXPERIMENT ENGINE")
    print("    [ ] Pas encore activé")

    print("\n[6] EXPLOIT ENGINE")
    print("    [ ] Pas encore activé")

    print("\n[7] FLAG FINDER")
    print("    [ ] Pas encore activé")

    print("\n══════════════════════════════════════════")
    print("CyberAI Global V1 terminé")
    print("══════════════════════════════════════════")


if __name__ == "__main__":
    main()
