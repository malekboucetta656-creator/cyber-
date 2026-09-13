#!/usr/bin/env python3

from pathlib import Path


CATEGORIES = {
    "web": {
        "extensions": {
            ".html": 5,
            ".htm": 5,
            ".js": 4,
            ".php": 4,
            ".py": 2,
            ".json": 2,
        },
        "keywords": [
            "docker",
            "express",
            "flask",
            "django",
            "php",
            "nginx",
            "apache",
            "server",
            "route",
            "cookie",
            "http",
            "html",
            "javascript",
        ],
    },

    "pwn": {
        "extensions": {
            ".c": 4,
            ".cpp": 4,
            ".cc": 4,
            ".h": 2,
            ".asm": 3,
            ".s": 3,
        },
        "keywords": [
            "pwn",
            "binary",
            "exploit",
            "libc",
            "rop",
            "buffer",
            "overflow",
            "socket",
        ],
    },

    "reverse": {
        "extensions": {
            ".elf": 5,
            ".exe": 5,
            ".dll": 4,
            ".so": 4,
            ".apk": 5,
            ".dex": 5,
        },
        "keywords": [
            "reverse",
            "rev",
            "binary",
            "crackme",
            "obfusc",
            "ghidra",
            "ida",
        ],
    },

    "crypto": {
        "extensions": {
            ".pem": 5,
            ".der": 5,
            ".key": 5,
        },
        "keywords": [
            "crypto",
            "rsa",
            "aes",
            "xor",
            "cipher",
            "decrypt",
            "encrypt",
            "hash",
            "modulo",
            "prime",
        ],
    },

    "forensics": {
        "extensions": {
            ".pcap": 8,
            ".pcapng": 8,
            ".raw": 5,
            ".mem": 6,
            ".dd": 6,
            ".img": 5,
        },
        "keywords": [
            "forensic",
            "forensics",
            "pcap",
            "memory",
            "dump",
            "stego",
            "metadata",
            "wireshark",
            "volatility",
        ],
    },

    "misc": {
        "extensions": {},
        "keywords": [
            "misc",
            "script",
            "logic",
            "automation",
            "encoding",
        ],
    },
}


def classify(challenge: Path):
    scores = {category: 0 for category in CATEGORIES}

    files = [
        p for p in challenge.rglob("*")
        if p.is_file()
    ]

    names = " ".join(
        p.name.lower()
        for p in files
    )

    paths = " ".join(
        str(p).lower()
        for p in files
    )

    for category, rules in CATEGORIES.items():

        for file in files:
            suffix = file.suffix.lower()

            if suffix in rules["extensions"]:
                scores[category] += rules["extensions"][suffix]

        for keyword in rules["keywords"]:
            if keyword in names or keyword in paths:
                scores[category] += 2

    ranked = sorted(
        scores.items(),
        key=lambda x: x[1],
        reverse=True
    )

    return {
        "scores": scores,
        "ranking": ranked,
        "primary": ranked[0][0],
    }


def print_report(result):
    print()
    print("╔══════════════════════════════════════════╗")
    print("║        CYBERAI CLASSIFICATION            ║")
    print("╚══════════════════════════════════════════╝")

    for category, score in result["ranking"]:
        print(f"    {category:<12} {score}")

    print()
    print(f"[+] Type probable : {result['primary'].upper()}")

if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python3 -m agent.classifier <challenge>")
        raise SystemExit(1)

    challenge = Path(sys.argv[1]).expanduser().resolve()

    if not challenge.exists():
        print(f"[!] Challenge introuvable : {challenge}")
        raise SystemExit(1)

    result = classify(challenge)
    print_report(result)
