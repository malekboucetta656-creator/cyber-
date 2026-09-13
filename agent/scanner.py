#!/usr/bin/env python3

import os
import subprocess
import sys


def run_command(command):
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.stdout.strip()

    except Exception as e:
        return f"Erreur : {e}"


def analyze_file(path):
    result = {
        "file": path,
        "type": "",
        "strings": [],
    }

    result["type"] = run_command(["file", path])

    output = run_command(["strings", "-n", "5", path])

    result["strings"] = output.splitlines()[:30]

    return result


def analyze_directory(path):
    files = []

    for root, dirs, filenames in os.walk(path):

        # Évite les dossiers inutiles/lourds
        dirs[:] = [
            d for d in dirs
            if d not in {
                ".git",
                "node_modules",
                "__pycache__",
                ".venv",
            }
        ]

        for filename in filenames:
            files.append(os.path.join(root, filename))

    results = []

    for file_path in files:
        try:
            results.append(analyze_file(file_path))
        except Exception as e:
            results.append({
                "file": file_path,
                "error": str(e),
            })

    return results


def analyze(target):
    """
    API utilisée par CyberAI.

    Accepte :
      - un fichier
      - un dossier de challenge
    """

    target = os.path.abspath(target)

    if not os.path.exists(target):
        raise FileNotFoundError(
            f"Chemin introuvable : {target}"
        )

    if os.path.isdir(target):
        results = analyze_directory(target)

        return {
            "scanner": results,
            "files_scanned": len(results),
            "challenge": target,
        }

    result = analyze_file(target)

    return {
        "scanner": [result],
        "files_scanned": 1,
        "challenge": target,
    }


def print_report(data):
    print()
    print("=" * 70)
    print("🔎 CYBERAI — SCANNER")
    print("=" * 70)

    results = data.get("scanner", [])

    print(f"\n📊 Fichiers analysés : {len(results)}")

    for item in results:

        path = item.get("file", "")

        print()
        print("=" * 60)
        print(path)
        print("=" * 60)

        if "error" in item:
            print("❌", item["error"])
            continue

        print("\n📦 Type")
        print(item.get("type", ""))

        print("\n🔤 Strings")

        for line in item.get("strings", []):
            print(line)


def main():

    if len(sys.argv) != 2:
        print(
            "Usage : python agent/scanner.py <fichier|dossier>"
        )
        sys.exit(1)

    target = sys.argv[1]

    try:
        result = analyze(target)
    except Exception as e:
        print("❌", e)
        sys.exit(1)

    print_report(result)


if __name__ == "__main__":
    main()
