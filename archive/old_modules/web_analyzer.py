#!/usr/bin/env python3

import os
import re
import sys


def read_file(path):
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as f:
            return f.read()

    except Exception as e:
        return f"ERROR: {e}"


def find_js_files(root):

    files = []

    for current, dirs, filenames in os.walk(root):

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

            if filename.endswith(".js"):
                files.append(
                    os.path.join(current, filename)
                )

    return files


def analyze_js(path):

    content = read_file(path)

    findings = []

    patterns = {

        "global_objects": [
            r"window\.([A-Za-z_$][\w$]*)",
        ],

        "property_access": [
            r"window\.([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)",
        ],

        "getAttribute": [
            r"\.getAttribute\s*\(\s*['\"]([^'\"]+)['\"]\s*\)",
        ],

        "href_access": [
            r"\.href\b",
        ],

        "type_checks": [
            r"typeof\s+([A-Za-z_$][\w$]*)\.([A-Za-z_$][\w$]*)",
        ],

        "url_construction": [
            r"new\s+URL\s*\(",
        ],

        "navigation": [
            r"\.assign\s*\(",
            r"\.replace\s*\(",
        ],

        "timers": [
            r"setTimeout\s*\(",
        ],
    }

    for category, regexes in patterns.items():

        for regex in regexes:

            for match in re.finditer(
                regex,
                content,
                re.IGNORECASE,
            ):

                line = (
                    content[:match.start()]
                    .count("\n")
                    + 1
                )

                findings.append({
                    "category": category,
                    "file": path,
                    "line": line,
                    "match": match.group(0),
                })

    return findings


def analyze(challenge):

    """
    API utilisée par CyberAI.

    Analyse tous les fichiers JavaScript
    du challenge.
    """

    challenge = os.path.abspath(challenge)

    if not os.path.isdir(challenge):
        raise FileNotFoundError(
            f"Challenge introuvable : {challenge}"
        )

    all_results = []

    for path in find_js_files(challenge):

        findings = analyze_js(path)

        if findings:
            all_results.extend(findings)

    return {
        "web_analysis": all_results,
        "findings": all_results,
        "files_analyzed": len(
            find_js_files(challenge)
        ),
    }


def print_report(results):

    print()
    print("=" * 70)
    print("🌐 CYBERAI — WEB ANALYZER")
    print("=" * 70)

    if not results:

        print(
            "\n❌ Aucun comportement web "
            "intéressant détecté."
        )

        return

    categories = {}

    for result in results:

        categories.setdefault(
            result["category"],
            [],
        ).append(result)

    for category, items in categories.items():

        print()
        print(f"🔎 {category.upper()}")
        print("-" * 70)

        for item in items:

            print(
                f"[+] {item['file']} "
                f"ligne {item['line']} → "
                f"{item['match']}"
            )

    globals_found = categories.get(
        "global_objects",
        [],
    )

    properties = categories.get(
        "property_access",
        [],
    )

    attributes = categories.get(
        "getAttribute",
        [],
    )

    hrefs = categories.get(
        "href_access",
        [],
    )

    urls = categories.get(
        "url_construction",
        [],
    )

    navigation = categories.get(
        "navigation",
        [],
    )

    print()
    print("=" * 70)
    print("🧠 INTERPRÉTATION")
    print("=" * 70)

    score = 0

    if globals_found:
        score += 20

    if properties:
        score += 20

    if attributes:
        score += 20

    if urls:
        score += 20

    if navigation:
        score += 20

    if score >= 60:

        print(
            "\n🔥 Client-side DOM manipulation détectée"
        )

        print(f"   Score : {score}/100")

    if (
        globals_found
        and properties
        and attributes
    ):

        print(
            "\n⚠️ Hypothèse : "
            "DOM property manipulation"
        )

    if urls and navigation:

        print(
            "\n⚠️ Une donnée peut influencer "
            "une navigation."
        )

    if hrefs:

        print(
            f"\n🔗 Accès href : "
            f"{len(hrefs)} occurrence(s)"
        )


def main():

    if len(sys.argv) != 2:

        print("Usage:")
        print(
            "python agent/web_analyzer.py <challenge>"
        )

        sys.exit(1)

    challenge = sys.argv[1]

    try:
        result = analyze(challenge)

    except Exception as e:

        print("❌", e)
        sys.exit(1)

    print_report(
        result["web_analysis"]
    )


if __name__ == "__main__":
    main()
