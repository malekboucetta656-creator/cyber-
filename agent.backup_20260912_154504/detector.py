#!/usr/bin/env python3

import os
import re
import sys


PATTERNS = {
    "dangerous_sinks": [
        r"\braw\s*\(",
        r"\binnerHTML\b",
        r"\bouterHTML\b",
        r"\beval\s*\(",
        r"\bFunction\s*\(",
        r"\bdocument\.write\s*\(",
    ],
    "xss_indicators": [
        r"\bescapeHtml\b",
        r"\bdecodeHtml\b",
        r"\bisSuspicious\b",
        r"\bfilter\b",
        r"<script",
        r"javascript:",
        r"onerror\s*=",
        r"onclick\s*=",
    ],
    "user_input": [
        r"req\.body",
        r"req\.query",
        r"req\.params",
        r"input\.",
        r"post\.description",
        r"post\.title",
        r"post\.author",
        r"post\.reference",
    ],
    "bot": [
        r"visitLatestPosts",
        r"requestVisit",
        r"XSSBot",
        r"admin/preview",
    ],
    "routes": [
        r"router\.(get|post|put|patch|delete)\s*\(",
        r'"/[^"]+"',
    ],
}


def scan_file(path):
    findings = []

    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="ignore",
        ) as f:
            content = f.read()

    except Exception as exc:
        return [{
            "type": "error",
            "file": path,
            "message": str(exc),
        }]

    for category, patterns in PATTERNS.items():
        for pattern in patterns:
            for match in re.finditer(
                pattern,
                content,
                re.IGNORECASE,
            ):
                line = content[:match.start()].count("\n") + 1

                findings.append({
                    "type": category,
                    "file": path,
                    "line": line,
                    "match": match.group(0),
                })

    return findings


def scan_directory(directory):
    results = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [
            d for d in dirs
            if d not in {
                ".git",
                "node_modules",
                "__pycache__",
                ".venv",
                ".cyberai",
            }
        ]

        for filename in files:
            if not filename.endswith((
                ".js",
                ".html",
                ".json",
                ".py",
                ".c",
                ".cpp",
                ".h",
            )):
                continue

            path = os.path.join(root, filename)
            results.extend(scan_file(path))

    return results


def build_analysis(results):
    categories = {}

    for result in results:
        category = result.get("type", "unknown")
        categories.setdefault(category, []).append(result)

    dangerous = len(categories.get("dangerous_sinks", []))
    inputs = len(categories.get("user_input", []))
    xss = len(categories.get("xss_indicators", []))
    bots = len(categories.get("bot", []))
    routes = len(categories.get("routes", []))

    score = 0

    if dangerous:
        score += 40
    if inputs:
        score += 20
    if xss:
        score += 20
    if bots:
        score += 20

    hypotheses = []

    if score >= 70:
        hypotheses.append({
            "name": "Stored XSS + Admin Bot",
            "confidence": min(score, 100),
            "reason": (
                "User-controlled data reaches potentially "
                "dangerous rendering and bot-related behavior "
                "was detected."
            ),
        })

    return {
        "findings": results,
        "categories": categories,
        "dangerous_sinks": dangerous,
        "user_inputs": inputs,
        "xss_indicators": xss,
        "bot_indicators": bots,
        "routes": routes,
        "score": min(score, 100),
        "hypotheses": hypotheses,
    }


def analyze(challenge):
    challenge = os.fspath(challenge)

    if not os.path.isdir(challenge):
        raise ValueError(
            f"Challenge directory not found: {challenge}"
        )

    results = scan_directory(challenge)
    analysis = build_analysis(results)

    return {
        "sources": [
            item["file"]
            for item in results
            if item.get("type") == "user_input"
        ],
        "sinks": [
            item["file"]
            for item in results
            if item.get("type") == "dangerous_sinks"
        ],
        "bot": [
            item["file"]
            for item in results
            if item.get("type") == "bot"
        ],
        "hypotheses": analysis["hypotheses"],
        "detector": analysis,
    }


def print_report(results):
    print()
    print("=" * 70)
    print("CYBERAI — DETECTOR")
    print("=" * 70)

    if not results:
        print("\nAucun indice détecté.")
        return

    categories = {}

    for result in results:
        category = result["type"]
        categories.setdefault(category, []).append(result)

    for category, items in categories.items():
        print()
        print(f"🔎 {category.upper()}")
        print("-" * 70)

        for item in items:
            print(
                f"[+] {item['file']}:"
                f"{item.get('line', '?')} "
                f"→ {item.get('match', '')}"
            )

    dangerous = len(categories.get("dangerous_sinks", []))
    inputs = len(categories.get("user_input", []))
    xss = len(categories.get("xss_indicators", []))
    bots = len(categories.get("bot", []))

    score = 0

    if dangerous:
        score += 40
    if inputs:
        score += 20
    if xss:
        score += 20
    if bots:
        score += 20

    print()
    print("=" * 70)
    print("ANALYSE RAPIDE")
    print("=" * 70)
    print(f"\nDangerous sinks : {dangerous}")
    print(f"User inputs     : {inputs}")
    print(f"XSS indicators  : {xss}")
    print(f"Bot indicators  : {bots}")
    print(f"\nScore Web/XSS : {score}/100")


def main():
    if len(sys.argv) != 2:
        print("Usage: python agent/detector.py <challenge>")
        sys.exit(1)

    target = sys.argv[1]

    if not os.path.isdir(target):
        print("Le challenge doit être un dossier.")
        sys.exit(1)

    results = scan_directory(target)
    print_report(results)


if __name__ == "__main__":
    main()
