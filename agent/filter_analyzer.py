#!/usr/bin/env python3

import os
import re
import sys


def find_filter_file(target):
    """
    Accepte :
      - le dossier du challenge
      - directement src/filter.js
    """
    target = os.path.abspath(target)

    if os.path.isfile(target):
        return target

    if os.path.isdir(target):
        candidate = os.path.join(target, "src", "filter.js")
        if os.path.isfile(candidate):
            return candidate

    return None


def read_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()


def extract_blocked(content):
    match = re.search(
        r"const\s+BLOCKED\s*=\s*\[(.*?)\];",
        content,
        re.S,
    )

    if not match:
        return []

    return re.findall(
        r"""['"]([^'"]+)['"]""",
        match.group(1),
    )


def extract_patterns(content):
    match = re.search(
        r"const\s+BLOCKED_PATTERNS\s*=\s*\[(.*?)\];",
        content,
        re.S,
    )

    if not match:
        return []

    block = match.group(1)

    return [
        line.strip()
        for line in block.splitlines()
        if line.strip()
    ]


def classify(blocked):
    groups = {
        "DOM / Browser": [
            "window",
            "document",
            "location",
            "navigator",
            "history",
            "self",
            "top",
            "parent",
            "frames",
        ],

        "Navigation": [
            "next",
            "assign",
            "replace",
            "reload",
            "protocol",
            "host",
            "hostname",
            "origin",
            "pathname",
            "search",
            "hash",
        ],

        "Execution": [
            "eval",
            "function",
            "constructor",
            "settimeout",
            "setinterval",
            "setimmediate",
        ],

        "HTML / Script": [
            "script",
            "iframe",
            "object",
            "embed",
            "svg",
            "style",
            "template",
            "canvas",
        ],

        "DOM APIs": [
            "innerhtml",
            "outerhtml",
            "createelement",
            "appendchild",
            "replacechild",
            "insertadjacenthtml",
        ],

        "Encoding": [
            "fromcharcode",
            "fromcodepoint",
            "charcodeat",
            "atob",
            "btoa",
            "decodeuri",
            "encodeuri",
        ],

        "Network": [
            "fetch",
            "xmlhttprequest",
            "websocket",
            "eventsource",
            "sendbeacon",
        ],
    }

    result = {}

    blocked_lower = {
        str(word).lower()
        for word in blocked
    }

    for name, words in groups.items():
        found = [
            word
            for word in words
            if word.lower() in blocked_lower
        ]

        if found:
            result[name] = found

    return result


def analyze(target):
    """
    Analyse src/filter.js à partir du dossier du challenge.
    """

    path = find_filter_file(target)

    if path is None:
        raise FileNotFoundError(
            f"filter.js introuvable dans : {target}"
        )

    content = read_file(path)

    blocked = extract_blocked(content)
    patterns = extract_patterns(content)
    groups = classify(blocked)

    return {
        "filter_file": path,
        "blocked": blocked,
        "patterns": patterns,
        "blocked_count": len(blocked),
        "pattern_count": len(patterns),
        "groups": groups,
        "filters": [path],
    }


def main():
    if len(sys.argv) != 2:
        print(
            "Usage: python agent/filter_analyzer.py <challenge>"
        )
        sys.exit(1)

    target = sys.argv[1]

    try:
        result = analyze(target)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)

    print()
    print("=== FILTER ANALYZER ===")
    print()
    print("FILE:")
    print(result["filter_file"])
    print()
    print("BLOCKED TOKENS:", result["blocked_count"])
    print("BLOCKED PATTERNS:", result["pattern_count"])
    print()

    print("GROUPS:")
    for group, values in result["groups"].items():
        print(f"  {group}:")
        for value in values:
            print(f"    - {value}")

    print()


if __name__ == "__main__":
    main()
