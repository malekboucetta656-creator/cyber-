import os
import sys
import re


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def collect_files(root):
    files = []

    for current, dirs, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith((".js", ".html")):
                files.append(os.path.join(current, filename))

    return files


def search_all(files, patterns):
    findings = []

    for path in files:
        content = read_file(path)

        for pattern in patterns:
            matches = list(re.finditer(pattern, content, re.IGNORECASE))

            for match in matches:
                line = content[:match.start()].count("\n") + 1

                findings.append({
                    "file": path,
                    "line": line,
                    "match": match.group(0),
                })

    return findings


def analyze(challenge):
    files = collect_files(challenge)

    result = {
        "sources": [],
        "filters": [],
        "storage": [],
        "sinks": [],
        "bot": [],
        "client": [],
        "dom": [],
        "navigation": [],
        "hypotheses": [],
    }

    result["sources"] = search_all(
        files,
        [
            r"req\.body",
            r"req\.query",
            r"req\.params",
        ],
    )

    result["filters"] = search_all(
        files,
        [
            r"isSuspicious",
            r"decodeHtml",
            r"BLOCKED",
            r"BLOCKED_PATTERNS",
        ],
    )

    result["storage"] = search_all(
        files,
        [
            r"addPost",
            r"postsByCategory",
            r"unshift\s*\(",
        ],
    )

    result["sinks"] = search_all(
        files,
        [
            r"\braw\s*\(",
            r"innerHTML",
            r"outerHTML",
        ],
    )

    result["bot"] = search_all(
        files,
        [
            r"XSSBot",
            r"requestVisit",
            r"visitLatestPosts",
            r"/admin/preview",
        ],
    )

    result["client"] = search_all(
        files,
        [
            r"window\.whatsNew",
            r"whatsNew\.",
        ],
    )

    result["dom"] = search_all(
        files,
        [
            r"\.getAttribute\s*\(",
            r"querySelector\s*\(",
            r"\.href\b",
            r"setAttribute\s*\(",
        ],
    )

    result["navigation"] = search_all(
        files,
        [
            r"new\s+URL\s*\(",
            r"location\.assign",
            r"location\.replace",
        ],
    )

    score = 0

    if result["sources"]:
        score += 15

    if result["filters"]:
        score += 10

    if result["storage"]:
        score += 15

    if result["sinks"]:
        score += 15

    if result["bot"]:
        score += 15

    if result["client"]:
        score += 10

    if result["dom"]:
        score += 5

    if result["navigation"]:
        score += 15

    score = min(score, 100)

    # Hypothesis 1
    if (
        result["sources"]
        and result["filters"]
        and result["storage"]
        and result["sinks"]
    ):
        result["hypotheses"].append({
            "name": "Stored XSS",
            "confidence": 85,
            "reason": (
                "Une donnée utilisateur atteint un rendu HTML "
                "non échappé après traitement et stockage."
            ),
        })

    # Hypothesis 2
    if result["bot"] and result["sinks"]:
        result["hypotheses"].append({
            "name": "Stored XSS + Admin Bot",
            "confidence": 90,
            "reason": (
                "Le contenu persistant peut être rendu dans une "
                "page visitée automatiquement par le bot."
            ),
        })

    # Hypothesis 3
    if result["client"] and result["dom"]:
        result["hypotheses"].append({
            "name": "DOM Property Manipulation",
            "confidence": 90,
            "reason": (
                "Le JavaScript client récupère des propriétés d'un "
                "objet global puis utilise des APIs DOM."
            ),
        })

    # Hypothesis 4
    if result["client"] and result["navigation"]:
        result["hypotheses"].append({
            "name": "DOM-controlled Navigation",
            "confidence": 95,
            "reason": (
                "Une propriété client-side est transformée en URL "
                "puis utilisée dans une opération de navigation."
            ),
        })

    result["overall_score"] = score

    return result


def print_section(title, items):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)

    if not items:
        print("   Aucun élément détecté.")
        return

    seen = set()

    for item in items:
        key = (
            item["file"],
            item["line"],
            item["match"],
        )

        if key in seen:
            continue

        seen.add(key)

        print(
            f"   [+] {item['file']}:{item['line']} "
            f"→ {item['match']}"
        )


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("python agent/hypothesis.py <challenge>")
        sys.exit(1)

    challenge = sys.argv[1]

    if not os.path.isdir(challenge):
        print("❌ Challenge introuvable :", challenge)
        sys.exit(1)

    result = analyze(challenge)

    print()
    print("=" * 70)
    print("🧠 CYBERAI V100.1 — HYPOTHESIS ENGINE")
    print("=" * 70)

    print(f"\n🎯 GLOBAL SCORE : {result['overall_score']}/100")

    print_section("📥 SOURCES", result["sources"])
    print_section("🛡️ FILTERS", result["filters"])
    print_section("💾 STORAGE", result["storage"])
    print_section("💥 SINKS", result["sinks"])
    print_section("🤖 BOT", result["bot"])
    print_section("🌐 CLIENT", result["client"])
    print_section("🏷️ DOM", result["dom"])
    print_section("🚀 NAVIGATION", result["navigation"])

    print()
    print("=" * 70)
    print("🎯 HYPOTHÈSES")
    print("=" * 70)

    if not result["hypotheses"]:
        print("\n❌ Aucune hypothèse suffisamment étayée.")
    else:
        for index, hypothesis in enumerate(
            result["hypotheses"],
            1
        ):
            print(
                f"\n🔥 H{index} — "
                f"{hypothesis['name']}"
            )
            print(
                f"   Confiance : "
                f"{hypothesis['confidence']}%"
            )
            print(
                f"   Pourquoi : "
                f"{hypothesis['reason']}"
            )

    print()
    print("=" * 70)
    print("➡️ PROCHAINE DÉCISION")
    print("=" * 70)

    if result["navigation"]:
        print("""
   1. Analyser précisément le flux client-side.
   2. Vérifier les propriétés contrôlables.
   3. Vérifier le comportement du filtre.
   4. Construire ensuite un test local contrôlé.
""")
    elif result["sinks"]:
        print("""
   1. Analyser le sink.
   2. Reconstituer le data-flow.
   3. Analyser le filtre.
""")
    else:
        print("""
   1. Continuer l'analyse statique.
""")


if __name__ == "__main__":
    main()
