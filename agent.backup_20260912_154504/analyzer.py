import os
import sys


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def find_files(root):
    files = []

    for current, dirs, filenames in os.walk(root):
        for filename in filenames:
            if filename.endswith((".js", ".html", ".json")):
                files.append(os.path.join(current, filename))

    return files


def contains(text, *terms):
    text_lower = text.lower()
    return any(term.lower() in text_lower for term in terms)


def detect_data_flow(challenge):
    path = os.path.join(
        challenge,
        "src",
        "routes",
        "categoryRoutes.js"
    )

    if not os.path.isfile(path):
        return []

    content = read_file(path)

    flow = []

    if "req.body.description" in content:
        flow.append("SOURCE: req.body.description")

    if "decodeHtml(req.body.description)" in content:
        flow.append("DECODE: decodeHtml(description)")

    if "isSuspicious(decodedDescription)" in content:
        flow.append("FILTER: isSuspicious(decodedDescription)")

    if "req.body.description = decodedDescription" in content:
        flow.append("ASSIGN: description = decodedDescription")

    if "store.addPost(category.slug, req.body)" in content:
        flow.append("STORAGE: store.addPost()")

    return flow


def analyze(root):
    files = find_files(root)

    result = {
        "challenge_type": "Unknown",
        "sources": [],
        "filters": [],
        "storage": [],
        "sinks": [],
        "bot": [],
        "triggers": [],
        "priority_files": [],
        "hypotheses": [],
        "data_flow": [],
    }

    for path in files:
        content = read_file(path)

        if not content:
            continue

        if contains(
            content,
            "req.body",
            "req.query",
            "req.params"
        ):
            result["sources"].append(path)

        if contains(
            content,
            "isSuspicious",
            "decodeHtml",
            "filter.js"
        ):
            result["filters"].append(path)

        if contains(
            content,
            "addPost",
            "postsByCategory",
            "unshift("
        ):
            result["storage"].append(path)

        if contains(
            content,
            "raw(",
            "innerHTML",
            "outerHTML"
        ):
            result["sinks"].append(path)

        if contains(
            content,
            "requestVisit",
            "visitLatestPosts",
            "XSSBot",
            "admin/preview"
        ):
            result["bot"].append(path)

        if contains(
            content,
            '"/report"',
            "visitLatestPosts()"
        ):
            result["triggers"].append(path)

    result["data_flow"] = detect_data_flow(root)

    if result["sinks"] and result["bot"]:
        result["challenge_type"] = "Web / XSS"

    if (
        result["sources"]
        and result["filters"]
        and result["storage"]
        and result["sinks"]
        and result["bot"]
    ):
        result["hypotheses"].append({
            "name": "Stored XSS + Admin Bot",
            "confidence": 95,
            "reason": (
                "Une donnée utilisateur traverse un filtre, "
                "est stockée puis atteint un sink HTML dangereux "
                "dans une page visitée par un bot."
            )
        })

        result["priority_files"] = [
            "src/filter.js",
            "src/routes/categoryRoutes.js",
            "src/categories/tech.js",
            "public/static/updates.js",
            "src/routes/reportRoutes.js",
        ]

    return result


def print_analysis(result):
    print()
    print("=" * 70)
    print("🧠 CYBERAI V5 — ANALYZER")
    print("=" * 70)

    print()
    print(f"🎯 Type : {result['challenge_type']}")

    print("\n📥 SOURCES")
    for item in result["sources"]:
        print(f"   [+] {item}")

    print("\n🛡️ FILTERS")
    for item in result["filters"]:
        print(f"   [+] {item}")

    print("\n💾 STORAGE")
    for item in result["storage"]:
        print(f"   [+] {item}")

    print("\n💥 SINKS")
    for item in result["sinks"]:
        print(f"   [+] {item}")

    print("\n🤖 BOT")
    for item in result["bot"]:
        print(f"   [+] {item}")

    print("\n🚨 TRIGGERS")
    for item in result["triggers"]:
        print(f"   [+] {item}")

    print("\n" + "=" * 70)
    print("🔗 DATA FLOW")
    print("=" * 70)

    for index, step in enumerate(result["data_flow"]):
        print(f"   {step}")

        if index < len(result["data_flow"]) - 1:
            print("      ↓")

    print("\n" + "=" * 70)
    print("🎯 HYPOTHÈSES")
    print("=" * 70)

    for hypothesis in result["hypotheses"]:
        print()
        print(f"🔥 {hypothesis['name']}")
        print(f"   Confiance : {hypothesis['confidence']}%")
        print(f"   {hypothesis['reason']}")

    print("\n" + "=" * 70)
    print("📂 FICHIERS PRIORITAIRES")
    print("=" * 70)

    for index, path in enumerate(
        result["priority_files"],
        1
    ):
        print(f"   {index}. {path}")

    print("\n➡️ PROCHAINE ACTION")
    print("   Analyser précisément le filtre.")


def main():
    if len(sys.argv) != 2:
        print("Usage: python agent/analyzer.py <challenge>")
        sys.exit(1)

    root = sys.argv[1]

    if not os.path.isdir(root):
        print("❌ Challenge introuvable :", root)
        sys.exit(1)

    result = analyze(root)
    print_analysis(result)


if __name__ == "__main__":
    main()	

