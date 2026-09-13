import os
import re
import subprocess
import tempfile


TESTS = [
    (
        "GLOBAL_ID",
        """
        <a id="whatsNew" href="/admin/preview">A</a>
        """,
    ),
    (
        "FORM_SINGLE_NAME",
        """
        <form id="whatsNew">
            <input name="next" value="TEST">
        </form>
        """,
    ),
    (
        "FORM_DOUBLE_NAME",
        """
        <form id="whatsNew">
            <input name="next" value="ONE">
            <input name="next" value="TWO">
        </form>
        """,
    ),
    (
        "FORM_ANCHOR_NAME",
        """
        <form id="whatsNew">
            <a name="next" href="/admin/preview">NEXT</a>
        </form>
        """,
    ),
    (
        "FORM_INPUT_ID",
        """
        <form id="whatsNew">
            <input id="next" value="TEST">
        </form>
        """,
    ),
    (
        "FORM_ANCHOR_ID",
        """
        <form id="whatsNew">
            <a id="next" href="/admin/preview">NEXT</a>
        </form>
        """,
    ),
]


def build_html(fragment):
    return f"""
<!doctype html>
<html>
<body>

{fragment}

<script>
console.log("=== EXPERIMENT ===");

const w = window.whatsNew;

console.log("WHATSNEW_TYPE:",
    w ? Object.prototype.toString.call(w) : "undefined");

console.log("NEXT_TYPE:",
    w && w.next
        ? Object.prototype.toString.call(w.next)
        : "undefined");

console.log("NEXT_GETATTRIBUTE:",
    w && w.next
        ? typeof w.next.getAttribute
        : "undefined");

console.log("NEXT_HREF:",
    w && w.next
        ? w.next.href
        : "undefined");

if (
    w &&
    w.next &&
    typeof w.next.getAttribute === "function"
) {{
    console.log(
        "GETATTRIBUTE_HREF:",
        w.next.getAttribute("href")
    );
}}
</script>

</body>
</html>
"""


def run_browser(html):
    fd, path = tempfile.mkstemp(suffix=".html")

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(html)

        result = subprocess.run(
            [
                "chromium",
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--enable-logging=stderr",
                "--dump-dom",
                "file://" + path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        return result.stdout + "\n" + result.stderr

    except subprocess.TimeoutExpired:
        return "TIMEOUT"

    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def parse(output):
    data = {}

    patterns = {
        "whatsnew_type": r'"WHATSNEW_TYPE:\s*([^"]+)"',
        "next_type": r'"NEXT_TYPE:\s*([^"]+)"',
        "getattribute": r'"NEXT_GETATTRIBUTE:\s*([^"]+)"',
        "href": r'"NEXT_HREF:\s*([^"]+)"',
        "getattribute_href": r'"GETATTRIBUTE_HREF:\s*([^"]+)"',
    }

    for key, pattern in patterns.items():
        match = re.search(pattern, output)

        if match:
            data[key] = match.group(1).strip()
        else:
            data[key] = "NOT_FOUND"

    return data


def score(data):
    score = 0
    reasons = []

    if data["whatsnew_type"] != "undefined":
        score += 20
        reasons.append("window.whatsNew existe")

    if data["next_type"] != "undefined":
        score += 25
        reasons.append("propriété next détectée")

    if data["getattribute"] == "function":
        score += 40
        reasons.append("next.getAttribute disponible")

    if data["href"] != "undefined":
        score += 10
        reasons.append("next.href disponible")

    if data["getattribute_href"] != "NOT_FOUND":
        score += 5
        reasons.append("href récupérable")

    return score, reasons


def analyze(challenge):
    print()
    print("=" * 70)
    print("🧠 CYBERAI V108 — EXPERIMENTAL ENGINE")
    print("=" * 70)

    if not os.path.isdir(challenge):
        print("❌ Challenge introuvable :", challenge)
        return

    print()
    print("🎯 Challenge :", challenge)
    print("🔬 Expériences :", len(TESTS))
    print()

    results = []

    for number, (name, fragment) in enumerate(TESTS, 1):

        print("-" * 70)
        print(f"[{number:02}] TEST : {name}")

        html = build_html(fragment)
        output = run_browser(html)
        data = parse(output)

        points, reasons = score(data)

        results.append(
            {
                "name": name,
                "score": points,
                "data": data,
                "reasons": reasons,
            }
        )

        print("    whatsNew :", data["whatsnew_type"])
        print("    next     :", data["next_type"])
        print("    getAttr  :", data["getattribute"])
        print("    href     :", data["href"])
        print("    score    :", points, "/ 100")

        if reasons:
            for reason in reasons:
                print("    [+]", reason)

    print()
    print("=" * 70)
    print("🎯 RÉSULTATS")
    print("=" * 70)

    results.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    for index, result in enumerate(results, 1):

        print(
            f"{index}. "
            f"{result['name']} "
            f"→ {result['score']}/100"
        )

    best = results[0]

    print()
    print("=" * 70)
    print("🔥 MEILLEURE HYPOTHÈSE")
    print("=" * 70)

    print(best["name"])
    print("Score :", best["score"], "/ 100")

    for reason in best["reasons"]:
        print("[+]", reason)

    print()
    print("=" * 70)
    print("🧠 DÉCISION")
    print("=" * 70)

    if best["data"]["getattribute"] == "function":
        print("🚨 VECTEUR DOM COMPATIBLE AVEC getAttribute()")
        print()
        print("La propriété next produit un objet DOM")
        print("compatible avec le sink utilisé par updates.js.")
    elif best["data"]["next_type"] != "undefined":
        print("⚠️ next existe mais n'est pas encore")
        print("compatible avec getAttribute().")
    else:
        print("❌ Aucun test ne produit une propriété next exploitable.")

    print()
    print("➡️ V108 termine les expériences DOM contrôlées.")
    print("=" * 70)


def main():
    if len(os.sys.argv) != 2:
        print(
            "Usage: python agent/experimental_engine.py "
            "<challenge>"
        )
        raise SystemExit(1)

    analyze(os.sys.argv[1])


if __name__ == "__main__":
    main()
