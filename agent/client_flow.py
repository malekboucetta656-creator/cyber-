import os
import re
import sys


def read_file(path):
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read()
    except Exception:
        return ""


def find_file(root, name):
    for current, dirs, files in os.walk(root):
        if name in files:
            return os.path.join(current, name)
    return None


def check(content, pattern):
    return bool(re.search(pattern, content, re.I))


def analyze(challenge):
    flow = []

    route = find_file(challenge, "categoryRoutes.js")
    category = find_file(challenge, "tech.js")
    store = find_file(challenge, "store.js")
    client = find_file(challenge, "updates.js")
    bot = find_file(challenge, "bot.js")

    route_c = read_file(route) if route else ""
    category_c = read_file(category) if category else ""
    store_c = read_file(store) if store else ""
    client_c = read_file(client) if client else ""
    bot_c = read_file(bot) if bot else ""

    if check(route_c, r"req\.body\.description"):
        flow.append(("SOURCE", "req.body.description"))

    if check(route_c, r"decodeHtml"):
        flow.append(("DECODE", "decodeHtml(description)"))

    if check(route_c, r"isSuspicious"):
        flow.append(("FILTER", "isSuspicious(decodedDescription)"))

    if check(route_c, r"addPost"):
        flow.append(("STORAGE", "store.addPost()"))

    if check(category_c, r"raw\s*\(\s*post\.description"):
        flow.append(("SINK", "raw(post.description)"))

    if check(bot_c, r"/admin/preview"):
        flow.append(("BOT", "visit /admin/preview"))

    if check(client_c, r"window\.whatsNew"):
        flow.append(("GLOBAL", "window.whatsNew"))

    if check(client_c, r"whatsNew\.next"):
        flow.append(("PROPERTY", "window.whatsNew.next"))

    if check(client_c, r"getAttribute\s*\(\s*['\"]href"):
        flow.append(("DOM", 'next.getAttribute("href")'))

    if check(client_c, r"next\.href"):
        flow.append(("PROPERTY", "next.href"))

    if check(client_c, r"new\s+URL"):
        flow.append(("URL", "new URL(next.href)"))

    if check(client_c, r"document\.cookie"):
        flow.append(("DATA", "document.cookie"))

    if check(client_c, r"location\.assign"):
        flow.append(("NAVIGATION", "location.assign(target.href)"))

    return flow


def main():
    if len(sys.argv) != 2:
        print("Usage: python agent/client_flow.py <challenge>")
        sys.exit(1)

    challenge = sys.argv[1]

    if not os.path.isdir(challenge):
        print("❌ Challenge introuvable")
        sys.exit(1)

    flow = analyze(challenge)

    print()
    print("=" * 70)
    print("🧠 CYBERAI V102 — CLIENT DATA-FLOW ENGINE")
    print("=" * 70)

    for index, (kind, value) in enumerate(flow):
        print(f"\n[{index + 1:02}] {kind}")
        print(f"     {value}")

        if index < len(flow) - 1:
            print("      ↓")

    print()
    print("=" * 70)
    print("🎯 ANALYSE")
    print("=" * 70)

    kinds = [x[0] for x in flow]

    if "GLOBAL" in kinds and "PROPERTY" in kinds:
        print("🔥 Objet global + propriété contrôlée détectés")

    if "DOM" in kinds and "URL" in kinds:
        print("🔥 Propriété DOM transformée en URL")

    if "DATA" in kinds and "NAVIGATION" in kinds:
        print("🚨 Cookie injecté dans une URL avant navigation")

    print()
    print("➡️ Priorité suivante : tester le flux côté navigateur.")
    print("=" * 70)


if __name__ == "__main__":
    main()
