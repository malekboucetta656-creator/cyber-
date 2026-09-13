import os
import sys


def inspect_file(challenge, relative_path):
    path = os.path.join(challenge, relative_path)

    if not os.path.isfile(path):
        return f"❌ Fichier introuvable : {path}"

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        return content

    except Exception as e:
        return f"❌ Erreur lecture : {e}"


def execute(challenge, action):
    action_type = action.get("action")
    file_path = action.get("file")

    if action_type == "inspect":
        return inspect_file(challenge, file_path)

    return f"⚠️ Action non supportée : {action_type}"


def main():
    if len(sys.argv) != 2:
        print("Usage: python agent/executor.py <challenge>")
        sys.exit(1)

    challenge = sys.argv[1]

    if not os.path.isdir(challenge):
        print("❌ Challenge introuvable :", challenge)
        sys.exit(1)

    action = {
        "action": "inspect",
        "file": "src/filter.js"
    }

    print()
    print("=" * 70)
    print("⚙️ CYBERAI V5 — EXECUTOR")
    print("=" * 70)

    print(f"\n▶ Action : {action['action']}")
    print(f"▶ Fichier : {action['file']}")

    result = execute(challenge, action)

    print("\n" + "=" * 70)
    print("📄 RÉSULTAT")
    print("=" * 70)

    print(result)


if __name__ == "__main__":
    main()
