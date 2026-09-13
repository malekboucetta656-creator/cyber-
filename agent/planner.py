import sys
import os


def build_plan(challenge):
    return [
        {
            "priority": 1,
            "action": "inspect",
            "file": "src/filter.js",
            "reason": "Comprendre exactement le décodage et le filtrage."
        },
        {
            "priority": 2,
            "action": "inspect",
            "file": "src/routes/categoryRoutes.js",
            "reason": "Déterminer quels champs utilisateur passent dans le filtre."
        },
        {
            "priority": 3,
            "action": "inspect",
            "file": "src/categories/tech.js",
            "reason": "Confirmer le sink HTML et le champ réellement injectable."
        },
        {
            "priority": 4,
            "action": "inspect",
            "file": "public/static/updates.js",
            "reason": "Comprendre le comportement côté navigateur."
        },
        {
            "priority": 5,
            "action": "inspect",
            "file": "src/routes/reportRoutes.js",
            "reason": "Comprendre le déclenchement du bot."
        },
        {
            "priority": 6,
            "action": "test",
            "file": None,
            "reason": "Construire ensuite un test local contrôlé."
        },
    ]


def show_plan(plan):
    print()
    print("=" * 70)
    print("🧠 CYBERAI V5 — PLANNER")
    print("=" * 70)

    print("\n🎯 PLAN D'INVESTIGATION\n")

    for step in plan:
        print(
            f"[{step['priority']}] "
            f"{step['action'].upper():7} "
            f"{step['file'] or '-'}"
        )
        print(f"    └─ {step['reason']}")

    print()
    print("=" * 70)
    print("▶ PROCHAINE ACTION")
    print("=" * 70)

    first = plan[0]

    print(f"\n{first['action'].upper()} : {first['file']}")
    print(f"Pourquoi : {first['reason']}")


def main():
    if len(sys.argv) != 2:
        print("Usage: python agent/planner.py <challenge>")
        sys.exit(1)

    challenge = sys.argv[1]

    if not os.path.isdir(challenge):
        print("❌ Challenge introuvable :", challenge)
        sys.exit(1)

    plan = build_plan(challenge)
    show_plan(plan)


if __name__ == "__main__":
    main()
