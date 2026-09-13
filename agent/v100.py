import os
import sys
import subprocess

BANNER = r"""
======================================================================
                 🛡️ CYBERAI V100 PRO
======================================================================
        Autonomous CTF Investigation Framework
======================================================================
"""


def run_module(name, command):
    print("\n" + "=" * 70)
    print(f"🧠 {name}")
    print("=" * 70)
    print("$", " ".join(command))
    print()

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=60
        )

        if result.stdout:
            print(result.stdout)

        if result.stderr:
            print(result.stderr)

        return result.returncode

    except subprocess.TimeoutExpired:
        print("⏱️ Module timeout")
        return 124

    except Exception as e:
        print(f"❌ Erreur : {e}")
        return 1


def validate_challenge(path):
    if not os.path.isdir(path):
        print(f"❌ Challenge introuvable : {path}")
        return False
    return True


def main():
    if len(sys.argv) != 2:
        print("Usage:")
        print("python agent/v100.py <challenge>")
        sys.exit(1)

    challenge = os.path.abspath(sys.argv[1])

    if not validate_challenge(challenge):
        sys.exit(1)

    print(BANNER)
    print(f"🎯 Challenge : {challenge}")

    modules = [
        ("PHASE 1 — SCANNER", "agent/scanner.py"),
        ("PHASE 2 — DETECTOR", "agent/detector.py"),
        ("PHASE 3 — STATIC ANALYZER", "agent/analyzer.py"),
        ("PHASE 4 — WEB ANALYZER", "agent/web_analyzer.py"),
        ("PHASE 5 — HYPOTHESIS ENGINE", "agent/hypothesis.py"),
        ("PHASE 6 — PLANNER", "agent/planner.py"),
    ]

    results = {}

    for name, module in modules:
        module_path = os.path.join(os.getcwd(), module)

        if not os.path.isfile(module_path):
            print(f"\n⚠️ Module absent : {module}")
            continue

        code = run_module(
            name,
            [sys.executable, module_path, challenge]
        )

        results[module] = code

    print("\n" + "=" * 70)
    print("🧠 CYBERAI V100 — SYNTHÈSE")
    print("=" * 70)

    for module, code in results.items():
        if code == 0:
            status = "✅ OK"
        elif code == 124:
            status = "⏱️ TIMEOUT"
        else:
            status = f"❌ EXIT {code}"

        print(f"{status:15} {module}")

    print("\n" + "=" * 70)
    print("🎯 V100 — INVESTIGATION STATE")
    print("=" * 70)

    print("""
SOURCE
  ↓
FILTER
  ↓
STORAGE
  ↓
SINK
  ↓
BOT
  ↓
CLIENT JAVASCRIPT
  ↓
DOM / PROPERTY ANALYSIS
  ↓
HYPOTHESIS
  ↓
PLANNER
""")

    print("=" * 70)
    print("🚀 NEXT ENGINE")
    print("=" * 70)

    print("""
V100.1
  ├── Filter Analyzer
  ├── Client Data-Flow Engine
  ├── Hypothesis Scoring
  ├── Controlled Test Engine
  └── Flag Finder
""")

    print("\n🛡️ CyberAI V100 Pro — reconnaissance terminée.")


if __name__ == "__main__":
    main()
