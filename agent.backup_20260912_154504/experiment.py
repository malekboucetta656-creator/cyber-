#!/usr/bin/env python3

import subprocess
import tempfile
from pathlib import Path
from itertools import product


TIMEOUT = 5


# ============================================================
# EXPERIMENT
# ============================================================

class Experiment:
    def __init__(self, name, html, required_checks):
        self.name = name
        self.html = html
        self.required_checks = required_checks


# ============================================================
# CHROMIUM
# ============================================================

def run_chromium(html):
    temp = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            suffix=".html",
            delete=False
        ) as f:
            f.write(html)
            temp = f.name

        cmd = [
            "chromium",
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--disable-dev-shm-usage",
            "--enable-logging=stderr",
            "--dump-dom",
            f"file://{temp}",
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
        )

        return result.stdout + "\n" + result.stderr

    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"

    except Exception as exc:
        return f"[ERROR] {exc}"

    finally:
        if temp:
            Path(temp).unlink(missing_ok=True)


# ============================================================
# VALIDATION
# ============================================================

def validate(output, checks):
    results = []

    low = output.lower()

    for description, expected in checks:

        passed = expected.lower() in low

        results.append({
            "description": description,
            "expected": expected,
            "passed": passed,
        })

    return results


def status(results):

    if not results:
        return "INCONCLUSIVE"

    if all(r["passed"] for r in results):
        return "VALIDATED"

    return "REJECTED"


# ============================================================
# HTML GENERATOR
# ============================================================

FORM_CONTROLS = [
    "input",
    "button",
    "output",
    "select",
    "textarea",
    "fieldset",
]


CONTROL_ATTRIBUTES = [
    "",
    'href="/admin/preview"',
    'value="/admin/preview"',
    'data="/admin/preview"',
]


NAMES = [
    "next",
]


def generate_html(tag, name, attributes):

    return f"""
<!doctype html>
<html>
<body>

<form id="whatsNew">

    <{tag}
        name="{name}"
        {attributes}>
        /admin/preview
    </{tag}>

</form>

<script>

const root = window.whatsNew;

console.log(
    "ROOT",
    Object.prototype.toString.call(root)
);

console.log(
    "NEXT",
    Object.prototype.toString.call(root?.next)
);

console.log(
    "GETATTR",
    typeof root?.next?.getAttribute
);

console.log(
    "HREF",
    typeof root?.next?.href
);

console.log(
    "RAW_HREF",
    root?.next?.getAttribute?.("href")
);

console.log(
    "VALUE",
    root?.next?.getAttribute?.("value")
);

console.log(
    "DATA",
    root?.next?.getAttribute?.("data")
);

</script>

</body>
</html>
"""


# ============================================================
# EXPERIMENT BUILDER
# ============================================================

def build_experiments():

    experiments = []

    number = 0

    for tag, name, attributes in product(
        FORM_CONTROLS,
        NAMES,
        CONTROL_ATTRIBUTES,
    ):

        number += 1

        experiment = Experiment(
            name=f"{tag.upper()}_{number}",
            html=generate_html(
                tag,
                name,
                attributes,
            ),
            required_checks=[
                (
                    "window.whatsNew exists",
                    "ROOT [object HTMLFormElement]",
                ),
                (
                    "next exists",
                    "NEXT [object HTML",
                ),
                (
                    "getAttribute exists",
                    "GETATTR function",
                ),
            ],
        )

        experiments.append(experiment)

    return experiments


# ============================================================
# DISPLAY
# ============================================================

def display_result(experiment, results, final_status):

    print(
        f"\n🧪 {experiment.name}"
    )

    for result in results:

        if result["passed"]:
            print(
                f"    [+] {result['description']}"
            )
        else:
            print(
                f"    [-] {result['description']}"
            )

    print(
        f"    STATUS : {final_status}"
    )


# ============================================================
# MAIN
# ============================================================

def main():

    print("""
╔══════════════════════════════════════════════╗
║       CYBERAI V3 — EXPERIMENT GENERATOR      ║
║                                              ║
║       AUTOMATIC DOM HYPOTHESIS SEARCH        ║
╚══════════════════════════════════════════════╝
""")

    experiments = build_experiments()

    print(
        f"[+] Expériences générées : {len(experiments)}"
    )

    validated = []
    rejected = []

    for experiment in experiments:

        output = run_chromium(
            experiment.html
        )

        results = validate(
            output,
            experiment.required_checks
        )

        final_status = status(results)

        display_result(
            experiment,
            results,
            final_status
        )

        if final_status == "VALIDATED":
            validated.append(experiment.name)

        elif final_status == "REJECTED":
            rejected.append(experiment.name)

    print("\n" + "=" * 55)
    print("V3 RESULTS")
    print("=" * 55)

    print(
        f"VALIDATED : {len(validated)}"
    )

    print(
        f"REJECTED  : {len(rejected)}"
    )

    if validated:

        print("\n🔥 HYPOTHÈSES VALIDÉES")

        for item in validated:
            print(
                f"    [+] {item}"
            )

    else:

        print(
            "\n[-] Aucune primitive complète validée."
        )

    print("""
=======================================================
CyberAI V3 termine la phase d'exploration automatique.

Prochaine évolution :
    V4 → générateur de chaînes d'exploitation
    V5 → validation multi-étapes
    V6 → recherche automatique de flag
=======================================================
""")


if __name__ == "__main__":
    main()
