#!/usr/bin/env python3

import json
import os
import re
import subprocess
import time
from pathlib import Path


class ExperimentEngine:
    """
    Moteur expérimental CyberAI.

    Une hypothèse n'est jamais considérée comme valide
    uniquement parce qu'elle possède un score élevé.

    Elle doit produire une observation réelle.
    """

    def __init__(self, challenge):
        self.challenge = os.path.abspath(challenge)
        self.results = []

    def make_experiment(self, hypothesis):
        name = hypothesis.get("name", "Unknown")
        confidence = hypothesis.get("confidence", 0)

        return {
            "id": f"exp-{len(self.results) + 1:03d}",
            "hypothesis": name,
            "confidence": confidence,
            "status": "PENDING",
            "observations": [],
            "validated": False,
            "timestamp": time.time(),
        }

    def observe_files(self):
        """
        Observation passive du challenge.
        Aucun exploit n'est lancé ici.
        """

        root = Path(self.challenge)

        observations = {
            "challenge_exists": root.exists(),
            "files": [],
            "javascript_files": [],
            "html_files": [],
        }

        if not root.exists():
            return observations

        for path in root.rglob("*"):

            if not path.is_file():
                continue

            if any(
                part in {
                    ".git",
                    "node_modules",
                    "__pycache__",
                    ".venv",
                }
                for part in path.parts
            ):
                continue

            path_str = str(path)

            observations["files"].append(path_str)

            if path.suffix.lower() == ".js":
                observations["javascript_files"].append(
                    path_str
                )

            if path.suffix.lower() in {
                ".html",
                ".htm",
            }:
                observations["html_files"].append(
                    path_str
                )

        return observations

    def inspect_hypothesis(self, hypothesis):
        """
        Première validation expérimentale.

        Cette phase cherche des preuves concrètes
        dans le challenge mais ne prétend pas encore
        avoir exécuté un exploit.
        """

        name = hypothesis.get(
            "name",
            "",
        ).lower()

        observations = []
        evidence = []

        files = self.observe_files()

        observations.append({
            "type": "filesystem",
            "value": {
                "files": len(files["files"]),
                "javascript": len(
                    files["javascript_files"]
                ),
                "html": len(
                    files["html_files"]
                ),
            },
        })

        # --------------------------------------------------
        # Stored XSS / Admin Bot
        # --------------------------------------------------

        if (
            "stored xss" in name
            or "admin bot" in name
        ):

            keywords = [
                "raw(",
                "decodehtml",
                "issuspicious",
                "visitlatestposts",
                "admin/preview",
            ]

            matches = self.search_source(
                keywords
            )

            if matches:
                evidence.extend(matches)

        # --------------------------------------------------
        # DOM property manipulation
        # --------------------------------------------------

        if (
            "dom property" in name
            or "dom-controlled" in name
            or "navigation" in name
        ):

            keywords = [
                "window.whatsnew",
                "getattribute",
                ".href",
                "new url",
                "location.assign",
            ]

            matches = self.search_source(
                keywords
            )

            if matches:
                evidence.extend(matches)

        # --------------------------------------------------
        # Détermination du résultat
        # --------------------------------------------------

        if evidence:

            status = "OBSERVED"

            observations.append({
                "type": "source_evidence",
                "count": len(evidence),
            })

            observations.extend(evidence)

        else:

            status = "NO_EVIDENCE"

        return {
            "status": status,
            "observations": observations,
            "evidence": evidence,
        }

    def search_source(self, keywords):
        """
        Recherche de preuves textuelles dans les sources.
        """

        results = []

        root = Path(self.challenge)

        if not root.exists():
            return results

        for path in root.rglob("*"):

            if not path.is_file():
                continue

            if any(
                part in {
                    ".git",
                    "node_modules",
                    "__pycache__",
                    ".venv",
                }
                for part in path.parts
            ):
                continue

            if path.suffix.lower() not in {
                ".js",
                ".html",
                ".py",
                ".json",
                ".c",
                ".cpp",
                ".h",
            }:
                continue

            try:
                content = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except Exception:
                continue

            lower = content.lower()

            for keyword in keywords:

                if keyword.lower() not in lower:
                    continue

                # trouver la première occurrence
                index = lower.find(
                    keyword.lower()
                )

                line = (
                    content[:index]
                    .count("\n")
                    + 1
                )

                results.append({
                    "type": "keyword",
                    "keyword": keyword,
                    "file": str(path),
                    "line": line,
                })

        return results

    def run(self, hypotheses):
        """
        Exécute les expériences dans l'ordre
        de confiance décroissante.
        """

        if not isinstance(
            hypotheses,
            list,
        ):
            hypotheses = []

        hypotheses = sorted(
            hypotheses,
            key=lambda x: x.get(
                "confidence",
                0,
            ),
            reverse=True,
        )

        for hypothesis in hypotheses:

            experiment = self.make_experiment(
                hypothesis
            )

            experiment["status"] = "RUNNING"

            result = self.inspect_hypothesis(
                hypothesis
            )

            experiment["observations"] = (
                result["observations"]
            )

            experiment["evidence"] = (
                result["evidence"]
            )

            # IMPORTANT :
            # OBSERVED != VALIDATED.
            #
            # Nous avons seulement trouvé
            # des preuves statiques.
            #
            # La validation réelle viendra
            # après exécution contrôlée.

            if result["status"] == "OBSERVED":

                experiment["status"] = (
                    "EVIDENCE_FOUND"
                )

                experiment["validated"] = False

            else:

                experiment["status"] = (
                    "REJECTED"
                )

                experiment["validated"] = False

            self.results.append(
                experiment
            )

        return self.results


def load_context(challenge):
    path = (
        Path(challenge)
        / ".cyberai"
        / "context.json"
    )

    if not path.exists():
        raise FileNotFoundError(
            f"context.json introuvable : {path}"
        )

    with open(
        path,
        "r",
        encoding="utf-8",
    ) as f:
        return json.load(f)


def save_context(challenge, context):
    path = (
        Path(challenge)
        / ".cyberai"
        / "context.json"
    )

    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with open(
        path,
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            context,
            f,
            indent=2,
            ensure_ascii=False,
        )


def main():

    import sys

    if len(sys.argv) != 2:

        print(
            "Usage: python agent/experiment_engine.py "
            "<challenge>"
        )

        raise SystemExit(1)

    challenge = os.path.abspath(
        sys.argv[1]
    )

    context = load_context(
        challenge
    )

    hypotheses = context.get(
        "hypotheses",
        [],
    )

    engine = ExperimentEngine(
        challenge
    )

    experiments = engine.run(
        hypotheses
    )

    context["experiments"] = experiments

    save_context(
        challenge,
        context,
    )

    print()
    print("=" * 70)
    print("🧪 CYBERAI — EXPERIMENT ENGINE")
    print("=" * 70)

    print(
        f"\nHypothèses : {len(hypotheses)}"
    )

    print(
        f"Expériences : {len(experiments)}"
    )

    for experiment in experiments:

        print()
        print(
            f"[{experiment['id']}] "
            f"{experiment['hypothesis']}"
        )

        print(
            f"  Status : "
            f"{experiment['status']}"
        )

        print(
            f"  Validated : "
            f"{experiment['validated']}"
        )

        print(
            f"  Evidence : "
            f"{len(experiment.get('evidence', []))}"
        )

    print()
    print(
        "⚠️ EVIDENCE_FOUND ne signifie PAS "
        "EXPLOIT VALIDÉ."
    )

    print(
        f"\n[+] Context sauvegardé : "
        f"{Path(challenge) / '.cyberai' / 'context.json'}"
    )


if __name__ == "__main__":
    main()
