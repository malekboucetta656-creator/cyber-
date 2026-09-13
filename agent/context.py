#!/usr/bin/env python3

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class ChallengeContext:
    """
    État central d'une analyse CyberAI.

    Tous les modules alimentent ce contexte.
    Aucun module ne doit dépendre directement d'un autre module.
    """

    challenge: str

    files: list[str] = field(default_factory=list)

    category: str = "unknown"

    scores: dict[str, float] = field(default_factory=dict)

    sources: list[Any] = field(default_factory=list)
    filters: list[Any] = field(default_factory=list)
    storage: list[Any] = field(default_factory=list)
    sinks: list[Any] = field(default_factory=list)

    bot: list[Any] = field(default_factory=list)
    triggers: list[Any] = field(default_factory=list)
    client: list[Any] = field(default_factory=list)
    dom: list[Any] = field(default_factory=list)
    navigation: list[Any] = field(default_factory=list)

    data_flow: list[Any] = field(default_factory=list)

    hypotheses: list[Any] = field(default_factory=list)

    experiments: list[Any] = field(default_factory=list)

    exploits: list[Any] = field(default_factory=list)

    flags: list[Any] = field(default_factory=list)

    module_results: dict[str, Any] = field(default_factory=dict)

    errors: list[Any] = field(default_factory=list)

    metadata: dict[str, Any] = field(default_factory=dict)

    def add_result(self, module_name: str, result: Any):
        self.module_results[module_name] = result

    def add_error(self, module_name: str, error: Any):
        self.errors.append({
            "module": module_name,
            "error": error,
        })

    def merge(self, result: Any):
        """
        Fusionne automatiquement les résultats d'un module
        dans le contexte global.
        """

        if not isinstance(result, dict):
            return

        mapping = {
            "sources": "sources",
            "filters": "filters",
            "storage": "storage",
            "sinks": "sinks",
            "bot": "bot",
            "triggers": "triggers",
            "client": "client",
            "dom": "dom",
            "navigation": "navigation",
            "data_flow": "data_flow",
            "hypotheses": "hypotheses",
            "experiments": "experiments",
            "exploits": "exploits",
            "flags": "flags",
        }

        for source_key, target_key in mapping.items():

            values = result.get(source_key)

            if not isinstance(values, list):
                continue

            target = getattr(self, target_key)

            for value in values:
                if value not in target:
                    target.append(value)

        if "challenge_type" in result:
            self.metadata["challenge_type"] = result["challenge_type"]

    def summary(self) -> dict:
        return {
            "challenge": self.challenge,
            "category": self.category,
            "files": len(self.files),
            "scores": self.scores,
            "sources": len(self.sources),
            "filters": len(self.filters),
            "storage": len(self.storage),
            "sinks": len(self.sinks),
            "bot": len(self.bot),
            "client": len(self.client),
            "dom": len(self.dom),
            "navigation": len(self.navigation),
            "hypotheses": len(self.hypotheses),
            "experiments": len(self.experiments),
            "exploits": len(self.exploits),
            "flags": len(self.flags),
            "errors": len(self.errors),
            "modules": len(self.module_results),
        }

    def to_dict(self) -> dict:
        return {
            "challenge": self.challenge,
            "category": self.category,
            "files": self.files,
            "scores": self.scores,
            "sources": self.sources,
            "filters": self.filters,
            "storage": self.storage,
            "sinks": self.sinks,
            "bot": self.bot,
            "triggers": self.triggers,
            "client": self.client,
            "dom": self.dom,
            "navigation": self.navigation,
            "data_flow": self.data_flow,
            "hypotheses": self.hypotheses,
            "experiments": self.experiments,
            "exploits": self.exploits,
            "flags": self.flags,
            "module_results": self.module_results,
            "errors": self.errors,
            "metadata": self.metadata,
        }


def discover_files(challenge: str) -> list[str]:
    """
    Découverte générique des fichiers du challenge.
    """

    root = Path(challenge)

    if root.is_file():
        return [str(root)]

    if not root.exists():
        return []

    files = []

    for path in root.rglob("*"):
        if not path.is_file():
            continue

        # Ignorer les gros artefacts inutiles.
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

        files.append(str(path))

    return sorted(files)
