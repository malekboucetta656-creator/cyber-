#!/usr/bin/env python3

import hashlib
import os
import subprocess
import time
from pathlib import Path


class ExperimentRunner:
    """
    Exécuteur générique d'expériences CTF locales.

    Retourne suffisamment d'informations pour que les moteurs
    d'analyse et de recherche de flag puissent travailler.
    """

    def __init__(self, challenge, timeout=30):
        self.challenge = os.path.abspath(challenge)
        self.timeout = timeout

    def snapshot_files(self):
        root = Path(self.challenge)

        if not root.exists():
            return {}

        snapshot = {}

        for path in root.rglob("*"):
            if not path.is_file():
                continue

            if any(
                part in {
                    ".git",
                    "node_modules",
                    "__pycache__",
                    ".venv",
                    ".cyberai",
                }
                for part in path.parts
            ):
                continue

            try:
                data = path.read_bytes()

                snapshot[str(path)] = {
                    "size": len(data),
                    "sha256": hashlib.sha256(data).hexdigest(),
                }

            except Exception:
                continue

        return snapshot

    def run(
        self,
        command,
        cwd=None,
        stdin=None,
        timeout=None,
        env=None,
    ):
        """
        Exécute une commande dans l'environnement du challenge.

        command:
            liste de paramètres, par exemple:
            ["./chall", "AAAA"]

        Ne passe jamais une commande utilisateur directement
        à shell=True.
        """

        if not isinstance(command, (list, tuple)):
            raise TypeError(
                "command doit être une liste ou un tuple"
            )

        if not command:
            raise ValueError(
                "command ne peut pas être vide"
            )

        if cwd is None:
            cwd = self.challenge

        cwd = os.path.abspath(cwd)

        if not os.path.isdir(cwd):
            raise FileNotFoundError(
                f"Répertoire inexistant : {cwd}"
            )

        limit = timeout or self.timeout

        before = self.snapshot_files()

        started = time.time()

        result = {
            "command": list(command),
            "cwd": cwd,
            "status": "ERROR",
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "duration": 0,
            "files_created": [],
            "files_modified": [],
        }

        try:
            process = subprocess.run(
                list(command),
                cwd=cwd,
                input=stdin,
                capture_output=True,
                text=True,
                timeout=limit,
                env=env,
                shell=False,
            )

            result["returncode"] = (
                process.returncode
            )

            result["stdout"] = process.stdout
            result["stderr"] = process.stderr

            if process.returncode == 0:
                result["status"] = "SUCCESS"
            else:
                result["status"] = "NONZERO_EXIT"

        except subprocess.TimeoutExpired as e:

            result["status"] = "TIMEOUT"
            result["timed_out"] = True

            if e.stdout:
                result["stdout"] = (
                    e.stdout
                    if isinstance(e.stdout, str)
                    else e.stdout.decode(
                        errors="ignore"
                    )
                )

            if e.stderr:
                result["stderr"] = (
                    e.stderr
                    if isinstance(e.stderr, str)
                    else e.stderr.decode(
                        errors="ignore"
                    )
                )

        except FileNotFoundError as e:

            result["status"] = "COMMAND_NOT_FOUND"
            result["stderr"] = str(e)

        except Exception as e:

            result["status"] = "ERROR"
            result["stderr"] = str(e)

        finally:

            result["duration"] = round(
                time.time() - started,
                3,
            )

        after = self.snapshot_files()

        before_paths = set(before)
        after_paths = set(after)

        result["files_created"] = sorted(
            after_paths - before_paths
        )

        common = before_paths & after_paths

        result["files_modified"] = sorted(
            path
            for path in common
            if before[path]["sha256"]
            != after[path]["sha256"]
        )

        return result


def main():
    """
    Petit test autonome.

    Usage:
        python -m agent.experiment_runner <challenge>
    """

    import sys

    if len(sys.argv) != 2:
        print(
            "Usage: python -m agent.experiment_runner "
            "<challenge>"
        )
        raise SystemExit(1)

    challenge = os.path.abspath(sys.argv[1])

    runner = ExperimentRunner(challenge)

    result = runner.run(
        ["python", "-c", "print('CYBERAI_TEST')"]
    )

    print()
    print("=" * 70)
    print("🧪 CYBERAI — EXPERIMENT RUNNER")
    print("=" * 70)

    print("Status    :", result["status"])
    print("Return    :", result["returncode"])
    print("Timeout   :", result["timed_out"])
    print("Duration  :", result["duration"], "s")
    print("Created   :", len(result["files_created"]))
    print("Modified  :", len(result["files_modified"]))

    print()
    print("STDOUT:")
    print(result["stdout"])

    if result["stderr"]:
        print("STDERR:")
        print(result["stderr"])


if __name__ == "__main__":
    main()
