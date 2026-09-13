#!/usr/bin/env python3

import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

from agent.experiment_runner import ExperimentRunner
from agent.flag_engine import FlagEngine


class WebExperiment:
    """
    Moteur expérimental générique pour challenges WEB.

    Principes :
      - aucune connaissance spécifique de whatsNew
      - observations séparées des conclusions
      - Chromium utilisé pour les observations navigateur
      - recherche de flags dans toutes les sorties
      - aucune hypothèse déclarée VALIDATED sans preuve dynamique
    """

    SERVER_COMMANDS = [
        ["npm", "start"],
        ["npm", "run", "start"],
        ["node", "src/server.js"],
    ]

    COMMON_PORTS = [
        3000,
        3001,
        5000,
        8000,
        8080,
        8081,
        8888,
    ]

    def __init__(self, challenge, timeout=30):
        self.challenge = Path(challenge).resolve()
        self.timeout = timeout

        self.runner = ExperimentRunner(
            str(self.challenge),
            timeout=timeout,
        )

        self.server_process = None
        self.server_command = None
        self.base_url = None

    # ---------------------------------------------------------
    # UTILITAIRES
    # ---------------------------------------------------------

    def chromium_path(self):
        for binary in (
            "chromium",
            "chromium-browser",
            "google-chrome",
            "google-chrome-stable",
        ):
            path = shutil.which(binary)

            if path:
                return path

        return None

    def read_package(self):
        package = self.challenge / "package.json"

        if not package.exists():
            return {}

        try:
            return json.loads(
                package.read_text(
                    encoding="utf-8"
                )
            )
        except Exception:
            return {}

    def detect_port(self):
        package = self.read_package()

        scripts = package.get(
            "scripts",
            {},
        )

        text = json.dumps(
            scripts,
            ensure_ascii=False,
        )

        matches = re.findall(
            r"(?:PORT[=\s]+|localhost:|127\.0\.0\.1:)(\d{2,5})",
            text,
            re.I,
        )

        for match in matches:
            port = int(match)

            if 1 <= port <= 65535:
                return port

        return None

    # ---------------------------------------------------------
    # SERVEUR
    # ---------------------------------------------------------

    def server_running(self, url):
        try:
            request = urllib.request.Request(
                url,
                method="GET",
                headers={
                    "User-Agent": "CyberAI-WebExperiment/1.0"
                },
            )

            with urllib.request.urlopen(
                request,
                timeout=2,
            ) as response:

                return {
                    "running": True,
                    "status": response.status,
                    "url": url,
                }

        except Exception as exc:

            return {
                "running": False,
                "error": str(exc),
                "url": url,
            }

    def start_server(self):
        """
        Démarre uniquement un serveur local du challenge.

        Aucun accès réseau externe n'est demandé ici.
        """

        existing_port = self.detect_port()

        ports = []

        if existing_port:
            ports.append(existing_port)

        ports.extend(
            p for p in self.COMMON_PORTS
            if p not in ports
        )

        for port in ports:

            url = f"http://127.0.0.1:{port}/"

            if self.server_running(url)["running"]:
                self.base_url = url
                return {
                    "status": "ALREADY_RUNNING",
                    "url": url,
                    "port": port,
                }

        package = self.read_package()
        scripts = package.get(
            "scripts",
            {},
        )

        commands = []

        if "start" in scripts:
            commands.append(
                ["npm", "start"]
            )

        if "start" in scripts:
            commands.append(
                ["npm", "run", "start"]
            )

        commands.append(
            ["node", "src/server.js"]
        )

        for command in commands:

            try:

                env = os.environ.copy()

                # On ne force PORT que si aucun port
                # n'est déjà fourni par le challenge.
                if "PORT" not in env:
                    env["PORT"] = str(
                        existing_port or 3000
                    )

                process = subprocess.Popen(
                    command,
                    cwd=str(self.challenge),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=env,
                )

                self.server_process = process
                self.server_command = command

                port = int(
                    env["PORT"]
                )

                url = (
                    f"http://127.0.0.1:"
                    f"{port}/"
                )

                deadline = time.time() + 10

                while time.time() < deadline:

                    if process.poll() is not None:
                        break

                    status = self.server_running(
                        url
                    )

                    if status["running"]:
                        self.base_url = url

                        return {
                            "status": "STARTED",
                            "url": url,
                            "port": port,
                            "command": command,
                        }

                    time.sleep(0.25)

            except Exception as exc:
                last_error = str(exc)
                continue

        return {
            "status": "FAILED",
            "error": locals().get(
                "last_error",
                "Impossible de démarrer le serveur",
            ),
        }

    def stop_server(self):
        if self.server_process is None:
            return

        if self.server_process.poll() is None:

            try:
                self.server_process.terminate()
                self.server_process.wait(
                    timeout=5
                )

            except subprocess.TimeoutExpired:
                self.server_process.kill()

        self.server_process = None

    # ---------------------------------------------------------
    # CHROMIUM
    # ---------------------------------------------------------

    def browser_probe(self, url):
        chromium = self.chromium_path()

        if not chromium:
            return {
                "status": "CHROMIUM_NOT_FOUND",
                "url": url,
            }

        script = r"""
const url = process.argv[1];

console.log("CYBERAI_BROWSER_START");
console.log("URL", url);

const { spawnSync } = require("child_process");

const result = spawnSync(
    "chromium",
    [
        "--headless",
        "--no-sandbox",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--dump-dom",
        "--enable-logging=stderr",
        url
    ],
    {
        encoding: "utf8",
        timeout: 15000
    }
);

console.log("RETURN_CODE", result.status);

if (result.stdout) {
    console.log("DOM_BEGIN");
    console.log(result.stdout);
    console.log("DOM_END");
}

if (result.stderr) {
    console.log("BROWSER_STDERR_BEGIN");
    console.log(result.stderr);
    console.log("BROWSER_STDERR_END");
}
"""

        result = self.runner.run(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess,sys\n"
                    "p=subprocess.run([\n"
                    f"'{chromium}',\n"
                    "'--headless',\n"
                    "'--no-sandbox',\n"
                    "'--disable-gpu',\n"
                    "'--disable-dev-shm-usage',\n"
                    "'--dump-dom',\n"
                    "'--enable-logging=stderr',\n"
                    "sys.argv[1]\n"
                    "],capture_output=True,text=True,"
                    "timeout=15)\n"
                    "print('RETURN_CODE',p.returncode)\n"
                    "print('DOM_BEGIN')\n"
                    "print(p.stdout)\n"
                    "print('DOM_END')\n"
                    "print('BROWSER_STDERR_BEGIN',"
                    "file=sys.stderr)\n"
                    "print(p.stderr,"
                    "file=sys.stderr)\n"
                    "print('BROWSER_STDERR_END',"
                    "file=sys.stderr)\n"
                ),
                url,
            ]
        )

        return {
            "status": result["status"],
            "url": url,
            "returncode": result["returncode"],
            "stdout": result["stdout"],
            "stderr": result["stderr"],
            "timed_out": result["timed_out"],
            "duration": result["duration"],
        }

    # ---------------------------------------------------------
    # EXTRACTION OBSERVATIONS
    # ---------------------------------------------------------

    def analyze_browser_output(self, result):
        stdout = result.get(
            "stdout",
            "",
        )

        stderr = result.get(
            "stderr",
            "",
        )

        combined = (
            stdout
            + "\n"
            + stderr
        )

        observations = {
            "dom_present": (
                "DOM_BEGIN" in stdout
            ),
            "html_length": len(stdout),
            "console_lines": [],
            "navigation_indicators": [],
            "dom_indicators": [],
            "flag_candidates": [],
        }

        for line in combined.splitlines():

            line = line.strip()

            if not line:
                continue

            if (
                "CONSOLE" in line
                or "INFO:CONSOLE" in line
            ):
                observations[
                    "console_lines"
                ].append(line)

        patterns = {
            "href": r"\bhref\s*=",
            "location": r"\blocation\b",
            "window": r"\bwindow\b",
            "getAttribute": r"\bgetAttribute\b",
            "innerHTML": r"\binnerHTML\b",
            "outerHTML": r"\bouterHTML\b",
            "script": r"<script\b",
        }

        for name, pattern in patterns.items():

            if re.search(
                pattern,
                combined,
                re.I,
            ):
                observations[
                    "dom_indicators"
                ].append(name)

        observations[
            "flag_candidates"
        ] = FlagEngine.extract_from_text(
            combined,
            "web_experiment",
        )

        return observations

    # ---------------------------------------------------------
    # HYPOTHÈSES
    # ---------------------------------------------------------

    def classify_hypothesis(self, hypothesis):
        name = str(
            hypothesis.get(
                "name",
                "",
            )
        ).lower()

        return {
            "browser": any(
                word in name
                for word in (
                    "xss",
                    "dom",
                    "navigation",
                    "prototype",
                    "clobber",
                    "client",
                )
            ),
            "navigation": any(
                word in name
                for word in (
                    "navigation",
                    "redirect",
                    "href",
                    "location",
                )
            ),
            "xss": "xss" in name,
        }

    # ---------------------------------------------------------
    # EXPÉRIENCE
    # ---------------------------------------------------------

    def run_hypothesis(
        self,
        hypothesis,
    ):
        name = hypothesis.get(
            "name",
            "unknown",
        )

        capabilities = (
            self.classify_hypothesis(
                hypothesis
            )
        )

        experiment = {
            "hypothesis": name,
            "confidence": hypothesis.get(
                "confidence",
                0,
            ),
            "status": "RUNNING",
            "capabilities": capabilities,
            "observations": [],
            "flags": [],
        }

        if not self.base_url:
            experiment["status"] = (
                "NO_SERVER"
            )
            return experiment

        # Première observation neutre.
        # Elle sert de baseline.
        result = self.browser_probe(
            self.base_url
        )

        observation = (
            self.analyze_browser_output(
                result
            )
        )

        experiment[
            "observations"
        ].append({
            "type": "browser_baseline",
            "result": result,
            "analysis": observation,
        })

        experiment["flags"].extend(
            observation.get(
                "flag_candidates",
                [],
            )
        )

        if experiment["flags"]:
            experiment["status"] = (
                "FLAG_CANDIDATE"
            )
        else:
            experiment["status"] = (
                "OBSERVED"
            )

        return experiment

    # ---------------------------------------------------------
    # EXÉCUTION GLOBALE
    # ---------------------------------------------------------

    def execute(self, context):
        hypotheses = context.get(
            "hypotheses",
            [],
        )

        hypotheses = [
            h for h in hypotheses
            if isinstance(h, dict)
            and h.get("name")
        ]

        hypotheses.sort(
            key=lambda h: h.get(
                "confidence",
                0,
            ),
            reverse=True,
        )

        server = self.start_server()

        experiments = []
        flags = []

        if server.get("status") in {
            "STARTED",
            "ALREADY_RUNNING",
        }:

            for hypothesis in hypotheses:

                result = self.run_hypothesis(
                    hypothesis
                )

                experiments.append(
                    result
                )

                flags.extend(
                    result.get(
                        "flags",
                        [],
                    )
                )

        else:

            experiments.append({
                "status": "SERVER_FAILED",
                "server": server,
            })

        self.stop_server()

        context[
            "web_experiments"
        ] = experiments

        if flags:
            context.setdefault(
                "flags",
                [],
            )

            for flag in flags:
                if flag not in context[
                    "flags"
                ]:
                    context[
                        "flags"
                    ].append(flag)

        context.setdefault(
            "metadata",
            {},
        )

        context[
            "metadata"
        ][
            "web_experiment"
        ] = {
            "server": server,
            "experiments": len(
                experiments
            ),
            "flags": len(flags),
        }

        return context


def main():

    if len(sys.argv) != 2:
        print(
            "Usage: python -m agent.web_experiment "
            "<challenge>"
        )
        raise SystemExit(1)

    challenge = Path(
        sys.argv[1]
    ).resolve()

    context_file = (
        challenge
        / ".cyberai"
        / "context.json"
    )

    if not context_file.exists():
        print(
            "[!] Context introuvable :",
            context_file,
        )
        raise SystemExit(1)

    with context_file.open(
        "r",
        encoding="utf-8",
    ) as f:
        context = json.load(f)

    engine = WebExperiment(
        str(challenge)
    )

    print()
    print("=" * 70)
    print("🌐 CYBERAI — WEB EXPERIMENT")
    print("=" * 70)

    context = engine.execute(
        context
    )

    experiments = context.get(
        "web_experiments",
        [],
    )

    print()
    print(
        "Expériences exécutées :",
        len(experiments),
    )

    for index, experiment in enumerate(
        experiments,
        1,
    ):

        print()
        print(
            f"[{index}]",
            experiment.get(
                "hypothesis",
                "server",
            ),
        )

        print(
            "    Status :",
            experiment.get(
                "status"
            ),
        )

        if experiment.get(
            "flags"
        ):
            print(
                "    🏁 Flags :",
                experiment["flags"],
            )

    print()
    print("=" * 70)

    if context.get("flags"):
        print(
            "🏁 FLAGS :",
            len(
                context["flags"]
            ),
        )

        for flag in context["flags"]:
            print(
                "   ",
                flag,
            )
    else:
        print(
            "[-] Aucun flag observé."
        )

    with context_file.open(
        "w",
        encoding="utf-8",
    ) as f:
        json.dump(
            context,
            f,
            indent=2,
            ensure_ascii=False,
        )

    print()
    print(
        "[+] Context sauvegardé :",
        context_file,
    )


if __name__ == "__main__":
    main()
