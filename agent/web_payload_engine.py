#!/usr/bin/env python3

import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from agent.flag_engine import FlagEngine


class WebPayloadEngine:

    def __init__(self, challenge, base_url=None):
        self.challenge = Path(challenge).resolve()
        self.base_url = base_url

    # =========================================================
    # ROUTES
    # =========================================================

    def get_routes(self, context=None):

        routes = []

        def add_route(route):

            if not isinstance(route, str):
                return

            route = route.strip()

            if not route.startswith("/"):
                return

            # Ne jamais considérer un chemin Linux comme une route.
            forbidden_prefixes = (
                "/home/",
                "/root/",
                "/tmp/",
                "/usr/",
                "/var/",
                "/opt/",
                "/etc/",
                "/proc/",
                "/sys/",
            )

            if route.startswith(forbidden_prefixes):
                return

            # Fichiers source = pas des endpoints.
            if re.search(
                r"\.(js|ts|py|c|cpp|h|json|css|html)$",
                route,
                re.I,
            ):
                return

            if route not in routes:
                routes.append(route)

        # -----------------------------------------------------
        # Recherche dans les fichiers JavaScript
        # -----------------------------------------------------

        for path in self.challenge.rglob("*.js"):

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
                text = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except Exception:
                continue

            # Express :
            # app.get("/...")
            # app.post("/...")
            # router.get("/...")
            # router.post("/...")
            pattern = re.compile(
                r"""(?:app|router)\s*\.\s*
                    (?:get|post|put|patch|delete|head|options)
                    \s*\(\s*
                    ["'`]([^"'`]+)["'`]""",
                re.I | re.X,
            )

            for match in pattern.finditer(text):
                add_route(match.group(1))

        # -----------------------------------------------------
        # Ne jamais transformer les liens HTML ou chemins
        # génériques en endpoints d'injection.
        #
        # Seules les routes Express découvertes dans le code
        # serveur sont conservées.
        # -----------------------------------------------------

        routes = [
            route
            for route in routes
            if route.startswith("/category/")
            or route in {
                "/report",
                "/admin/preview",
            }
        ]

        # -----------------------------------------------------
        # Recherche dans le contexte CyberAI
        # -----------------------------------------------------

        if isinstance(context, dict):

            groups = [
                context.get("sources", []),
                context.get("client", []),
                context.get("navigation", []),
                context.get("data_flow", []),
            ]

            for group in groups:

                if not isinstance(group, list):
                    continue

                for item in group:

                    if isinstance(item, str):
                        text = item

                    elif isinstance(item, dict):
                        text = json.dumps(
                            item,
                            ensure_ascii=False,
                        )

                    else:
                        continue

                    pattern = re.compile(
                        r"""(?:
                            GET|POST|PUT|PATCH|DELETE
                            )?\s*
                            (/
                             (?!home/|root/|tmp/|usr/|var/)
                             [A-Za-z0-9_:\-./]+
                            )""",
                        re.I | re.X,
                    )

                    for match in pattern.finditer(text):
                        add_route(match.group(1))

        # -----------------------------------------------------
        # Tri
        # -----------------------------------------------------

        priority = {
            "/report": 0,
            "/admin/preview": 1,
            "/category/:slug/new": 2,
        }

        routes.sort(
            key=lambda route: (
                priority.get(route, 100),
                len(route),
                route,
            )
        )

        return routes

    # =========================================================
    # CHAMPS HTTP
    # =========================================================

    def discover_input_fields(self):

        fields = []

        for path in self.challenge.rglob("*.js"):

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
                text = path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            except Exception:
                continue

            # req.body.description
            pattern = re.compile(
                r"req\.body\.([A-Za-z_][A-Za-z0-9_]*)"
            )

            for match in pattern.finditer(text):

                field = match.group(1)

                if field not in fields:
                    fields.append(field)

            # req.body["description"]
            # req.body['description']
            pattern = re.compile(
                r"""req\.body\[
                    ["']([A-Za-z_][A-Za-z0-9_]*)["']
                    \]""",
                re.X,
            )

            for match in pattern.finditer(text):

                field = match.group(1)

                if field not in fields:
                    fields.append(field)

        return fields

    # =========================================================
    # PAYLOADS
    # =========================================================

    def xss_payloads(self):

        return [
            {
                "name": "html-marker",
                "value": (
                    '<b data-cyberai="xss-marker">'
                    'CYBERAI_XSS'
                    "</b>"
                ),
            },
            {
                "name": "svg-marker",
                "value": (
                    '<svg data-cyberai="svg-marker">'
                    "CYBERAI_SVG"
                    "</svg>"
                ),
            },
            {
                "name": "event-marker",
                "value": (
                    '<img src=x '
                    'onerror="console.log(\'CYBERAI_XSS\')">'
                ),
            },
            {
                "name": "script-marker",
                "value": (
                    '<script>'
                    'console.log("CYBERAI_SCRIPT")'
                    "</script>"
                ),
            },
        ]

    def dom_payloads(self):

        return [
            {
                "name": "dom-marker",
                "value": (
                    '<a id="cyberai_dom_marker">'
                    "CYBERAI_DOM"
                    "</a>"
                ),
            },
            {
                "name": "named-property",
                "value": (
                    '<input id="cyberai_dom_input">'
                ),
            },
            {
                "name": "href-marker",
                "value": (
                    '<a id="cyberai_next_marker" '
                    'href="/cyberai-marker">'
                    "CYBERAI_NAV"
                    "</a>"
                ),
            },
        ]

    def navigation_payloads(self):

        return [
            {
                "name": "relative-navigation",
                "value": (
                    '<a id="cyberai_nav" '
                    'href="/cyberai-navigation">'
                    "CYBERAI_NAV"
                    "</a>"
                ),
            },
            {
                "name": "fragment-navigation",
                "value": (
                    '<a id="cyberai_fragment" '
                    'href="#CYBERAI_NAV">'
                    "CYBERAI_NAV"
                    "</a>"
                ),
            },
        ]

    # =========================================================
    # PAYLOAD SELECTION
    # =========================================================

    def payloads_for(self, hypothesis):

        name = str(
            hypothesis.get("name", "")
        ).lower()

        payloads = []

        if "xss" in name:
            payloads.extend(
                self.xss_payloads()
            )

        if "dom" in name:
            payloads.extend(
                self.dom_payloads()
            )

        if "navigation" in name:
            payloads.extend(
                self.navigation_payloads()
            )

        if not payloads:

            payloads.append(
                {
                    "name": "generic-marker",
                    "value": "CYBERAI_MARKER",
                }
            )

        return payloads

    # =========================================================
    # HTTP
    # =========================================================

    def request(
        self,
        method,
        path,
        data=None,
    ):

        if not self.base_url:

            return {
                "status": "NO_BASE_URL"
            }

        url = urllib.parse.urljoin(
            self.base_url,
            path,
        )

        body = None

        if data is not None:

            body = urllib.parse.urlencode(
                data
            ).encode()

        request = urllib.request.Request(
            url,
            data=body,
            method=method.upper(),
            headers={
                "User-Agent":
                    "CyberAI-WebPayloadEngine/1.0",
                "Content-Type":
                    "application/x-www-form-urlencoded",
            },
        )

        try:

            with urllib.request.urlopen(
                request,
                timeout=10,
            ) as response:

                content = response.read(
                    1024 * 1024
                ).decode(
                    errors="replace"
                )

                return {
                    "status": "SUCCESS",
                    "url": url,
                    "http_status":
                        response.status,
                    "body": content,
                }

        except urllib.error.HTTPError as exc:

            try:
                content = exc.read().decode(
                    errors="replace"
                )
            except Exception:
                content = ""

            return {
                "status": "HTTP_ERROR",
                "url": url,
                "http_status":
                    exc.code,
                "body": content,
            }

        except Exception as exc:

            return {
                "status": "ERROR",
                "url": url,
                "error": str(exc),
            }

    # =========================================================
    # RESPONSE ANALYSIS
    # =========================================================

    def inspect_response(self, response):

        body = response.get(
            "body",
            "",
        )

        markers = [
            "CYBERAI_XSS",
            "CYBERAI_SVG",
            "CYBERAI_SCRIPT",
            "CYBERAI_DOM",
            "CYBERAI_NAV",
            "CYBERAI_MARKER",
        ]

        found = [
            marker
            for marker in markers
            if marker in body
        ]

        flags = FlagEngine.extract_from_text(
            body,
            "web_payload_http_response",
        )

        return {
            "body_length": len(body),
            "markers": found,
            "flags": flags,
            "contains_script":
                bool(
                    re.search(
                        r"<script\b",
                        body,
                        re.I,
                    )
                ),
            "contains_event":
                bool(
                    re.search(
                        r"\bon[a-z]+\s*=",
                        body,
                        re.I,
                    )
                ),
            "contains_href":
                bool(
                    re.search(
                        r"\bhref\s*=",
                        body,
                        re.I,
                    )
                ),
        }

    # =========================================================
    # EXPERIMENT
    # =========================================================

    def execute_payload(
        self,
        hypothesis,
        payload,
        route,
    ):

        result = {
            "hypothesis":
                hypothesis.get("name"),
            "confidence":
                hypothesis.get("confidence", 0),
            "payload":
                payload,
            "route":
                route,
            "status":
                "RUNNING",
        }

        # Ne tente pas les routes GET avec POST.
        if route in (
            "/report",
            "/admin/preview",
        ):

            result["status"] = "SKIPPED"
            result["reason"] = (
                "Route de déclenchement/lecture, "
                "pas une route d'injection."
            )

            return result

        # Première phase :
        # seulement les routes qui ressemblent
        # à des endpoints de création.
        if (
            ":slug" not in route
            and "/new" not in route
        ):

            result["status"] = "SKIPPED"
            result["reason"] = (
                "Route non identifiée comme "
                "endpoint d'injection."
            )

            return result

        target_route = route

        if ":slug" in target_route:

            target_route = target_route.replace(
                ":slug",
                "tech",
            )

        response = self.request(
            "POST",
            target_route,
            data={
                "title":
                    "CyberAI experiment",
                "author":
                    "CyberAI",
                "description":
                    payload["value"],
                "reference":
                    "CYBERAI",
            },
        )

        observation = self.inspect_response(
            response
        )

        result["response"] = response
        result["observation"] = observation
        result["flags"] = observation.get(
            "flags",
            [],
        )

        if result["flags"]:

            result["status"] = (
                "FLAG_CANDIDATE"
            )

        elif observation["markers"]:

            result["status"] = (
                "PAYLOAD_REFLECTED"
            )

        elif response.get(
            "http_status"
        ) in (200, 201, 302, 303):

            result["status"] = (
                "ACCEPTED_NO_REFLECTION"
            )

        else:

            result["status"] = (
                "NO_EFFECT_OBSERVED"
            )

        return result

    # =========================================================
    # RUN
    # =========================================================

    def run(self, context):

        hypotheses = [
            h for h in context.get(
                "hypotheses",
                [],
            )
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

        routes = self.get_routes(
            context
        )

        print()
        print(
            "Routes HTTP détectées :"
        )

        for route in routes:
            print(
                "  ",
                route,
            )

        fields = self.discover_input_fields()

        print()
        print(
            "Champs HTTP détectés :"
        )

        for field in fields:
            print(
                "  ",
                field,
            )

        experiments = []
        flags = []

        injection_routes = [
            route
            for route in routes
            if ":slug" in route
            or "/new" in route
        ]

        if not injection_routes:
            injection_routes = ["/"]

        for hypothesis in hypotheses:

            for payload in self.payloads_for(
                hypothesis
            ):

                for route in injection_routes:

                    result = self.execute_payload(
                        hypothesis,
                        payload,
                        route,
                    )

                    experiments.append(
                        result
                    )

                    for flag in result.get(
                        "flags",
                        [],
                    ):
                        if flag not in flags:
                            flags.append(flag)

        context[
            "web_payload_experiments"
        ] = experiments

        context.setdefault(
            "metadata",
            {},
        )

        context[
            "metadata"
        ][
            "web_payload_engine"
        ] = {
            "hypotheses":
                len(hypotheses),
            "routes":
                routes,
            "injection_routes":
                injection_routes,
            "fields":
                fields,
            "experiments":
                len(experiments),
            "flags":
                len(flags),
        }

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

        return context


def main():

    if len(sys.argv) != 2:

        print(
            "Usage: python -m agent.web_payload_engine "
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

    base_url = (
        context
        .get("metadata", {})
        .get("web_experiment", {})
        .get("server", {})
        .get("url")
    )

    if not base_url:

        base_url = (
            "http://127.0.0.1:3000/"
        )

    engine = WebPayloadEngine(
        str(challenge),
        base_url,
    )

    print()
    print("=" * 70)
    print(
        "💥 CYBERAI — WEB PAYLOAD ENGINE V2"
    )
    print("=" * 70)

    context = engine.run(
        context
    )

    experiments = context.get(
        "web_payload_experiments",
        [],
    )

    print()
    print(
        "Expériences :",
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
                "hypothesis"
            ),
        )

        print(
            "    Payload :",
            experiment.get(
                "payload",
                {},
            ).get(
                "name"
            ),
        )

        print(
            "    Route   :",
            experiment.get(
                "route"
            ),
        )

        print(
            "    Status  :",
            experiment.get(
                "status"
            ),
        )

        if experiment.get(
            "reason"
        ):

            print(
                "    Reason  :",
                experiment[
                    "reason"
                ],
            )

        if experiment.get(
            "observation",
            {},
        ).get(
            "markers"
        ):

            print(
                "    Markers :",
                experiment[
                    "observation"
                ][
                    "markers"
                ],
            )

    print()
    print("=" * 70)

    flags = context.get(
        "flags",
        [],
    )

    if flags:

        print(
            "🏁 FLAGS TROUVÉS :",
            len(flags),
        )

        for flag in flags:
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
