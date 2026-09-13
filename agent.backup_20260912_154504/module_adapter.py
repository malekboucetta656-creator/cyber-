#!/usr/bin/env python3

import importlib
import inspect
import traceback

ENTRYPOINTS = [
    "run",
    "analyze",
    "analyse",
    "scan",
    "detect",
    "execute",
]


def load(module_name):
    try:
        return importlib.import_module(module_name), None
    except Exception as exc:
        return None, f"IMPORT ERROR: {exc}"


def find_entrypoint(module):
    for name in ENTRYPOINTS:
        function = getattr(module, name, None)
        if callable(function):
            return name, function
    return None, None


def _required_parameters(function):
    try:
        signature = inspect.signature(function)
    except (TypeError, ValueError):
        return []

    required = []

    for parameter in signature.parameters.values():
        if (
            parameter.default is inspect.Parameter.empty
            and parameter.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD,
            )
        ):
            required.append(parameter)

    return required


def call(function, challenge):
    try:
        required = _required_parameters(function)

        if len(required) == 0:
            return {
                "ok": True,
                "result": function(),
            }

        if len(required) == 1:
            return {
                "ok": True,
                "result": function(challenge),
            }

        return {
            "ok": False,
            "error": (
                "UNSUPPORTED SIGNATURE: "
                f"{function.__module__}.{function.__name__}"
            ),
        }

    except Exception as exc:
        return {
            "ok": False,
            "error": str(exc),
            "traceback": traceback.format_exc(),
        }


def execute(module_name, challenge):
    module, error = load(module_name)

    if module is None:
        return {
            "status": "ERROR",
            "module": module_name,
            "error": error,
        }

    entrypoint_name, function = find_entrypoint(module)

    if function is None:
        return {
            "status": "NO_ENTRYPOINT",
            "module": module_name,
        }

    result = call(function, challenge)

    if not result["ok"]:
        return {
            "status": "ERROR",
            "module": module_name,
            "entrypoint": entrypoint_name,
            "error": result["error"],
            "traceback": result.get("traceback"),
        }

    return {
        "status": "EXECUTED",
        "module": module_name,
        "entrypoint": entrypoint_name,
        "result": result["result"],
    }


def execute_many(modules, challenge):
    return [
        execute(module_name, challenge)
        for module_name in modules
    ]


def summarize(results):
    summary = {
        "total": len(results),
        "executed": 0,
        "errors": 0,
        "no_entrypoint": 0,
    }

    for result in results:
        status = result.get("status")

        if status == "EXECUTED":
            summary["executed"] += 1
        elif status == "ERROR":
            summary["errors"] += 1
        elif status == "NO_ENTRYPOINT":
            summary["no_entrypoint"] += 1

    return summary
