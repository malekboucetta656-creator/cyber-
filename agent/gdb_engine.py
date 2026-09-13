#!/usr/bin/env python3

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path


class GDBEngine:
    VERSION = "1.2"

    TARGET_ONLY = {
        "win",
        "flag",
        "shell",
        "get_flag",
        "print_flag",
    }

    INTERESTING_NAMES = {
        "main",
        "game",
        "win",
        "vuln",
        "vulnerable",
        "pwn",
        "shell",
        "flag",
        "get_flag",
        "print_flag",
    }

    def __init__(self, binary, timeout=12):
        self.binary = os.path.abspath(binary)
        self.timeout = timeout

    # ---------------------------------------------------------
    # Generic command runner
    # ---------------------------------------------------------

    def run_gdb(self, commands, timeout=None):
        if timeout is None:
            timeout = self.timeout

        cmd = [
            "gdb",
            "-q",
            "-nx",
            "--batch",
            self.binary,
        ]

        for command in commands:
            cmd.extend(["-ex", command])

        try:
            p = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )

            return {
                "returncode": p.returncode,
                "timeout": False,
                "output": p.stdout,
            }

        except subprocess.TimeoutExpired as e:
            output = e.stdout or ""

            if isinstance(output, bytes):
                output = output.decode(errors="replace")

            return {
                "returncode": -1,
                "timeout": True,
                "output": output + "\n[GDB TIMEOUT]",
            }

        except Exception as e:
            return {
                "returncode": -1,
                "timeout": False,
                "output": f"[GDB ERROR] {e}",
            }

    # ---------------------------------------------------------
    # Architecture
    # ---------------------------------------------------------

    def architecture(self):
        result = self.run_gdb([
            "show architecture",
            "show endian",
        ])

        return {
            "raw": result["output"],
            "timeout": result["timeout"],
        }

    # ---------------------------------------------------------
    # Function discovery
    # ---------------------------------------------------------

    def discover_functions(self):
        result = self.run_gdb([
            "info functions",
        ])

        functions = []

        pattern = re.compile(
            r"^\s*(0x[0-9a-fA-F]+)\s+(.+)$"
        )

        for line in result["output"].splitlines():

            line = line.strip()

            if not line:
                continue

            m = pattern.match(line)

            if not m:
                continue

            address = m.group(1)
            name = m.group(2).strip()

            # Remove argument list
            clean_name = name.split("(")[0].strip()

            functions.append({
                "name": clean_name,
                "address": address,
                "source": "gdb",
            })

        # DWARF/debug-symbol fallback
        for name in sorted(self.INTERESTING_NAMES):

            check = self.run_gdb([
                f"info address {name}",
            ])

            output = check["output"]

            if "No symbol" in output:
                continue

            if name not in {
                f["name"] for f in functions
            }:

                address = None

                m = re.search(
                    r"(0x[0-9a-fA-F]+)",
                    output
                )

                if m:
                    address = m.group(1)

                functions.append({
                    "name": name,
                    "address": address,
                    "source": "gdb-symbol",
                })

        # Remove duplicates
        unique = {}

        for f in functions:
            key = (
                f.get("name"),
                f.get("address"),
            )

            unique[key] = f

        return list(unique.values())

    # ---------------------------------------------------------
    # Interesting functions
    # ---------------------------------------------------------

    def interesting_functions(self, functions):
        result = []

        for f in functions:

            name = f.get("name", "")

            lower = name.lower()

            if (
                name in self.INTERESTING_NAMES
                or lower in self.INTERESTING_NAMES
                or any(
                    keyword in lower
                    for keyword in [
                        "win",
                        "flag",
                        "vuln",
                        "game",
                        "pwn",
                        "shell",
                    ]
                )
            ):
                result.append(name)

        return sorted(set(result))

    # ---------------------------------------------------------
    # Parse locals
    # ---------------------------------------------------------

    def parse_locals(self, output):
        locals_found = {}

        for line in output.splitlines():

            line = line.strip()

            if not line.startswith(
                ("balance", "wager", "addr", "value",
                 "name", "name_length", "input",
                 "buf", "buffer", "size", "len")
            ):
                continue

            if "=" not in line:
                continue

            name, value = line.split("=", 1)

            name = name.strip()
            value = value.strip()

            if name and value:
                locals_found[name] = value

        return locals_found

    # ---------------------------------------------------------
    # Parse registers
    # ---------------------------------------------------------

    def parse_registers(self, output):
        registers = {}

        for line in output.splitlines():

            line = line.strip()

            m = re.match(
                r"^(x\d+|sp|pc|fp|lr|cpsr|fpsr|fpcr)\s+(.+)$",
                line,
                re.IGNORECASE,
            )

            if not m:
                continue

            registers[m.group(1)] = m.group(2).strip()

        return registers

    # ---------------------------------------------------------
    # Parse backtrace
    # ---------------------------------------------------------

    def parse_backtrace(self, output):
        frames = []

        for line in output.splitlines():

            line = line.strip()

            if not line.startswith("#"):
                continue

            frames.append(line)

        return frames

    # ---------------------------------------------------------
    # Variable addresses
    # ---------------------------------------------------------

    def inspect_variable_addresses(self, function_name, input_file):
        commands = [
            f"break {function_name}",
            f"run < {input_file}",
        ]

        result = self.run_gdb(commands)

        output = result["output"]

        variables = {}

        locals_found = self.parse_locals(output)

        # Known variables first
        candidates = set(locals_found.keys())

        candidates.update({
            "balance",
            "wager",
            "addr",
            "value",
            "name",
            "name_length",
            "buf",
            "buffer",
            "input",
        })

        for variable in sorted(candidates):

            probe = self.run_gdb([
                f"break {function_name}",
                f"run < {input_file}",
                f"p/x &{variable}",
            ])

            probe_output = probe["output"]

            matches = re.findall(
                r"\$\d+\s*=\s*(0x[0-9a-fA-F]+)",
                probe_output,
            )

            if matches:
                variables[variable] = matches[-1]

        return variables

    # ---------------------------------------------------------
    # Main function inspector
    # ---------------------------------------------------------

    def inspect_function(self, function_name):

        # -----------------------------------------------------
        # NEVER execute direct flag/win targets
        # -----------------------------------------------------

        if function_name.lower() in self.TARGET_ONLY:

            return {
                "function": function_name,
                "mode": "TARGET_ONLY",
                "status": "NOT_EXECUTED",
                "reason": (
                    "Target function detected; "
                    "direct execution disabled."
                ),
            }

        # -----------------------------------------------------
        # Controlled stdin
        # -----------------------------------------------------

        input_file = "/tmp/cyberai_gdb_input"

        try:
            with open(input_file, "w") as f:

                # Name length
                f.write("1\n")

                # Controlled address input
                f.write("0\n")

                # Controlled value
                f.write("0\n")

                # Controlled wager
                f.write("0\n")

                # Name
                f.write("A\n")

        except Exception as e:

            return {
                "function": function_name,
                "status": "ERROR",
                "error": str(e),
            }

        # -----------------------------------------------------
        # One controlled GDB execution
        # -----------------------------------------------------

        commands = [
            f"break {function_name}",
            f"run < {input_file}",
            "set pagination off",
            "info args",
            "info locals",
            "info frame",
            "info registers",
            "bt",
        ]

        result = self.run_gdb(commands)

        output = result["output"]

        # -----------------------------------------------------
        # Parse everything
        # -----------------------------------------------------

        locals_found = self.parse_locals(output)

        registers = self.parse_registers(output)

        backtrace = self.parse_backtrace(output)

        # -----------------------------------------------------
        # Variable addresses
        # -----------------------------------------------------

        variable_addresses = {}

        important_variables = [
            "balance",
            "wager",
            "addr",
            "value",
            "name",
            "name_length",
            "buf",
            "buffer",
            "input",
        ]

        for variable in important_variables:

            probe = self.run_gdb([
                f"break {function_name}",
                f"run < {input_file}",
                f"p/x &{variable}",
            ])

            probe_output = probe["output"]

            matches = re.findall(
                r"\$\d+\s*=\s*(0x[0-9a-fA-F]+)",
                probe_output,
            )

            if matches:
                variable_addresses[variable] = matches[-1]

        # -----------------------------------------------------
        # Frame-relative DWARF information
        # -----------------------------------------------------

        frame_info = []

        for line in output.splitlines():

            if "DW_OP_fbreg" in line:
                frame_info.append(line.strip())

        # -----------------------------------------------------
        # Current instruction
        # -----------------------------------------------------

        current_pc = None

        m = re.search(
            r"\bpc\s+(0x[0-9a-fA-F]+)",
            output,
            re.IGNORECASE,
        )

        if m:
            current_pc = m.group(1)

        # -----------------------------------------------------
        # Status
        # -----------------------------------------------------

        if result["timeout"]:
            status = "TIMEOUT"
        elif "[GDB ERROR]" in output:
            status = "ERROR"
        else:
            status = "ANALYZED"

        # -----------------------------------------------------
        # Result
        # -----------------------------------------------------

        return {
            "function": function_name,
            "mode": "CONTROLLED_RUN",
            "status": status,
            "locals": locals_found,
            "variable_addresses": variable_addresses,
            "registers": registers,
            "backtrace": backtrace,
            "frame_info": frame_info,
            "pc": current_pc,
            "raw": output,
        }

    # ---------------------------------------------------------
    # Static source line information
    # ---------------------------------------------------------

    def source_location(self, function_name):

        result = self.run_gdb([
            f"info line {function_name}",
        ])

        return result["output"]

    # ---------------------------------------------------------
    # Full analysis
    # ---------------------------------------------------------

    def analyze(self):

        result = {
            "engine": "GDBEngine",
            "version": self.VERSION,
            "status": "STARTING",
            "binary": self.binary,
            "architecture": {},
            "functions": [],
            "interesting_functions": [],
            "observations": [],
        }

        if not os.path.exists(self.binary):

            result["status"] = "ERROR"
            result["error"] = (
                f"Binary not found: {self.binary}"
            )

            return result

        # Architecture
        result["architecture"] = self.architecture()

        # Functions
        functions = self.discover_functions()

        result["functions"] = functions

        interesting = self.interesting_functions(functions)

        result["interesting_functions"] = interesting

        # -----------------------------------------------------
        # Analyze interesting functions
        # -----------------------------------------------------

        for function_name in interesting:

            try:

                observation = self.inspect_function(
                    function_name
                )

                result["observations"].append(
                    observation
                )

            except Exception as e:

                result["observations"].append({
                    "function": function_name,
                    "status": "ERROR",
                    "error": str(e),
                })

        result["status"] = "ANALYZED"

        return result


# =============================================================
# CLI
# =============================================================

def main():

    if len(sys.argv) < 2:

        print(
            "Usage: python3 -m agent.gdb_engine <binary>"
        )

        sys.exit(1)

    binary = sys.argv[1]

    engine = GDBEngine(binary)

    result = engine.analyze()

    print(
        json.dumps(
            result,
            indent=2,
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    main()
