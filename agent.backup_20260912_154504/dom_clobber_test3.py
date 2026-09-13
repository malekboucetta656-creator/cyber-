import subprocess
import tempfile
import os

HTML = r"""
<!doctype html>
<html>
<body>

<form id="whatsNew">
    <input name="next" value="ONE">
    <input name="next" value="TWO">
</form>

<script>
console.log("=== DOM CLOBBERING V106 ===");

const w = window.whatsNew;

console.log("whatsNew:", w);
console.log("whatsNew type:", Object.prototype.toString.call(w));

console.log("next:", w && w.next);
console.log("next type:",
    w && Object.prototype.toString.call(w.next));

console.log("namedItem:",
    w && typeof w.namedItem === "function"
        ? w.namedItem("next")
        : "NO namedItem");

console.log("elements length:",
    w && w.elements ? w.elements.length : "NO elements");

if (w && w.elements) {
    console.log("elements[0]:", w.elements[0]);
    console.log("elements[1]:", w.elements[1]);
}
</script>

</body>
</html>
"""


def main():
    fd, path = tempfile.mkstemp(suffix=".html")

    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(HTML)

        result = subprocess.run(
            [
                "chromium",
                "--headless",
                "--no-sandbox",
                "--disable-gpu",
                "--enable-logging=stderr",
                "--dump-dom",
                "file://" + path,
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        output = result.stdout + "\n" + result.stderr

        print("=" * 70)
        print("🧠 CYBERAI V106 — NAMED PROPERTY ANALYSIS")
        print("=" * 70)

        for line in output.splitlines():
            if "CONSOLE:" in line:
                print(line)

        print("=" * 70)

    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


if __name__ == "__main__":
    main()
