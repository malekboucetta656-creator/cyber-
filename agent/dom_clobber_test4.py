import subprocess
import tempfile
import os

HTML = r"""
<!doctype html>
<html>
<body>

<form id="whatsNew">

    <a name="next" href="/admin/preview">LINK</a>

</form>

<script>
console.log("=== DOM CLOBBERING V107 ===");

const w = window.whatsNew;

console.log("whatsNew:",
    Object.prototype.toString.call(w));

console.log("next:",
    w && w.next);

console.log("next type:",
    w && Object.prototype.toString.call(w.next));

console.log("next getAttribute:",
    w && w.next && typeof w.next.getAttribute);

console.log("next href:",
    w && w.next && w.next.href);

if (w && w.next && typeof w.next.getAttribute === "function") {
    console.log(
        "href attribute:",
        w.next.getAttribute("href")
    );
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
        print("🧠 CYBERAI V107 — SINGLE NAMED ELEMENT")
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
