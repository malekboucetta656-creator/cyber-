import subprocess
import tempfile
import os

HTML = r"""
<!doctype html>
<html>
<body>

<form id="whatsNew">
    <a id="next" name="next" href="/admin/preview">NEXT</a>
</form>

<script>
console.log("=== DOM CLOBBERING V105 ===");

console.log("whatsNew:", window.whatsNew);
console.log("whatsNew type:",
    Object.prototype.toString.call(window.whatsNew));

console.log("whatsNew.next:",
    window.whatsNew && window.whatsNew.next);

console.log("whatsNew.next type:",
    window.whatsNew &&
    Object.prototype.toString.call(window.whatsNew.next));

if (window.whatsNew && window.whatsNew.next) {
    console.log(
        "href:",
        window.whatsNew.next.getAttribute("href")
    );

    console.log(
        "property href:",
        window.whatsNew.next.href
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
        print("🧠 CYBERAI V105 — NESTED DOM CLOBBERING")
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

