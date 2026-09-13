import subprocess
import tempfile
import os

HTML = r"""
<!doctype html>
<html>
<body>

<a id="whatsNew" name="next" href="/admin/preview">TEST</a>

<script>
console.log("=== DOM CLOBBERING V104 ===");

console.log("typeof window.whatsNew:", typeof window.whatsNew);
console.log("window.whatsNew:", window.whatsNew);

console.log("window.whatsNew.next:",
    window.whatsNew && window.whatsNew.next);

console.log("typeof window.whatsNew.next:",
    window.whatsNew && typeof window.whatsNew.next);

if (window.whatsNew && window.whatsNew.next) {
    console.log(
        "NEXT TYPE:",
        Object.prototype.toString.call(window.whatsNew.next)
    );

    console.log(
        "NEXT HREF:",
        window.whatsNew.next.getAttribute("href")
    );

    console.log(
        "NEXT href PROPERTY:",
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
        print("🧠 CYBERAI V104 — DOM CLOBBERING TEST")
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
