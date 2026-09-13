import subprocess
import tempfile
import os


HTML = r"""
<!doctype html>
<html>
<body>

<div id="latest-posts"></div>

<!-- tests DOM clobbering contrôlés -->
<form id="whatsNew">
</form>

<a id="next" href="/admin/preview">NEXT</a>

<script>
console.log("=== DOM TEST ===");

console.log("TYPE window.whatsNew:", typeof window.whatsNew);
console.log("TYPE window.next:", typeof window.next);
console.log("TYPE window.whatsNew?.next:",
    typeof window.whatsNew?.next);

console.log("GLOBAL whatsNew:", window.whatsNew);
console.log("GLOBAL next:", window.next);

if (window.whatsNew) {
    console.log(
        "whatsNew.id:",
        window.whatsNew.id
    );

    console.log(
        "whatsNew.href:",
        window.whatsNew.href
    );

    console.log(
        "whatsNew.getAttribute:",
        typeof window.whatsNew.getAttribute
    );
}

if (window.next) {
    console.log(
        "next.href:",
        window.next.href
    );

    console.log(
        "next.getAttribute:",
        typeof window.next.getAttribute
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

        cmd = [
            "chromium",
            "--headless",
            "--no-sandbox",
            "--disable-gpu",
            "--enable-logging=stderr",
            "--dump-dom",
            "file://" + path,
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=10,
        )

        output = result.stdout + "\n" + result.stderr

        print("=" * 70)
        print("🧠 CYBERAI V103 — BROWSER DOM PROPERTY TEST")
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
