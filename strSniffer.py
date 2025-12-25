import re
from pathlib import Path
from rich.console import Console
from rich.table import Table

# =========================
# Keyword database
# =========================
KEYWORDS = {
    "License": [
        "license",
        "serial",
        "key",
        "activation",
        "activate",
        "trial",
        "expired",
    ],
    "Auth": ["login", "password", "username", "auth", "denied", "granted", "invalid"],
    "Anti-Debug": ["debug", "dbg", "olly", "x64dbg", "ida", "gdb", "windbg"],
    "Anti-VM": ["vmware", "virtualbox", "vbox", "qemu", "hyper-v"],
    "Crypto": ["encrypt", "decrypt", "aes", "rsa", "sha", "md5"],
    "Network": ["http", "https", "socket", "connect", "send", "recv"],
    "Filesystem": ["file", "path", "registry", "regedit", "hkey"],
    "Errors": ["error", "failed", "exception", "crash"],
    "SUS": [
        "login",
        "password",
        "username",
        "auth",
        "denied",
        "granted",
        "invalid",
        "license",
        "serial",
        "key",
        "activation",
        "activate",
        "trial",
        "expired",
        "_scanf",
        "puts",
        "_puts",
        "printf",
        "_printf",
    ],
}


def main(target):

    # =========================
    # Category priority (ORDER)
    # =========================
    CATEGORY_ORDER = {
        "SUS": 0,
        "Auth": 1,
        "Anti-Debug": 2,
        "License": 3,
        "Errors": 4,
    }

    # =========================
    # String extraction
    # =========================
    def extract_strings(path, min_len=4):
        with open(path, "rb") as f:
            data = f.read()

        results = []

        # ASCII strings
        ascii_re = rb"[ -~]{" + str(min_len).encode() + rb",}"
        for m in re.finditer(ascii_re, data):
            results.append((m.start(), m.group().decode("ascii", errors="ignore")))

        # UTF-16LE strings
        utf16_re = rb"(?:[ -~]\x00){" + str(min_len).encode() + rb",}"
        for m in re.finditer(utf16_re, data):
            try:
                s = m.group().decode("utf-16le", errors="ignore")
                results.append((m.start(), s))
            except Exception:
                pass

        return results

    # =========================
    # Keyword detection
    # =========================
    def find_keywords(strings):
        hits = []

        for offset, s in strings:
            lower = s.lower()
            for category, words in KEYWORDS.items():
                for w in words:
                    if w in lower:
                        hits.append((category, w, offset, s))
                        break

        return hits

    # =========================
    # Sorting logic
    # =========================
    def sort_hits(hits):
        return sorted(
            hits,
            key=lambda x: (
                CATEGORY_ORDER.get(x[0], 99),  # category priority
                x[2],  # offset order
            ),
        )

    # =========================
    # Rich table rendering
    # =========================
    def render_table(module_path, hits):
        console = Console()

        table = Table(
            title=f"[bold cyan]String Scan → {Path(module_path).name}",
            show_lines=True,
        )

        table.add_column("Category", style="magenta", no_wrap=True)
        table.add_column("Keyword", style="red")
        table.add_column("Offset", style="yellow")
        table.add_column("String", style="white")

        for category, keyword, offset, string in hits:
            table.add_row(category, keyword, hex(offset), string)

        console.print(table)

    # =========================
    # Interactive entry point
    # =========================
    if True:

        path = Path(target)
        if not path.exists() or not path.is_file():
            print("Invalid file path. Try again, detective.")
            exit(1)

        strings = extract_strings(path)
        hits = find_keywords(strings)
        hits = sort_hits(hits)

        if hits:
            render_table(path, hits)
        else:
            print(
                "No interesting keywords found. Binary is either clean or hiding well."
            )
