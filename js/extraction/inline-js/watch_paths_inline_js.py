import re
PATH_RE = re.compile(
    r"""
    (?<![\w$])
    (
        /[a-zA-Z0-9][a-zA-Z0-9\-._~/%?=&+#:@]*
    )
    """,
    re.VERBOSE,
)

def looks_like_real_path(p):
    return ("/" in p[1:] or "." in p or "?" in p or "=" in p or any(c.isdigit() for c in p))

def is_valid_path(p):
    if not p.startswith("/"): return False
    if p.startswith(("/^", "/(", "/[", "//")): return False
    if not looks_like_real_path(p): return False
    if p.startswith("/www."): return False
    if re.match(r"^/[^/]+\.com(/|$)", p): return False
    if len(p) < 3: return False
    return True

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "paths.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    paths = set()
    files = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for p in PATH_RE.findall(data):
            if is_valid_path(p):
                paths.add(p)

    if not paths:
        print(f"     {colors.YELLOW}no paths found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(paths)) + "\n", encoding="utf-8")
    print(f"     Files : {files}")
    print(f"     Paths : {len(paths)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(paths)