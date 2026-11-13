import re
ENDPOINT_RE = re.compile(
    r'["\'`](/(?:[a-zA-Z0-9_\-/{}/\.]+)(?:\?[a-zA-Z0-9_\-&=%{}\.]+)?)["\'`]'
)
IGNORE_EXT = (
    ".js", ".css", ".png", ".jpg", ".jpeg", ".svg",
    ".gif", ".ico", ".woff", ".woff2", ".map",
)

def looks_real(ep):
    if not ep.startswith("/"): return False
    if ep in ("/", "//"): return False
    if ep.lower().endswith(IGNORE_EXT): return False
    if ep.count("/") < 2: return False
    return True

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "endpoints.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    results = set()
    files = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for ep in ENDPOINT_RE.findall(data):
            if looks_real(ep):
                results.add(ep.split("?", 1)[0])

    if not results:
        print(f"     {colors.YELLOW}no endpoints found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(results)) + "\n", encoding="utf-8")
    print(f"     Files     : {files}")
    print(f"     Endpoints : {len(results)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(results)