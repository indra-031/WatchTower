import re
URL_RE = re.compile(
    r"""
    \b
    (
        (?:http|https|ws|wss|ftp|file|data|blob|javascript|chrome|moz-extension)
        :
        [^\s"'<>]+
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

def clean_url(u):
    return u.rstrip(";,)]}>")

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "urls.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    urls = set()
    files = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for m in URL_RE.findall(data):
            urls.add(clean_url(m))

    if not urls:
        print(f"     {colors.YELLOW}no URLs found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(urls)) + "\n", encoding="utf-8")
    print(f"     Files : {files}")
    print(f"     URLs  : {len(urls)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(urls)