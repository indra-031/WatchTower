import re, json
LIB_PATTERNS = [
    r"(jquery)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(react)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(vue)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(angular)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(axios)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(lodash)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(moment)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
    r"(bootstrap)[^\n]{0,80}?(\d+\.\d+(?:\.\d+)?)",
]
LIB_REGEX = [re.compile(p, re.IGNORECASE) for p in LIB_PATTERNS]

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "libraries.json"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    seen = set()
    results = []
    files = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for rgx in LIB_REGEX:
            for m in rgx.finditer(data):
                lib = m.group(1).lower()
                ver = m.group(2)
                key = (lib, ver, js_path.name)
                if key in seen:
                    continue
                seen.add(key)
                results.append({"library": lib, "version": ver, "file": js_path.name})

    if not results:
        print(f"     {colors.YELLOW}no libraries found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"     Files : {files}")
    print(f"     Hits  : {len(results)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(results)