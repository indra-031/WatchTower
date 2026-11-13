import re
FRAGMENT_RE = re.compile(
    r'[a-zA-Z][a-zA-Z0-9+.-]*://[^\s"\'<>]+(#[a-zA-Z0-9/_\-\.]+)'
    r'|["\'](#[a-zA-Z0-9/_\-\.]{2,})["\']'
)

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "fragments.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    output = []
    files = 0
    total = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        found = set()
        for match in FRAGMENT_RE.findall(data):
            if isinstance(match, tuple):
                for m in match:
                    if m and len(m) > 1:
                        found.add(m)
            elif match and len(match) > 1:
                found.add(match)
        if not found:
            continue
        output.append(f"=== {js_path.name} ===")
        output.extend(sorted(found))
        output.append("")
        total += len(found)

    if not output:
        print(f"     {colors.YELLOW}no fragments found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(output), encoding="utf-8")
    print(f"     Files     : {files}")
    print(f"     Fragments : {total}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return total