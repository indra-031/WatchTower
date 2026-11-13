import re
EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")
JUNK = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".map")

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "emails.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    emails = set()
    files = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            data = js_path.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        for em in EMAIL_RE.findall(data):
            if not em.lower().endswith(JUNK):
                emails.add(em)

    if not emails:
        print(f"     {colors.YELLOW}no emails found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(emails)) + "\n", encoding="utf-8")
    print(f"     Files  : {files}")
    print(f"     Emails : {len(emails)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(emails)