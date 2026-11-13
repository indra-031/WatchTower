import re
URL_PARAM_RE = re.compile(r"[?&]([a-zA-Z0-9_%\-]{2,})=")
BODY_PARAM_RE = re.compile(r"([a-zA-Z0-9_%-]{2,})\s*=")
OBJECT_RE = re.compile(r"{([^}]{1,300})}")
LOCATION_RE = re.compile(r"location\.(search|hash)")
IGNORE = {
    "var", "let", "const", "if", "for", "while",
    "true", "false", "null", "undefined", "return",
    "function", "this", "new", "typeof",
}

def clean_param(p):
    p = p.strip()
    if len(p) < 2: return None
    if p.lower() in IGNORE: return None
    if p.isdigit(): return None
    return p

def extract_from_text(text, params):
    for p in URL_PARAM_RE.findall(text):
        cp = clean_param(p)
        if cp: params.add(cp)
    for block in OBJECT_RE.findall(text):
        for p in BODY_PARAM_RE.findall(block):
            cp = clean_param(p)
            if cp: params.add(cp)
    if LOCATION_RE.search(text):
        params.add("location_search")
        params.add("location_hash")

def process_program(program):
    pn = program["program_name"]
    pd = program["path"]
    js_dir = pd / "js" / "download" / INPUT_SUBDIR
    if not js_dir.exists():
        print(f"{colors.YELLOW}⚠️ No {INPUT_SUBDIR} for {pn}{colors.RESET}\n")
        return 0
    out_dir = pd / "js" / "extraction" / OUTPUT_TOOL
    out_file = out_dir / "parameters.txt"

    print(f"{colors.BLUE}{'='*60}{colors.RESET}")
    print(f"{colors.BLUE}🎯 {pn}{colors.RESET}")
    print(f"{colors.BLUE}{'='*60}{colors.RESET}")

    params = set()
    files = 0
    for js_path in sorted(js_dir.glob("*.js")):
        files += 1
        try:
            extract_from_text(js_path.read_text(encoding="utf-8", errors="ignore"), params)
        except Exception:
            continue

    if not params:
        print(f"     {colors.YELLOW}no parameters found{colors.RESET}\n")
        return 0

    out_dir.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(params)) + "\n", encoding="utf-8")
    print(f"     Files      : {files}")
    print(f"     Parameters : {len(params)}")
    print(f"     {colors.GREEN}💾 saved → {out_file}{colors.RESET}\n")
    return len(params)