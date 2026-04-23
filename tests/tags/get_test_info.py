import re, sys


def main():
    mode = sys.argv[1]
    want = [t.lower() for t in re.split(r"[,\s]+", sys.argv[2].strip()) if t]
    files = sys.argv[3:]
    for path in files:
        print_file_test_info_matching(path, mode, want)


def print_file_test_info_matching(path: str, mode: str, want: list[str]):
    try:
        lines = open(path, "r", encoding="utf-8", errors="replace").read().splitlines()
    except OSError as e:
        print(str(e))
        return

    pending_tags = None
    for i, line in enumerate(lines, 1):
        # pending_tags = add_test_info(line, pending_tags)
        m = re.match(r"^\s*#\s*tags?\s*:\s*(.+)\s*$", line, flags=re.I)
        if m:
            pending_tags = norm_tags(line)
            continue

        m = re.match(r'^\s*@test\s+"([^"]+)"', line)
        if m:
            test_name = m.group(1)
            tags = pending_tags or []
            pending_tags = None

            print_test_if_match(path, i, test_name, tags, want, mode)


def norm_tags(s: str):
    s = s.strip()
    s = re.sub(r"^\s*#\s*tags?\s*:\s*", "", s, flags=re.I)
    parts = [p for p in re.split(r"[,\s]+", s) if p]
    return parts


def print_test_if_match(file: str, line_num: int, name: str, tags, want: list[str], mode: str):
    if not want:
        ok = True
    else:
        lowercase_tagset = [t.lower() for t in set(tags)]
        if mode == "any":
            ok = any(t in lowercase_tagset for t in want)
        else:
            ok = all(t in lowercase_tagset for t in want)
    if ok:
        print(f"{file}:{line_num}\t[{','.join(tags)}]\t{name}")


if __name__ == "__main__":
    raise SystemExit(main())