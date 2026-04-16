#!/usr/bin/python3

import os
import sys

import ast
import re
from typing import TextIO


def load_description_string(m: re.Match[str]) -> str:
    val = m.group(1)
    # Unquote simple YAML scalars when quoted.
    if val.startswith(("\"", "'")):
        try:
            val = ast.literal_eval(val)
        except (ValueError, SyntaxError):
            val = val.strip("\"'")
    return val


def load_tags_from_file(f: TextIO) -> dict:
    in_tags = False
    current_group = None
    current_tag = None
    data: dict = {"tags": {}}

    for raw_line in f:
        line = raw_line.rstrip("\n")
        if not line.strip() or line.lstrip().startswith("#"):
            continue

        if re.match(r"^tags:\s*$", line):
            in_tags = True
            current_group = None
            current_tag = None
            continue

        if not in_tags:
            continue

        # 2-space indent: group
        m = re.match(r"^\s{2}([^:\s]+):\s*$", line)
        if m:
            current_group = m.group(1)
            data["tags"].setdefault(current_group, {})
            current_tag = None
            continue

        # 4-space indent: tag
        m = re.match(r"^\s{4}([^:\s]+):\s*$", line)
        if m and current_group is not None:
            current_tag = m.group(1)
            data["tags"][current_group].setdefault(current_tag, {})
            continue

        # 6-space indent: desc
        m = re.match(r"^\s{6}desc:\s*(.*)\s*$", line)
        if m and current_group is not None and current_tag is not None:
            data["tags"][current_group][current_tag]["desc"] = load_description_string(m)
    return data


def load_tags(path: str) -> dict:
    # Minimal YAML reader for this project's tags.yaml structure.
    # Supports:
    # tags:
    #   group:
    #     tag:
    #       desc: "..."
    in_tags = False
    current_group = None
    current_tag = None

    with open(path, "r", encoding="utf-8") as f:
        return load_tags_from_file(f)


def list_all_tag_descriptions(data: dict) -> None:
    tags = data.get("tags", {})
    for group in sorted(tags.keys()):
        print(f"{group} tags:")
        group_tags = tags.get(group, {}) or {}
        for tag in sorted(group_tags.keys()):
            desc = (group_tags.get(tag, {}) or {}).get("desc", "")
            print(f"\t{tag}: {desc}")


def print_tag_description(data: dict, tag: str) -> int:
    tags = data.get("tags", {})
    for g in tags:
        group_tags = tags.get(g, {}) or {}
        g_lower = {k.lower(): v for k, v in group_tags.items()}
        tag_lower = tag.lower()
        if tag_lower in g_lower:
            desc = (g_lower.get(tag_lower, {}) or {}).get("desc", "")
            print(f"{tag}: {desc}")
            return 0
    return 1


def usage() -> None:
    prog = os.path.basename(sys.argv[0])
    print(
        "\n".join(
            [
                f"Usage:",
                f"  {prog} [yaml]        # print all",
                f"  {prog} [yaml] <tag>  # searches all groups",
                f"  {prog} [-h|--help]   # print help",
            ]
        ),
        file=sys.stderr,
    )


def main() -> int:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_path = os.path.join(script_dir, "tags.yaml")

    args = sys.argv[1:]
    if args and (args[0] == "-h" or args[0] == "--help"):
        usage()

    path = default_path
    if args and args[0].endswith((".yml", ".yaml")):
        path = args[0]
        args = args[1:]

    data = load_tags(path)

    if not args or args[0] == "":
        list_all_tag_descriptions(data)
        return 0

    return print_tag_description(data, args[0])


if __name__ == "__main__":
    raise SystemExit(main())
