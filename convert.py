#!/usr/bin/env python3
"""
Downloads reversinglabs/reversinglabs-yara-rules as a zip,
extracts .yara files, converts string patterns to DTAO NAS JSON.
One download — no branch detection, no tree API calls.
"""
import os, re, json, sys, zipfile, io
from datetime import datetime, timezone
import urllib.request, urllib.error

GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
RLABS_REPO   = "reversinglabs/reversinglabs-yara-rules"

PRIORITY_CATS = {
    "ransomware", "backdoor", "rat", "stealer",
    "miner", "trojan", "dropper", "webshell", "exploit"
}

SEVERITY_MAP = {
    "ransomware": "CRITICAL", "backdoor": "CRITICAL", "rat": "CRITICAL",
    "stealer":    "CRITICAL", "webshell": "CRITICAL", "rootkit": "CRITICAL",
    "miner":      "HIGH",     "trojan":   "HIGH",     "dropper": "HIGH",
    "exploit":    "HIGH",     "worm":     "HIGH",     "downloader": "MEDIUM",
}

MAX_FILES = 80
MAX_RULES = 150


def download_zipball():
    for branch in ["master", "main"]:
        url = f"https://api.github.com/repos/{RLABS_REPO}/zipball/{branch}"
        req = urllib.request.Request(url)
        if GITHUB_TOKEN:
            req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("User-Agent", "DTAO-YARA-Converter/1.0")
        print(f"Trying branch: {branch} ...")
        try:
            with urllib.request.urlopen(req, timeout=120) as r:
                data = r.read()
            print(f"Downloaded {len(data) // 1024} KB from branch '{branch}'")
            return data
        except Exception as e:
            print(f"  branch '{branch}' failed: {e}", file=sys.stderr)
    return None


def get_severity(path, rule_name):
    text = (path + " " + rule_name).lower()
    for kw, sev in SEVERITY_MAP.items():
        if kw in text:
            return sev
    return "HIGH"


def parse_strings(section):
    seen, out = set(), []
    for m in re.finditer(r'\$\w*\s*=\s*"([^"]{5,})"', section):
        s = m.group(1).strip().lower()
        if s not in seen:
            seen.add(s)
            out.append(s)
        if len(out) == 6:
            break
    return out


def parse_yara(content, filepath):
    rules = []
    for m in re.finditer(
        r'rule\s+(\w+)(?:\s*:\s*[\w\s]+)?\s*\{(.*?)\n\}', content, re.DOTALL
    ):
        name = m.group(1)
        body = m.group(2)

        desc = name.replace("_", " ")
        mm = re.search(r'meta\s*:(.*?)(?=strings\s*:|condition\s*:|$)', body, re.DOTALL)
        if mm:
            dm = re.search(r'description\s*=\s*"([^"]+)"', mm.group(1))
            if dm:
                desc = dm.group(1)

        sm = re.search(r'strings\s*:(.*?)(?=condition\s*:|$)', body, re.DOTALL)
        strings = parse_strings(sm.group(1)) if sm else []
        if not strings:
            continue

        condition = "any"
        cm = re.search(r'condition\s*:(.*?)$', body, re.DOTALL)
        if cm and re.search(r'\ball\s+of\b', cm.group(1).lower()):
            condition = "all"

        rules.append({
            "id":            name.upper(),
            "name":          name.replace("_", " "),
            "severity":      get_severity(filepath, name),
            "description":   desc[:200],
            "patternType":   "STRING",
            "strings":       strings,
            "condition":     condition,
            "binaryOnly":    False,
            "nonBinaryOnly": False,
        })
    return rules


def main():
    now         = datetime.now(timezone.utc)
    version     = now.strftime("%Y-%m")
    released_at = now.strftime("%Y-%m-01")

    data = download_zipball()
    if not data:
        print("ERROR: Could not download repo zip from any branch", file=sys.stderr)
        sys.exit(1)

    all_rules, seen_ids = [], set()

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        yara_paths = [n for n in zf.namelist() if n.endswith(".yara")]

        filtered = []
        for path in yara_paths:
            parts = path.lower().split("/")
            if any(cat in part for cat in PRIORITY_CATS for part in parts):
                filtered.append(path)

        def priority(p):
            pl = p.lower()
            if "ransomware" in pl: return 0
            if "backdoor"   in pl or "rat" in pl: return 1
            if "stealer"    in pl or "webshell" in pl: return 2
            if "miner"      in pl or "exploit"  in pl: return 3
            return 4

        filtered.sort(key=priority)
        cap = min(len(filtered), MAX_FILES)
        print(f"Found {len(filtered)} relevant .yara files — processing {cap}")

        for i, path in enumerate(filtered[:cap]):
            try:
                content = zf.read(path).decode("utf-8", errors="replace")
            except Exception as e:
                print(f"  Skip {path}: {e}", file=sys.stderr)
                continue

            for rule in parse_yara(content, path):
                if rule["id"] not in seen_ids:
                    seen_ids.add(rule["id"])
                    all_rules.append(rule)

            print(f"  [{i+1}/{cap}] {path.split('/')[-1]}", end="\r")

            if len(all_rules) >= MAX_RULES:
                break

    print(f"\nTotal rules converted: {len(all_rules)}")

    output = {
        "version":    version,
        "releasedAt": released_at,
        "source":     f"https://github.com/{RLABS_REPO}",
        "rules":      all_rules,
    }
    with open("yara-rules.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)

    print(f"Done — yara-rules.json written (version {version}, {len(all_rules)} rules)")


if __name__ == "__main__":
    main()
