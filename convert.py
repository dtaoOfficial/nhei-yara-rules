#!/usr/bin/env python3
"""
Auto-fetches YARA rules from reversinglabs/reversinglabs-yara-rules,
converts text-string patterns to DTAO NAS JSON format,
writes yara-rules.json.
"""
import os, re, json, time, sys
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
    "stealer": "CRITICAL",    "webshell": "CRITICAL", "rootkit": "CRITICAL",
    "miner": "HIGH",          "trojan": "HIGH",       "dropper": "HIGH",
    "exploit": "HIGH",        "worm": "HIGH",         "downloader": "MEDIUM",
}

MAX_FILES = 80
MAX_RULES = 150

def gh_request(url, is_raw=False):
    req = urllib.request.Request(url)
    if GITHUB_TOKEN:
        req.add_header("Authorization", f"Bearer {GITHUB_TOKEN}")
    if not is_raw:
        req.add_header("Accept", "application/vnd.github+json")
    req.add_header("User-Agent", "DTAO-YARA-Converter/1.0")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        print(f"HTTP {e.code} → {url}", file=sys.stderr)
        return None
    except Exception as e:
        print(f"Error: {e} → {url}", file=sys.stderr)
        return None

def get_default_branch():
    print("Detecting default branch...")
    data = gh_request(f"https://api.github.com/repos/{RLABS_REPO}")
    if data:
        branch = json.loads(data).get("default_branch", "master")
        print(f"Default branch: {branch}")
        return branch
    print("Could not detect branch, falling back to master")
    return "master"

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
    for m in re.finditer(r'rule\s+(\w+)(?:\s*:\s*[\w\s]+)?\s*\{(.*?)\n\}', content, re.DOTALL):
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
    now = datetime.now(timezone.utc)
    version     = now.strftime("%Y-%m")
    released_at = now.strftime("%Y-%m-01")

    branch   = get_default_branch()
    tree_api = f"https://api.github.com/repos/{RLABS_REPO}/git/trees/{branch}?recursive=1"
    raw_base = f"https://raw.githubusercontent.com/{RLABS_REPO}/{branch}/"

    print(f"Fetching file tree from {RLABS_REPO} ({branch})...")
    tree_raw = gh_request(tree_api)
    if not tree_raw:
        print("Failed to fetch tree", file=sys.stderr)
        sys.exit(1)

    tree = json.loads(tree_raw)
    all_files = [i["path"] for i in tree.get("tree", []) if i["type"] == "blob"]

    yara_files = []
    for path in all_files:
        if not path.endswith(".yara"):
            continue
        parts = path.lower().split("/")
        if any(cat in part for cat in PRIORITY_CATS for part in parts):
            yara_files.append(path)

    def priority(p):
        pl = p.lower()
        if "ransomware" in pl: return 0
        if "backdoor" in pl or "rat" in pl: return 1
        if "stealer" in pl or "webshell" in pl: return 2
        if "miner" in pl or "exploit" in pl: return 3
        return 4

    yara_files.sort(key=priority)
    yara_files = yara_files[:MAX_FILES]
    print(f"Found {len(yara_files)} .yara files — converting...")

    all_rules, seen_ids = [], set()

    for i, path in enumerate(yara_files):
        content = gh_request(raw_base + path, is_raw=True)
        if not content:
            continue
        for rule in parse_yara(content, path):
            if rule["id"] not in seen_ids:
                seen_ids.add(rule["id"])
                all_rules.append(rule)
        if i % 10 == 9:
            time.sleep(1)
        if len(all_rules) >= MAX_RULES:
            break
        print(f"  [{i+1}/{len(yara_files)}] {path}", end="\r")

    print(f"\nDone — {len(all_rules)} rules converted")

    output = {
        "version":    version,
        "releasedAt": released_at,
        "source":     f"https://github.com/{RLABS_REPO}",
        "rules":      all_rules,
    }
    with open("yara-rules.json", "w", encoding="utf-8") as f:
        json.dump(output, f, indent=2, ensure_ascii=False)
    print(f"yara-rules.json written — version {version}, {len(all_rules)} rules")

if __name__ == "__main__":
    main()
