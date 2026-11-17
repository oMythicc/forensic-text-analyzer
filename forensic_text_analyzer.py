#!/usr/bin/env python3
"""
Forensic Text Analyzer
----------------------
Triage a folder of text evidence (chat logs, exported emails, server logs,
notes, CSV/JSON exports) and pull out what an investigator needs first:

  * Indicators of compromise (IOCs): IPs, URLs, domains, emails, file hashes,
    crypto wallet addresses, CVE IDs, with defanged forms (hxxp, [.]) handled
  * Watchlist keyword hits, each shown in context with file and line number
  * Word and phrase frequencies (stopwords removed) to see what the evidence is about
  * A SHA-256 hash of every evidence file for chain of custody

Pure Python standard library: no installs, so it runs on locked-down machines.

Inspired by an NLTK text-analysis exercise from a Python course at the
University of Arizona (2024); this tool is an original rewrite.
"""

import argparse
import csv
import email
import email.policy
import hashlib
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone

TEXT_EXTS = {".txt", ".log", ".csv", ".tsv", ".json", ".xml", ".html", ".htm", ".md",
             ".eml", ".ini", ".cfg", ".conf", ".yaml", ".yml", ".sql", ".ps1", ".bat",
             ".sh", ".py", ".js", ".rtf", ".msg", ".evtx.txt"}

DEFAULT_KEYWORDS = [
    # credentials & access
    "password", "passwd", "credentials", "login", "username", "admin", "root", "token", "api key",
    "mfa", "2fa", "otp",
    # money
    "wire transfer", "bitcoin", "btc", "crypto", "wallet", "gift card", "invoice", "payment", "bank",
    # evasion / destruction
    "delete", "wipe", "shred", "clear logs", "encrypt", "vpn", "tor", "proxy", "burner",
    # exfil & tooling
    "exfil", "upload", "dropbox", "mega", "pastebin", "usb", "payload", "malware", "ransom",
    "mimikatz", "powershell", "backdoor", "keylogger",
    # social engineering
    "urgent", "confidential", "do not tell", "don't tell", "dont tell",
]

STOPWORDS = set("""
a about above after again against all am an and any are aren't as at be because been before being
below between both but by can can't cannot could couldn't did didn't do does doesn't doing don't down
during each few for from further get got had hadn't has hasn't have haven't having he he'd he'll he's
her here here's hers herself him himself his how how's i i'd i'll i'm i've if in into is isn't it it's
its itself just let's like me more most mustn't my myself no nor not now of off on once only or other
ought our ours ourselves out over own same shan't she she'd she'll she's should shouldn't so some such
than that that's the their theirs them themselves then there there's these they they'd they'll they're
they've this those through to too under until up us very was wasn't we we'd we'll we're we've were
weren't what what's when when's where where's which while who who's whom why why's will with won't
would wouldn't you you'd you'll you're you've your yours yourself yourselves also yes ok okay yeah
http https www com
""".split())

# --- IOC patterns -----------------------------------------------------------
TLDS = ("com|net|org|edu|gov|mil|int|io|co|info|biz|xyz|top|online|site|club|app|dev|ru|cn|uk|"
        "de|fr|nl|br|in|jp|kr|ir|kp|us|ca|au|tk|ml|ga|cf|gq|pw|cc|su|ws|me|tv|onion|test|example|local")
RE_URL = re.compile(r"\b(?:https?|ftp)://[^\s<>\"'\])}]+", re.I)
RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}\b")
RE_DOMAIN = re.compile(rf"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+(?:{TLDS})\b", re.I)
RE_IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
RE_SHA256 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{64}(?![A-Fa-f0-9])")
RE_SHA1 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{40}(?![A-Fa-f0-9])")
RE_MD5 = re.compile(r"(?<![A-Fa-f0-9])[A-Fa-f0-9]{32}(?![A-Fa-f0-9])")
RE_BTC = re.compile(r"\b(?:bc1[ac-hj-np-z02-9]{25,62}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b")
RE_ETH = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
RE_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
RE_WORD = re.compile(r"[A-Za-z][A-Za-z'\-]{1,}")

# Undo common "defanging" so IOCs written as hxxp://evil[.]com are still caught
REFANG = [
    (re.compile(r"\bhxxp", re.I), "http"),
    (re.compile(r"\bfxp", re.I), "ftp"),
    (re.compile(r"\[\s*\.\s*\]|\(\s*\.\s*\)|\{\s*\.\s*\}|\[dot\]|\(dot\)", re.I), "."),
    (re.compile(r"\[\s*@\s*\]|\(\s*@\s*\)|\[at\]|\(at\)", re.I), "@"),
    (re.compile(r"\[:\]"), ":"),
    (re.compile(r"\[://\]"), "://"),
]


def refang(text):
    for pat, repl in REFANG:
        text = pat.sub(repl, text)
    return text


def defang(ioc):
    return ioc.replace("http", "hxxp", 1).replace(".", "[.]")


PRIVATE_NETS = [ipaddress.ip_network(n) for n in
                ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]
DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]


def classify_ip(ip):
    """public / private / documentation / loopback / reserved, or None if not a valid IP."""
    try:
        obj = ipaddress.ip_address(ip)
    except ValueError:
        return None
    if obj.is_loopback:
        return "loopback"
    if any(obj in n for n in PRIVATE_NETS):
        return "private"
    if any(obj in n for n in DOC_NETS):
        return "documentation"  # RFC 5737 example ranges, used in training data and write-ups
    if obj.is_multicast or obj.is_unspecified or obj.is_link_local or obj.is_reserved \
            or str(obj) == "255.255.255.255" or not obj.is_global:
        return "reserved"
    return "public"


# --- Reading evidence -------------------------------------------------------
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def looks_binary(path):
    with open(path, "rb") as fh:
        chunk = fh.read(4096)
    return b"\x00" in chunk


def read_eml(path):
    """Flatten an .eml file into headers + plain-text body."""
    with open(path, "rb") as fh:
        msg = email.message_from_binary_file(fh, policy=email.policy.default)
    lines = [f"{h}: {msg[h]}" for h in ("From", "To", "Cc", "Reply-To", "Date", "Subject",
                                       "Return-Path", "X-Originating-IP") if msg[h]]
    for rcv in msg.get_all("Received", []) or []:
        lines.append(f"Received: {' '.join(str(rcv).split())}")
    lines.append("")
    for part in msg.walk():
        if part.get_content_type() in ("text/plain", "text/html") and not part.is_multipart():
            try:
                body = part.get_content()
            except (LookupError, UnicodeDecodeError):
                body = part.get_payload(decode=True).decode("utf-8", "replace")
            if part.get_content_type() == "text/html":
                body = re.sub(r"<[^>]+>", " ", body)
            lines.extend(body.splitlines())
        elif part.get_filename():
            lines.append(f"[attachment] {part.get_filename()}")
    return lines


def read_lines(path):
    if path.lower().endswith(".eml"):
        return read_eml(path)
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return fh.read().splitlines()


def collect(target, all_files, excludes):
    if os.path.isfile(target):
        yield os.path.abspath(target)
        return
    for root, dirs, files in os.walk(target):
        dirs[:] = sorted(d for d in dirs if d not in excludes and not d.startswith("."))
        for name in sorted(files):
            ext = os.path.splitext(name)[1].lower()
            if all_files or ext in TEXT_EXTS:
                yield os.path.abspath(os.path.join(root, name))


# --- Analysis ---------------------------------------------------------------
def context(line, start, end, width):
    """Return a single-line snippet with the match marked >>like this<<."""
    left = line[max(0, start - width):start]
    right = line[end:end + width]
    lead = "…" if start - width > 0 else ""
    trail = "…" if end + width < len(line) else ""
    return f"{lead}{left}>>{line[start:end]}<<{right}{trail}".strip()


class Analyzer:
    def __init__(self, keywords, width, include_private):
        self.width = width
        self.include_private = include_private
        self.kw_patterns = [(k, re.compile(r"(?<![A-Za-z0-9])" + re.escape(k) + r"(?![A-Za-z0-9])", re.I))
                            for k in keywords]
        self.iocs = defaultdict(dict)        # type -> value -> {count, first_seen, files}
        self.hits = []                       # keyword hits
        self.words = Counter()
        self.bigrams = Counter()
        self.files = []

    def _add_ioc(self, kind, value, where, extra=None):
        entry = self.iocs[kind].get(value)
        if not entry:
            entry = {"value": value, "count": 0, "first_seen": where, "files": set()}
            if extra:
                entry.update(extra)
            self.iocs[kind][value] = entry
        entry["count"] += 1
        entry["files"].add(where.rsplit(":", 1)[0])

    def scan_line(self, raw, relpath, lineno):
        where = f"{relpath}:{lineno}"
        line = refang(raw)

        # Hashes first, and blank them out so they aren't re-read as smaller hashes or wallets
        masked = line
        for kind, pat in (("sha256", RE_SHA256), ("sha1", RE_SHA1), ("md5", RE_MD5)):
            for m in pat.finditer(masked):
                self._add_ioc(kind, m.group().lower(), where)
            masked = pat.sub(lambda m: " " * len(m.group()), masked)

        url_hosts = set()
        for m in RE_URL.finditer(masked):
            url = m.group().rstrip(".,;:!?")
            self._add_ioc("url", url, where)
            host = re.sub(r"^[a-z]+://", "", url, flags=re.I).split("/")[0].split(":")[0].lower()
            url_hosts.add(host)
        for m in RE_EMAIL.finditer(masked):
            self._add_ioc("email", m.group().lower(), where)
        email_domains = {m.group().split("@")[1].lower() for m in RE_EMAIL.finditer(masked)}
        for m in RE_IPV4.finditer(masked):
            ip = m.group()
            kind = classify_ip(ip)
            if kind in ("public", "documentation") or (kind and self.include_private):
                self._add_ioc("ipv4", ip, where, {"scope": kind})
        no_emails = RE_EMAIL.sub(" ", masked)
        for m in RE_DOMAIN.finditer(no_emails):
            d = m.group().lower()
            self._add_ioc("domain", d, where)
        for h in url_hosts | email_domains:
            if not RE_IPV4.fullmatch(h) and h not in self.iocs["domain"]:
                self._add_ioc("domain", h, where)
        for m in RE_BTC.finditer(masked):
            self._add_ioc("bitcoin", m.group(), where)
        for m in RE_ETH.finditer(masked):
            self._add_ioc("ethereum", m.group(), where)
        for m in RE_CVE.finditer(masked):
            self._add_ioc("cve", m.group().upper(), where)

        # Keyword watchlist, with context
        for kw, pat in self.kw_patterns:
            for m in pat.finditer(raw):
                self.hits.append({"keyword": kw, "file": relpath, "line": lineno,
                                  "context": context(raw, m.start(), m.end(), self.width)})

        # Word / phrase frequency (stopwords removed)
        clean = RE_DOMAIN.sub(" ", RE_EMAIL.sub(" ", RE_URL.sub(" ", line)))
        toks = [w.lower().strip("'-") for w in RE_WORD.findall(clean)]
        toks = [t for t in toks if len(t) > 2 and t not in STOPWORDS]
        self.words.update(toks)
        self.bigrams.update(zip(toks, toks[1:]))

    def scan_file(self, path, base):
        rel = os.path.relpath(path, base) if os.path.isdir(base) else os.path.basename(path)
        info = {"file": rel, "sha256": sha256_file(path), "bytes": os.path.getsize(path)}
        if looks_binary(path) and not path.lower().endswith(".eml"):
            info["skipped"] = "binary file"
            self.files.append(info)
            return
        lines = read_lines(path)
        info["lines"] = len(lines)
        for n, line in enumerate(lines, 1):
            self.scan_line(line, rel, n)
        self.files.append(info)

    def results(self, top):
        iocs = {}
        for kind, values in self.iocs.items():
            rows = sorted(values.values(), key=lambda e: (-e["count"], e["value"]))
            iocs[kind] = [{**e, "files": sorted(e["files"])} for e in rows]
        kw_counts = Counter(h["keyword"] for h in self.hits)
        return {
            "files": self.files,
            "iocs": iocs,
            "keyword_counts": kw_counts.most_common(),
            "keyword_hits": self.hits,
            "top_words": self.words.most_common(top),
            "top_phrases": [(" ".join(b), c) for b, c in self.bigrams.most_common(top) if c > 1],
        }


def concordance(paths, base, term, width):
    pat = re.compile(r"(?<![A-Za-z0-9])" + re.escape(term) + r"(?![A-Za-z0-9])", re.I)
    out = []
    for path in paths:
        if looks_binary(path) and not path.lower().endswith(".eml"):
            continue
        rel = os.path.relpath(path, base) if os.path.isdir(base) else os.path.basename(path)
        for n, line in enumerate(read_lines(path), 1):
            for m in pat.finditer(line):
                out.append({"file": rel, "line": n, "context": context(line, m.start(), m.end(), width)})
    return out


# --- Reports ----------------------------------------------------------------
IOC_LABELS = [("ipv4", "IP addresses"), ("url", "URLs"), ("domain", "Domains"), ("email", "Email addresses"),
              ("sha256", "SHA-256 hashes"), ("sha1", "SHA-1 hashes"), ("md5", "MD5 hashes"),
              ("bitcoin", "Bitcoin addresses"), ("ethereum", "Ethereum addresses"), ("cve", "CVE IDs")]


def write_reports(res, meta, out_dir, defanged):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as fh:
        json.dump({**meta, **res}, fh, indent=2)

    with open(os.path.join(out_dir, "iocs.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["type", "value", "defanged", "count", "scope", "first_seen", "files"])
        for kind, _ in IOC_LABELS:
            for e in res["iocs"].get(kind, []):
                w.writerow([kind, e["value"], defang(e["value"]), e["count"], e.get("scope", ""),
                            e["first_seen"], ";".join(e["files"])])

    with open(os.path.join(out_dir, "keyword_hits.csv"), "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["keyword", "file", "line", "context"])
        w.writeheader()
        w.writerows(res["keyword_hits"])

    # Human-readable case summary
    show = defang if defanged else (lambda v: v)
    md = [f"# Forensic Text Analysis Report", "",
          f"- **Evidence:** `{meta['target']}`",
          f"- **Analyzed:** {meta['analyzed_at']}",
          f"- **Files analyzed:** {sum(1 for f in res['files'] if 'skipped' not in f)} "
          f"(skipped {sum(1 for f in res['files'] if 'skipped' in f)})", "",
          "## Evidence files (chain of custody)", "", "| File | SHA-256 | Bytes |", "|---|---|---|"]
    md += [f"| {f['file']} | `{f['sha256']}` | {f['bytes']:,} |" for f in res["files"]]
    md += ["", "## Indicators of compromise", ""]
    if not any(res["iocs"].values()):
        md.append("_None found._")
    for kind, label in IOC_LABELS:
        rows = res["iocs"].get(kind)
        if not rows:
            continue
        md += [f"### {label} ({len(rows)})", "", "| Value | Count | First seen |", "|---|---|---|"]
        for e in rows:
            scope = f" _({e['scope']})_" if e.get("scope") else ""
            md.append(f"| `{show(e['value'])}`{scope} | {e['count']} | {e['first_seen']} |")
        md.append("")
    md += ["## Keyword hits", ""]
    if res["keyword_hits"]:
        md += ["| Keyword | Hits |", "|---|---|"] + [f"| {k} | {c} |" for k, c in res["keyword_counts"]]
        md += ["", "| Location | Context |", "|---|---|"]
        md += [f"| {h['file']}:{h['line']} | {h['context'].replace('|', '/')} |" for h in res["keyword_hits"][:200]]
    else:
        md.append("_No watchlist keywords found._")
    md += ["", "## What the evidence talks about", "",
           "**Top words:** " + ", ".join(f"{w} ({c})" for w, c in res["top_words"][:20]), "",
           "**Top phrases:** " + (", ".join(f"{p} ({c})" for p, c in res["top_phrases"][:15]) or "_none repeated_")]
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as fh:
        fh.write("\n".join(md) + "\n")


def print_summary(res, meta, defanged, max_hits):
    show = defang if defanged else (lambda v: v)
    bar = "=" * 70
    analyzed = [f for f in res["files"] if "skipped" not in f]
    print(f"\n{bar}\n FORENSIC TEXT ANALYSIS  {meta['target']}\n{bar}")
    print(f" Files analyzed : {len(analyzed)}  ({sum(f.get('lines', 0) for f in analyzed):,} lines)")
    skipped = len(res["files"]) - len(analyzed)
    if skipped:
        print(f" Files skipped  : {skipped} (binary)")

    print(f"\n INDICATORS OF COMPROMISE")
    any_ioc = False
    for kind, label in IOC_LABELS:
        rows = res["iocs"].get(kind)
        if not rows:
            continue
        any_ioc = True
        print(f"  {label} ({len(rows)})")
        for e in rows[:10]:
            scope = f" [{e['scope']}]" if e.get("scope") else ""
            print(f"     - {show(e['value'])}{scope}  x{e['count']}  ({e['first_seen']})")
        if len(rows) > 10:
            print(f"     … {len(rows) - 10} more in iocs.csv")
    if not any_ioc:
        print("  none found")

    print(f"\n KEYWORD HITS ({len(res['keyword_hits'])})")
    if res["keyword_counts"]:
        print("  " + ", ".join(f"{k} x{c}" for k, c in res["keyword_counts"][:12]))
        for h in res["keyword_hits"][:max_hits]:
            print(f"     {h['file']}:{h['line']}  {h['context']}")
        if len(res["keyword_hits"]) > max_hits:
            print(f"     … {len(res['keyword_hits']) - max_hits} more in keyword_hits.csv")
    else:
        print("  none found")

    print(f"\n TOP WORDS   : " + ", ".join(w for w, _ in res["top_words"][:12]))
    if res["top_phrases"]:
        print(f" TOP PHRASES : " + ", ".join(p for p, _ in res["top_phrases"][:8]))
    print(bar)


# --- Main -------------------------------------------------------------------
def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Triage text evidence: extract IOCs, flag watchlist keywords in context, "
                    "and summarize what the documents discuss.")
    ap.add_argument("target", help="evidence file or folder")
    ap.add_argument("-k", "--keywords", metavar="FILE",
                    help="watchlist file, one keyword or phrase per line (replaces the default list)")
    ap.add_argument("--add-keyword", action="append", default=[], metavar="WORD",
                    help="add a keyword to the watchlist (repeatable)")
    ap.add_argument("-s", "--search", metavar="TERM",
                    help="only print every occurrence of TERM in context (concordance)")
    ap.add_argument("--private-ips", action="store_true", help="also report private/internal IPs")
    ap.add_argument("--all-files", action="store_true", help="read every file, not just text extensions")
    ap.add_argument("--no-defang", action="store_true", help="show IOCs live instead of defanged in output")
    ap.add_argument("--width", type=int, default=40, help="characters of context around hits (default 40)")
    ap.add_argument("--top", type=int, default=25, help="how many top words/phrases to keep (default 25)")
    ap.add_argument("--max-hits", type=int, default=15, help="keyword hits to print on screen (default 15)")
    ap.add_argument("-o", "--out", help="output folder (default analysis_<timestamp>)")
    args = ap.parse_args(argv)

    if not os.path.exists(args.target):
        ap.error(f"{args.target} does not exist")
    base = os.path.abspath(args.target)
    paths = list(collect(base, args.all_files, {"node_modules", "__pycache__"}))
    if not paths:
        print("[!] No text files found. Try --all-files.", file=sys.stderr)
        return 1

    if args.search:
        hits = concordance(paths, base, args.search, args.width)
        print(f"\n{len(hits)} occurrence(s) of '{args.search}':\n")
        for h in hits:
            print(f"  {h['file']}:{h['line']}  {h['context']}")
        return 0

    if args.keywords:
        with open(args.keywords, encoding="utf-8") as fh:
            keywords = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        keywords = list(DEFAULT_KEYWORDS)
    keywords += args.add_keyword

    an = Analyzer(keywords, args.width, args.private_ips)
    print(f"[*] Analyzing {len(paths)} file(s) under {base}")
    for p in paths:
        try:
            an.scan_file(p, base)
        except OSError as err:
            an.files.append({"file": p, "skipped": err.strerror or str(err), "sha256": "", "bytes": 0})

    res = an.results(args.top)
    meta = {"target": base, "analyzed_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "watchlist_size": len(keywords)}
    out_dir = args.out or f"analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    defanged = not args.no_defang
    write_reports(res, meta, out_dir, defanged)
    print_summary(res, meta, defanged, args.max_hits)
    print(f"[+] Reports saved to {out_dir}/ (report.md, report.json, iocs.csv, keyword_hits.csv)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
